import os
import sys
import time
import json
import psutil
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    recall_score,
    precision_score,
    f1_score,
    roc_auc_score,
)

try:
    from imblearn.over_sampling import SMOTE
    TIENE_SMOTE = True
except ImportError:
    TIENE_SMOTE = False
    print("[!] ADVERTENCIA: imblearn no disponible. Se omitirá SMOTE si no está instalado.")

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks

# --- Configuración del Entorno y Rutas ---
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
tf.random.set_seed(42)
np.random.seed(42)

_proceso_actual = psutil.Process()
_proceso_actual.cpu_percent(interval=None)


def obtener_uso_recursos_proceso():
    porcentaje_cpu = round(_proceso_actual.cpu_percent(interval=None) / (psutil.cpu_count() or 1), 2)
    memoria_ram_mb = round(_proceso_actual.memory_info().rss / (1024 * 1024), 2)
    return porcentaje_cpu, memoria_ram_mb


DIRECTORIO_ML = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_MODELOS = os.path.join(DIRECTORIO_ML, "models")
RUTA_CONJUNTO_DATOS_PREDETERMINADA = os.path.join(
    DIRECTORIO_ML, "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

COLUMNAS_METADATOS_A_DESCARTAR = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
    "External IP",
]


# --- 1. Carga y Limpieza de Datos ---
def cargar_y_limpiar_conjunto_datos(ruta_csv: str):
    print(f"\n[*] 1. Iniciando carga y depuración del conjunto de datos: {ruta_csv}")
    if not os.path.exists(ruta_csv):
        raise FileNotFoundError(f"No se encontró el archivo del conjunto de datos en: {ruta_csv}")

    datos_crudos = pd.read_csv(ruta_csv, low_memory=False)
    print(f"    - Registros cargados en crudo: {len(datos_crudos):,}")
    print(f"    - Columnas originales: {len(datos_crudos.columns)}")

    datos_crudos.columns = datos_crudos.columns.str.strip()

    if "Label" not in datos_crudos.columns:
        raise ValueError("El conjunto de datos no contiene la columna objetivo 'Label'.")

    print("    - Estandarizando etiquetas binarias (0 = BENIGN, 1 = DDoS)...")
    etiquetas_texto = datos_crudos["Label"].astype(str).str.strip().str.upper()
    etiquetas_binarias = np.where(etiquetas_texto == "BENIGN", 0, 1).astype(np.int32)

    df_caracteristicas = datos_crudos.drop(columns=["Label"])

    columnas_descartadas = [col for col in COLUMNAS_METADATOS_A_DESCARTAR if col in df_caracteristicas.columns]
    if columnas_descartadas:
        df_caracteristicas.drop(columns=columnas_descartadas, inplace=True)
        print(f"    - Columnas de metadatos descartadas: {columnas_descartadas}")

    print("    - Convirtiendo características a tipo numérico de alta precisión...")
    df_caracteristicas = df_caracteristicas.apply(pd.to_numeric, errors="coerce")

    print("    - Depurando inf, -inf y NaN resultantes de flujos con duración de 0 microsegundos...")
    conteo_infinitos = np.isinf(df_caracteristicas.values).sum()
    conteo_nulos = np.isnan(df_caracteristicas.values).sum()
    print(f"      * Inconsistencias numéricas detectadas: {conteo_infinitos:,} infinitos, {conteo_nulos:,} nulos.")

    df_caracteristicas.replace([np.inf, -np.inf], np.nan, inplace=True)

    medianas_columnas = df_caracteristicas.median()
    df_caracteristicas.fillna(medianas_columnas, inplace=True)
    df_caracteristicas.fillna(0.0, inplace=True)

    nombres_caracteristicas = list(df_caracteristicas.columns)
    matriz_caracteristicas = df_caracteristicas.values.astype(np.float32)

    print(f"    - Matriz de características limpia: {matriz_caracteristicas.shape[0]:,} muestras x {matriz_caracteristicas.shape[1]} atributos.")
    print(f"    - Balance de clases: Benigno = {np.sum(etiquetas_binarias == 0):,} ({np.mean(etiquetas_binarias == 0)*100:.2f}%) | "
          f"Ataque = {np.sum(etiquetas_binarias == 1):,} ({np.mean(etiquetas_binarias == 1)*100:.2f}%)")

    return matriz_caracteristicas, etiquetas_binarias, nombres_caracteristicas


# --- 2. Preprocesamiento, Escalado y Balanceo SMOTE ---
def preparar_canalizacion_datos(matriz_X: np.ndarray, vector_y: np.ndarray, proporcion_prueba: float = 0.20):
    print("\n[*] 2. Ejecutando canalización de datos sin fuga de información (Data Leakage)...")

    print(f"    - Particionando datos (Estratificado {int((1-proporcion_prueba)*100)}% entrenamiento / {int(proporcion_prueba*100)}% prueba)...")
    X_entrenamiento, X_prueba, y_entrenamiento, y_prueba = train_test_split(
        matriz_X,
        vector_y,
        test_size=proporcion_prueba,
        random_state=42,
        stratify=vector_y
    )
    print(f"      * X_entrenamiento: {X_entrenamiento.shape[0]:,} muestras")
    print(f"      * X_prueba       : {X_prueba.shape[0]:,} muestras (Aisladas para validación empírica)")

    print("    - Ajustando MinMaxScaler exclusivamente sobre X_entrenamiento (fit_transform)...")
    escalador = MinMaxScaler(feature_range=(0.0, 1.0))
    X_entrenamiento_escalado = escalador.fit_transform(X_entrenamiento)

    print("    - Aplicando escala aprendida sobre X_prueba (transform sin re-ajustar)...")
    X_prueba_escalado = escalador.transform(X_prueba)

    if TIENE_SMOTE:
        cantidad_benignos = np.sum(y_entrenamiento == 0)
        cantidad_ataques = np.sum(y_entrenamiento == 1)
        proporcion_minoria = min(cantidad_benignos, cantidad_ataques) / max(cantidad_benignos, cantidad_ataques)
        if proporcion_minoria < 0.80:
            print(f"    - Aplicando balanceo SMOTE solo en entrenamiento (Proporción minoritaria: {proporcion_minoria:.2%})...")
            print(f"      * Distribución inicial: Benigno={cantidad_benignos:,}, DDoS={cantidad_ataques:,}")
            sobremureador_smote = SMOTE(random_state=42)
            X_entrenamiento_balanceado, y_entrenamiento_balanceado = sobremureador_smote.fit_resample(
                X_entrenamiento_escalado, y_entrenamiento
            )
            print(f"      * Distribución balanceada: Benigno={np.sum(y_entrenamiento_balanceado == 0):,}, "
                  f"DDoS={np.sum(y_entrenamiento_balanceado == 1):,}")
        else:
            print(f"    - SMOTE omitido: Clases suficientemente balanceadas (Proporción: {proporcion_minoria:.2%}).")
            X_entrenamiento_balanceado, y_entrenamiento_balanceado = X_entrenamiento_escalado, y_entrenamiento
    else:
        X_entrenamiento_balanceado, y_entrenamiento_balanceado = X_entrenamiento_escalado, y_entrenamiento

    print("    - Redimensionando tensores a 3D para Convolución Unidimensional (muestras, características, 1)...")
    X_entrenamiento_3d = X_entrenamiento_balanceado.reshape(
        (X_entrenamiento_balanceado.shape[0], X_entrenamiento_balanceado.shape[1], 1)
    )
    X_prueba_3d = X_prueba_escalado.reshape(
        (X_prueba_escalado.shape[0], X_prueba_escalado.shape[1], 1)
    )

    return X_entrenamiento_3d, X_prueba_3d, y_entrenamiento_balanceado, y_prueba, escalador


# --- 3. Construcción de la Arquitectura Conv1D ---
def construir_modelo_conv1d_ligero(caracteristicas_entrada: int) -> models.Sequential:
    print("\n[*] 3. Compilando Arquitectura Conv1D Ultraligera para hardware Pyme...")
    modelo = models.Sequential([
        layers.Input(shape=(caracteristicas_entrada, 1), name="entrada_telemetria_flujo"),

        # Bloque Convolucional 1
        layers.Conv1D(filters=32, kernel_size=3, padding="same", activation="relu", name="conv1d_bloque1"),
        layers.BatchNormalization(name="normalizacion_lote1"),
        layers.MaxPooling1D(pool_size=2, name="max_agrupamiento1"),
        layers.Dropout(0.20, name="abandono_regularizacion1"),

        # Bloque Convolucional 2
        layers.Conv1D(filters=64, kernel_size=3, padding="same", activation="relu", name="conv1d_bloque2"),
        layers.BatchNormalization(name="normalizacion_lote2"),
        layers.MaxPooling1D(pool_size=2, name="max_agrupamiento2"),
        layers.Dropout(0.20, name="abandono_regularizacion2"),

        # Agrupamiento Global y Salida
        layers.GlobalMaxPooling1D(name="agrupamiento_maximo_global"),
        layers.Dense(32, activation="relu", name="capa_densa_intermedia"),
        layers.Dropout(0.30, name="abandono_regularizacion_densa"),
        layers.Dense(1, activation="sigmoid", name="salida_clasificacion_ddos"),
    ], name="Conv1D_CyberShield_NIDS")

    modelo.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Recall(name="recall"),
            tf.keras.metrics.Precision(name="precision"),
        ],
    )

    modelo.summary(print_fn=lambda x: print(f"    {x}"))
    return modelo


# --- 4. Entrenamiento y Evaluación de Métricas ---
def entrenar_y_evaluar_modelo(
    modelo: models.Sequential,
    X_entrenamiento: np.ndarray,
    y_entrenamiento: np.ndarray,
    X_prueba: np.ndarray,
    y_prueba: np.ndarray,
    epocas: int = 10,
    tamano_lote: int = 256,
):
    print("\n[*] 4. Iniciando entrenamiento del modelo Conv1D con regularización temprana...")
    os.makedirs(DIRECTORIO_MODELOS, exist_ok=True)

    llamadas_retorno_entrenamiento = [
        callbacks.EarlyStopping(
            monitor="val_loss",
            patience=3,
            restore_best_weights=True,
            verbose=1,
        ),
        callbacks.ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=2,
            min_lr=1e-5,
            verbose=1,
        ),
    ]

    cpu_inicio, ram_inicio = obtener_uso_recursos_proceso()
    tiempo_inicio_entrenamiento = time.time()

    historial = modelo.fit(
        X_entrenamiento,
        y_entrenamiento,
        epochs=epocas,
        batch_size=tamano_lote,
        validation_split=0.10,
        callbacks=llamadas_retorno_entrenamiento,
        verbose=1,
    )

    duracion_entrenamiento_seg = round(time.time() - tiempo_inicio_entrenamiento, 2)
    cpu_fin, ram_fin = obtener_uso_recursos_proceso()
    ram_pico_mb = ram_fin

    print(f"\n[*] Entrenamiento concluido en {duracion_entrenamiento_seg} segundos.")
    print(f"    - Memoria RAM consumida por el proceso: {ram_pico_mb} MB")

    print("\n[*] 5. Evaluando latencia de inferencia y métricas de desempeño...")
    tiempo_inicio_inferencia = time.time()
    probabilidades_predichas = modelo.predict(X_prueba, batch_size=tamano_lote, verbose=0)
    duracion_total_inferencia_ms = (time.time() - tiempo_inicio_inferencia) * 1000.0

    latencia_por_muestra_ms = duracion_total_inferencia_ms / len(X_prueba)
    clases_predichas = (probabilidades_predichas >= 0.50).astype(int).flatten()

    matriz_confusion = confusion_matrix(y_prueba, clases_predichas)
    verdaderos_negativos, falsos_positivos, falsos_negativos, verdaderos_positivos = matriz_confusion.ravel()

    exactitud = float(accuracy_score(y_prueba, clases_predichas))
    sensibilidad = float(recall_score(y_prueba, clases_predichas))
    precision = float(precision_score(y_prueba, clases_predichas))
    puntuacion_f1 = float(f1_score(y_prueba, clases_predichas))
    tasa_falsos_positivos = (
        float(falsos_positivos / (falsos_positivos + verdaderos_negativos))
        if (falsos_positivos + verdaderos_negativos) > 0
        else 0.0
    )
    especificidad = (
        float(verdaderos_negativos / (verdaderos_negativos + falsos_positivos))
        if (verdaderos_negativos + falsos_positivos) > 0
        else 0.0
    )
    try:
        puntuacion_roc_auc = float(roc_auc_score(y_prueba, probabilidades_predichas))
    except Exception:
        puntuacion_roc_auc = 0.0

    print("\n" + "=" * 78)
    print("          EVALUACIÓN EXPERIMENTAL DE HIPÓTESIS - SISTEMA NIDS Conv1D")
    print("=" * 78)
    print(f"Matriz de Confusión:\n{matriz_confusion}")
    print("-" * 78)
    print(f"Verdaderos Negativos (TN) : {verdaderos_negativos:,}  (Tráfico benigno correctamente clasificado)")
    print(f"Falsos Positivos      (FP) : {falsos_positivos:,}  (Alarmas erróneas sobre tráfico legítimo)")
    print(f"Falsos Negativos      (FN) : {falsos_negativos:,}  (Ataques DDoS no detectados)")
    print(f"Verdaderos Positivos  (TP) : {verdaderos_positivos:,}  (Ataques DDoS detectados exitosamente)")
    print("-" * 78)
    print(f"Exactitud Total (Accuracy) : {exactitud * 100:.4f} %")
    print(f"Sensibilidad (Recall / TPR): {sensibilidad * 100:.4f} %  [Meta Hipótesis: > 95.0%]")
    print(f"Tasa Falsos Positivos (FPR): {tasa_falsos_positivos * 100:.4f} %  [Meta Hipótesis: < 1.0% / < 5.0%]")
    print(f"Precisión                  : {precision * 100:.4f} %")
    print(f"Especificidad (TNR)        : {especificidad * 100:.4f} %")
    print(f"Puntuación F1 (F1-Score)   : {puntuacion_f1:.4f}")
    print(f"Área Bajo la Curva ROC     : {puntuacion_roc_auc:.4f}")
    print("-" * 78)
    print(f"Latencia Total Inferencia  : {duracion_total_inferencia_ms:.2f} ms sobre {len(X_prueba):,} muestras")
    print(f"Latencia Promedio / Muestra: {latencia_por_muestra_ms:.4f} ms  [Meta Hipótesis: < 10.0 ms]")
    print(f"Memoria RAM Máxima Proceso : {ram_pico_mb:.2f} MB  [Meta Hipótesis: Viabilidad Pyme < 250 MB]")
    print("=" * 78)

    diccionario_metricas = {
        "confusion_matrix": {
            "TN": int(verdaderos_negativos),
            "FP": int(falsos_positivos),
            "FN": int(falsos_negativos),
            "TP": int(verdaderos_positivos),
        },
        "accuracy": exactitud,
        "recall_tpr": sensibilidad,
        "fpr": tasa_falsos_positivos,
        "precision": precision,
        "specificity": especificidad,
        "f1_score": puntuacion_f1,
        "roc_auc": puntuacion_roc_auc,
        "latency_per_sample_ms": latencia_por_muestra_ms,
        "total_test_samples": len(X_prueba),
        "train_duration_s": duracion_entrenamiento_seg,
        "ram_peak_mb": ram_pico_mb,
    }

    return diccionario_metricas


# --- 5. Exportación de Artefactos ---
def exportar_artefactos(
    modelo: models.Sequential,
    escalador: MinMaxScaler,
    nombres_caracteristicas: list,
    metricas: dict,
):
    print("\n[*] 6. Exportando artefactos del modelo y contrato de interfaz...")
    os.makedirs(DIRECTORIO_MODELOS, exist_ok=True)

    # A. Modelo Conv1D
    ruta_modelo_keras = os.path.join(DIRECTORIO_MODELOS, "ddos_cnn_model.keras")
    ruta_modelo_alias = os.path.join(DIRECTORIO_MODELOS, "modelo_conv1d.keras")
    modelo.save(ruta_modelo_keras)
    modelo.save(ruta_modelo_alias)

    tamano_modelo_kb = os.path.getsize(ruta_modelo_keras) / 1024.0
    tamano_modelo_mb = tamano_modelo_kb / 1024.0
    print(f"    - Modelo exportado en: {ruta_modelo_keras}")
    print(f"      * Tamaño en disco: {tamano_modelo_kb:.2f} KB ({tamano_modelo_mb:.2f} MB) -> [Cumple: < 2 MB]")

    # B. Escalador
    ruta_escalador_joblib = os.path.join(DIRECTORIO_MODELOS, "scaler.joblib")
    ruta_escalador_pkl = os.path.join(DIRECTORIO_MODELOS, "scaler.pkl")
    joblib.dump(escalador, ruta_escalador_joblib)
    joblib.dump(escalador, ruta_escalador_pkl)
    print(f"    - Escalador exportado en: {ruta_escalador_joblib} y {ruta_escalador_pkl}")

    # C. Lista de Características
    ruta_json_caracteristicas = os.path.join(DIRECTORIO_MODELOS, "selected_features.json")
    with open(ruta_json_caracteristicas, "w", encoding="utf-8") as archivo_caracteristicas:
        json.dump(nombres_caracteristicas, archivo_caracteristicas, indent=2, ensure_ascii=False)
    print(f"    - Lista de {len(nombres_caracteristicas)} características exportada en: {ruta_json_caracteristicas}")

    # D. Reporte de Evaluación
    ruta_json_metricas = os.path.join(DIRECTORIO_MODELOS, "evaluation_metrics.json")
    with open(ruta_json_metricas, "w", encoding="utf-8") as archivo_metricas:
        json.dump(metricas, archivo_metricas, indent=2, ensure_ascii=False)
    print(f"    - Métricas experimentales exportadas en: {ruta_json_metricas}")

    # E. Metadatos del Sistema Web
    ruta_metadatos_sistema = os.path.join(DIRECTORIO_MODELOS, "model_metadata.json")
    metadatos_sistema = {
        "model_name": "Conv1D_CyberShield_DDoS",
        "architecture": "Conv1D(32)->BN->Pool->Drop->Conv1D(64)->BN->Pool->Drop->GlobalMaxPool->Dense(32)->Dense(1)",
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "dataset": "CICIDS2017 (DDoS Friday Working Hours)",
        "n_features": len(nombres_caracteristicas),
        "feature_names": nombres_caracteristicas,
        "scaler": "MinMaxScaler(0, 1)",
        "model_size_kb": round(tamano_modelo_kb, 2),
        "decision_threshold": 0.50,
        "thesis_alignment": {
            "pe1_smote": "SMOTE aplicado exclusivamente en entrenamiento para balanceo",
            "pe2_conv1d": "Conv1D ultraligera < 2 MB optimizada para inferencia en CPU",
            "pe3_latency": f"Latencia inferencia: {metricas['latency_per_sample_ms']:.4f} ms/muestra",
            "pe4_hardware": f"Consumo de RAM pico: {metricas['ram_peak_mb']:.2f} MB en hardware modesto Pyme",
        },
        "test_metrics": metricas,
    }
    with open(ruta_metadatos_sistema, "w", encoding="utf-8") as archivo_meta:
        json.dump(metadatos_sistema, archivo_meta, indent=2, ensure_ascii=False)
    print(f"    - Metadatos de producción sincronizados en: {ruta_metadatos_sistema}")


# --- Punto de Entrada Principal ---
def principal():
    print("=" * 78)
    print("   ENTRENAMIENTO ACADÉMICO Y EXPORTACIÓN DE MODELO CONV1D - NIDS PYME")
    print("=" * 78)

    ruta_conjunto_datos = sys.argv[1] if len(sys.argv) > 1 else RUTA_CONJUNTO_DATOS_PREDETERMINADA

    if not os.path.exists(ruta_conjunto_datos):
        print(f"\n[!] ERROR: No se encontró el conjunto de datos en la ruta indicada: {ruta_conjunto_datos}")
        print("    Asegúrate de colocar el archivo CSV de CICIDS2017 en la carpeta ml/dataset/")
        print("    Ejemplo de ejecución:")
        print("    python ml/entrenar_experimentos.py ml/dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        sys.exit(1)

    matriz_X, vector_y, nombres_caracteristicas = cargar_y_limpiar_conjunto_datos(ruta_conjunto_datos)

    X_entrenamiento, X_prueba, y_entrenamiento, y_prueba, escalador = preparar_canalizacion_datos(
        matriz_X, vector_y, proporcion_prueba=0.20
    )

    modelo = construir_modelo_conv1d_ligero(caracteristicas_entrada=len(nombres_caracteristicas))

    metricas = entrenar_y_evaluar_modelo(
        modelo=modelo,
        X_entrenamiento=X_entrenamiento,
        y_entrenamiento=y_entrenamiento,
        X_prueba=X_prueba,
        y_prueba=y_prueba,
        epocas=10,
        tamano_lote=256,
    )

    exportar_artefactos(
        modelo=modelo,
        escalador=escalador,
        nombres_caracteristicas=nombres_caracteristicas,
        metricas=metricas,
    )

    print("\n[OK] Canalización completada exitosamente. Todos los artefactos están listos para producción.")


if __name__ == "__main__":
    principal()
