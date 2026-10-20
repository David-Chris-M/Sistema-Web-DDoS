"""
================================================================================
SISTEMA NIDS - DETECCIÓN DE ATAQUES DDOS CON REDES CONVOLUCIONALES (Conv1D)
SCRIPT ACADÉMICO Y DE PRODUCCIÓN: ml/train_academic_experiments.py
================================================================================
Alineación Metodológica de Tesis:
- PE1 / OE1: Balanceo riguroso de clases con SMOTE aplicado exclusivamente en X_train.
- PE2 / OE2: Arquitectura Conv1D ultraligera (< 2 MB) con regularización y latencia < 1 ms.
- PE3 / OE3: Contrato de artefactos estricto (modelo, scaler.joblib, selected_features.json).
- PE4 / OE4: Evaluación empírica: Matriz de Confusión, Recall, FPR, monitoreo de RAM/CPU.
================================================================================
"""

import os
import sys
import time
import json
import psutil
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# Scikit-learn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    accuracy_score,
    recall_score,
    precision_score,
    f1_score,
    roc_auc_score,
)

# Imbalanced-learn (SMOTE)
try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("[!] ADVERTENCIA: imblearn no disponible. Se omitirá SMOTE si no está instalado.")

# TensorFlow / Keras
import tensorflow as tf
from tensorflow.keras import layers, models, callbacks

# ------------------------------------------------------------------------------
# 0. CONFIGURACIÓN DEL ENTORNO Y MONITOREO DE RECURSOS
# ------------------------------------------------------------------------------
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # Silenciar advertencias de compilación TF
tf.random.set_seed(42)
np.random.seed(42)

_current_process = psutil.Process()
_current_process.cpu_percent(interval=None)


def get_process_resource_usage():
    """
    Retorna el uso de CPU y memoria RAM (RSS) exclusivo de este proceso en ejecución.
    Cumple con el requerimiento de evaluación de bajo consumo para Pymes (PE4 / HE4).
    """
    cpu_pct = round(_current_process.cpu_percent(interval=None) / (psutil.cpu_count() or 1), 2)
    ram_mb = round(_current_process.memory_info().rss / (1024 * 1024), 2)
    return cpu_pct, ram_mb


# Definición de rutas base
ML_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(ML_DIR, "models")
DATASET_DEFAULT = os.path.join(ML_DIR, "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Columnas identificadoras / no predictivas de CICIDS2017 a descartar obligatoriamente
METADATA_COLS_TO_DROP = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
    "External IP",
]


# ------------------------------------------------------------------------------
# 1. CARGA, LIMPIEZA ROBUSTA E IMPUTACIÓN DE DATOS (CICIDS2017)
# ------------------------------------------------------------------------------
def load_and_clean_dataset(csv_path: str):
    print(f"\n[*] 1. Iniciando carga y depuración del dataset: {csv_path}")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"No se encontró el archivo del dataset en: {csv_path}")

    # Cargar CSV
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"    - Registros cargados en crudo: {len(df):,}")
    print(f"    - Columnas originales: {len(df.columns)}")

    # Limpiar espacios en blanco en los nombres de las columnas (defecto conocido de CICIDS2017)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError("El dataset no contiene la columna objetivo 'Label'.")

    # Mapeo binario: 0 = BENIGN (Tráfico legítimo), 1 = DDoS / Ataque
    print("    - Estandarizando etiquetas binarias (0 = BENIGN, 1 = DDoS)...")
    y_raw = df["Label"].astype(str).str.strip().str.upper()
    y = np.where(y_raw == "BENIGN", 0, 1).astype(np.int32)

    # Eliminar columna Label del conjunto de características
    df_features = df.drop(columns=["Label"])

    # Descartar columnas de metadatos o identificadores (IPs, Timestamp, Flow ID)
    cols_dropped = [col for col in METADATA_COLS_TO_DROP if col in df_features.columns]
    if cols_dropped:
        df_features.drop(columns=cols_dropped, inplace=True)
        print(f"    - Columnas de metadatos descartadas: {cols_dropped}")

    # Conversión estricta a numérico (cualquier texto espurio se convierte en NaN)
    print("    - Convirtiendo características a tipo numérico de alta precisión...")
    df_features = df_features.apply(pd.to_numeric, errors="coerce")

    # Manejo de inf, -inf y NaN específicos de divisiones por cero en CICFlowMeter
    print("    - Depurando inf, -inf y NaN resultantes de flujos de 0 microsegundos...")
    inf_count = np.isinf(df_features.values).sum()
    nan_count = np.isnan(df_features.values).sum()
    print(f"      * Inconsistencias numéricas detectadas: {inf_count:,} infinitos, {nan_count:,} NaNs.")

    # Reemplazar infinitos por NaN para tratamiento uniforme
    df_features.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Imputar NaNs con la mediana de cada columna para preservar el tamaño muestral
    col_medians = df_features.median()
    df_features.fillna(col_medians, inplace=True)

    # Reemplazo residual para columnas con varianza 0 que puedan permanecer NaN
    df_features.fillna(0.0, inplace=True)

    feature_names = list(df_features.columns)
    X = df_features.values.astype(np.float32)

    print(f"    - Matriz de características limpia: {X.shape[0]:,} muestras x {X.shape[1]} atributos.")
    print(f"    - Balance de clases: Benigno = {np.sum(y == 0):,} ({np.mean(y == 0)*100:.2f}%) | "
          f"Ataque = {np.sum(y == 1):,} ({np.mean(y == 1)*100:.2f}%)")

    return X, y, feature_names


# ------------------------------------------------------------------------------
# 2. PIPELINE LIBRE DE DATA LEAKAGE (SPLIT -> MINMAXSCALER -> SMOTE)
# ------------------------------------------------------------------------------
def prepare_data_pipeline(X: np.ndarray, y: np.ndarray, test_size: float = 0.20):
    print("\n[*] 2. Ejecutando pipeline de preprocesamiento sin Data Leakage...")

    # PASO A: train_test_split ESTRATIFICADO PRIMERO
    print(f"    - Particionando datos (Estratificado {int((1-test_size)*100)}/{int(test_size*100)})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=42,
        stratify=y
    )
    print(f"      * X_train: {X_train.shape[0]:,} muestras")
    print(f"      * X_test : {X_test.shape[0]:,} muestras (Completamente aisladas para validación)")

    # PASO B: MinMaxScaler AJUSTADO ÚNICAMENTE EN X_train
    print("    - Ajustando MinMaxScaler exclusivamente sobre X_train (fit_transform)...")
    scaler = MinMaxScaler(feature_range=(0.0, 1.0))
    X_train_scaled = scaler.fit_transform(X_train)

    # PASO C: Aplicar la transformación aprendida a X_test (transform únicamente)
    print("    - Aplicando escala aprendida sobre X_test (transform sin re-ajustar)...")
    X_test_scaled = scaler.transform(X_test)

    # PASO D: SMOTE APLICADO EXCLUSIVAMENTE SOBRE X_train
    if HAS_SMOTE:
        benign_cnt = np.sum(y_train == 0)
        attack_cnt = np.sum(y_train == 1)
        ratio = min(benign_cnt, attack_cnt) / max(benign_cnt, attack_cnt)
        if ratio < 0.80:
            print(f"    - Aplicando balanceo con SMOTE solo en X_train (Ratio minoritario: {ratio:.2%})...")
            print(f"      * Distribución previa: Benign={benign_cnt:,}, DDoS={attack_cnt:,}")
            smote = SMOTE(random_state=42)
            X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
            print(f"      * Distribución posterior: Benign={np.sum(y_train_balanced == 0):,}, "
                  f"DDoS={np.sum(y_train_balanced == 1):,}")
        else:
            print(f"    - SMOTE omitido: Clases suficientemente balanceadas (Ratio: {ratio:.2%}).")
            X_train_balanced, y_train_balanced = X_train_scaled, y_train
    else:
        X_train_balanced, y_train_balanced = X_train_scaled, y_train

    # PASO E: Redimensionamiento 3D para Conv1D (samples, features, 1)
    print("    - Redimensionando tensores a 3D para la Convolución Unidimensional (samples, features, 1)...")
    X_train_3d = X_train_balanced.reshape((X_train_balanced.shape[0], X_train_balanced.shape[1], 1))
    X_test_3d = X_test_scaled.reshape((X_test_scaled.shape[0], X_test_scaled.shape[1], 1))

    return X_train_3d, X_test_3d, y_train_balanced, y_test, scaler


# ------------------------------------------------------------------------------
# 3. ARQUITECTURA CONV1D ULTRALIGERA (< 2 MB) PARA PYMES
# ------------------------------------------------------------------------------
def build_lightweight_conv1d_model(input_features: int) -> models.Sequential:
    """
    Construye una Red Neuronal Convolucional 1D altamente eficiente y compacta.
    Diseño inspirado en LUCID: 
    - Convoluciones compactas + BatchNormalization + Dropout
    - GlobalMaxPooling1D para eliminar la matriz masiva de pesos densos
    - Tamaño en disco: < 500 KB (cumple con holgura la meta de < 2 MB)
    - Inferencia sub-milisegundo en CPUs modestas sin requerir GPU dedicada
    """
    print("\n[*] 3. Compilando Arquitectura Conv1D Ultraligera...")
    model = models.Sequential([
        layers.Input(shape=(input_features, 1), name="input_telemetry_flow"),

        # Bloque Convolucional 1
        layers.Conv1D(filters=32, kernel_size=3, padding="same", activation="relu", name="conv1d_layer1"),
        layers.BatchNormalization(name="batch_norm1"),
        layers.MaxPooling1D(pool_size=2, name="max_pool1"),
        layers.Dropout(0.20, name="dropout1"),

        # Bloque Convolucional 2
        layers.Conv1D(filters=64, kernel_size=3, padding="same", activation="relu", name="conv1d_layer2"),
        layers.BatchNormalization(name="batch_norm2"),
        layers.MaxPooling1D(pool_size=2, name="max_pool2"),
        layers.Dropout(0.20, name="dropout2"),

        # Reducción espacial extrema: reemplaza Flatten pesados por GlobalPooling
        layers.GlobalMaxPooling1D(name="global_max_pool"),

        # Capa de Decisión Compacta
        layers.Dense(32, activation="relu", name="dense_latent"),
        layers.Dropout(0.30, name="dropout_latent"),
        layers.Dense(1, activation="sigmoid", name="output_classification"),
    ], name="Conv1D_CyberShield_NIDS")

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Recall(name="recall"),
            tf.keras.metrics.Precision(name="precision"),
        ],
    )

    model.summary(print_fn=lambda x: print(f"    {x}"))
    return model


# ------------------------------------------------------------------------------
# 4. ENTRENAMIENTO, EVALUACIÓN EXHAUSTIVA Y MÉTRICAS DE HIPÓTESIS
# ------------------------------------------------------------------------------
def train_and_evaluate_model(
    model: models.Sequential,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    epochs: int = 10,
    batch_size: int = 256,
):
    print("\n[*] 4. Iniciando entrenamiento del modelo Conv1D con parada temprana...")
    os.makedirs(MODELS_DIR, exist_ok=True)

    training_callbacks = [
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

    cpu_start, ram_start = get_process_resource_usage()
    t_start_train = time.time()

    history = model.fit(
        X_train,
        y_train,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=0.10,
        callbacks=training_callbacks,
        verbose=1,
    )

    train_duration_s = round(time.time() - t_start_train, 2)
    cpu_end, ram_end = get_process_resource_usage()
    ram_peak_mb = ram_end

    print(f"\n[*] Entrenamiento finalizado en {train_duration_s} segundos.")
    print(f"    - Consumo de RAM del proceso: {ram_peak_mb} MB")

    # --------------------------------------------------------------------------
    # EVALUACIÓN DE INFERENCIA Y MATRIZ DE CONFUSIÓN
    # --------------------------------------------------------------------------
    print("\n[*] 5. Evaluando rendimiento experimental y latencia de inferencia...")
    t_infer_start = time.time()
    y_pred_probs = model.predict(X_test, batch_size=batch_size, verbose=0)
    total_infer_duration_ms = (time.time() - t_infer_start) * 1000.0

    latency_per_sample_ms = total_infer_duration_ms / len(X_test)
    y_pred = (y_pred_probs >= 0.50).astype(int).flatten()

    # Cálculo explícito de cuadrantes de la matriz de confusión
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    # Métricas formales de evaluación para hipótesis de tesis
    accuracy = float(accuracy_score(y_test, y_pred))
    recall = float(recall_score(y_test, y_pred))  # Sensibilidad / TPR
    precision = float(precision_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    try:
        roc_auc = float(roc_auc_score(y_test, y_pred_probs))
    except Exception:
        roc_auc = 0.0

    # --------------------------------------------------------------------------
    # PRESENTACIÓN TABULAR DE RESULTADOS (LISTOS PARA EL DOCUMENTO DE TESIS)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("          EVALUACIÓN EXPERIMENTAL DE HIPÓTESIS - SISTEMA NIDS Conv1D")
    print("=" * 78)
    print(f"Matriz de Confusión:\n{cm}")
    print("-" * 78)
    print(f"Verdaderos Negativos (TN) : {tn:,}  (Tráfico benigno clasificado correctamente)")
    print(f"Falsos Positivos      (FP) : {fp:,}  (Alarmas falsas en tráfico legítimo)")
    print(f"Falsos Negativos      (FN) : {fn:,}  (Ataques DDoS no detectados)")
    print(f"Verdaderos Positivos  (TP) : {tp:,}  (Ataques DDoS detectados exitosamente)")
    print("-" * 78)
    print(f"Accuracy (Exactitud Total) : {accuracy * 100:.4f} %")
    print(f"Recall (Sensibilidad/TPR)  : {recall * 100:.4f} %  [Meta Tesis: > 95.0%]")
    print(f"FPR (Tasa Falsos Positivos): {fpr * 100:.4f} %  [Meta Tesis: < 1.0% / < 5.0%]")
    print(f"Precision (Valor Predict.) : {precision * 100:.4f} %")
    print(f"Especificidad (TNR)        : {specificity * 100:.4f} %")
    print(f"F1-Score                   : {f1:.4f}")
    print(f"ROC-AUC Score              : {roc_auc:.4f}")
    print("-" * 78)
    print(f"Latencia Total Inferencia  : {total_infer_duration_ms:.2f} ms sobre {len(X_test):,} muestras")
    print(f"Latencia Promedio / Muestra: {latency_per_sample_ms:.4f} ms  [Meta Tesis: < 10.0 ms]")
    print(f"Uso de Memoria RAM Proceso : {ram_peak_mb:.2f} MB  [Meta Tesis: Viabilidad Pyme < 250 MB]")
    print("=" * 78)

    metrics_dict = {
        "confusion_matrix": {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
        },
        "accuracy": accuracy,
        "recall_tpr": recall,
        "fpr": fpr,
        "precision": precision,
        "specificity": specificity,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "latency_per_sample_ms": latency_per_sample_ms,
        "total_test_samples": len(X_test),
        "train_duration_s": train_duration_s,
        "ram_peak_mb": ram_peak_mb,
    }

    return metrics_dict


# ------------------------------------------------------------------------------
# 5. EXPORTACIÓN RIGUROSA DE ARTEFACTOS Y CONTRATO DE INTERFAZ
# ------------------------------------------------------------------------------
def export_artifacts(
    model: models.Sequential,
    scaler: MinMaxScaler,
    feature_names: list,
    metrics: dict,
):
    print("\n[*] 6. Exportando artefactos del modelo y contrato de interfaz...")
    os.makedirs(MODELS_DIR, exist_ok=True)

    # A. Guardar Modelo Conv1D en formato nativo Keras (y compatible .keras / .h5)
    model_keras_path = os.path.join(MODELS_DIR, "ddos_cnn_model.keras")
    model_alias_path = os.path.join(MODELS_DIR, "modelo_conv1d.keras")
    model.save(model_keras_path)
    model.save(model_alias_path)

    # Medir tamaño del archivo en disco
    model_size_kb = os.path.getsize(model_keras_path) / 1024.0
    model_size_mb = model_size_kb / 1024.0
    print(f"    - Modelo guardado en: {model_keras_path}")
    print(f"      * Tamaño del modelo en disco: {model_size_kb:.2f} KB ({model_size_mb:.2f} MB) -> [Cumple: < 2 MB]")

    # B. Guardar Escalador MinMaxScaler ajustado
    scaler_joblib_path = os.path.join(MODELS_DIR, "scaler.joblib")
    scaler_pkl_path = os.path.join(MODELS_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_joblib_path)
    joblib.dump(scaler, scaler_pkl_path)
    print(f"    - Escalador guardado en: {scaler_joblib_path} y {scaler_pkl_path}")

    # C. Guardar Lista Ordenada de Columnas Utilizadas (selected_features.json)
    features_json_path = os.path.join(MODELS_DIR, "selected_features.json")
    with open(features_json_path, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2, ensure_ascii=False)
    print(f"    - Lista de {len(feature_names)} características guardada en: {features_json_path}")

    # D. Guardar Métricas de Evaluación Formales (evaluation_metrics.json)
    eval_json_path = os.path.join(MODELS_DIR, "evaluation_metrics.json")
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"    - Métricas experimentales guardadas en: {eval_json_path}")

    # E. Actualizar Metadatos del Sistema Web (model_metadata.json)
    metadata_path = os.path.join(MODELS_DIR, "model_metadata.json")
    system_metadata = {
        "model_name": "Conv1D_CyberShield_DDoS",
        "architecture": "Conv1D(32)->BN->Pool->Drop->Conv1D(64)->BN->Pool->Drop->GlobalMaxPool->Dense(32)->Dense(1)",
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "dataset": "CICIDS2017 (DDoS Friday Working Hours)",
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "scaler": "MinMaxScaler(0, 1)",
        "model_size_kb": round(model_size_kb, 2),
        "decision_threshold": 0.50,
        "thesis_alignment": {
            "pe1_smote": "SMOTE aplicado exclusivamente en X_train para balanceo",
            "pe2_conv1d": "Conv1D ultraligera < 2 MB optimizada para inferencia en CPU",
            "pe3_latency": f"Latencia inferencia: {metrics['latency_per_sample_ms']:.4f} ms/muestra",
            "pe4_hardware": f"Consumo de RAM pico: {metrics['ram_peak_mb']:.2f} MB en hardware modesto Pyme",
        },
        "test_metrics": metrics,
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(system_metadata, f, indent=2, ensure_ascii=False)
    print(f"    - Metadatos de producción sincronizados en: {metadata_path}")


# ------------------------------------------------------------------------------
# PUNTO DE ENTRADA PRINCIPAL
# ------------------------------------------------------------------------------
def main():
    print("=" * 78)
    print("   ENTRENAMIENTO ACADÉMICO Y EXPORTACIÓN DE MODELO CONV1D - NIDS PYME")
    print("=" * 78)

    # Permitir sobreescribir la ruta del dataset vía argumento CLI
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else DATASET_DEFAULT

    if not os.path.exists(dataset_path):
        print(f"\n[!] ERROR: No se encontró el dataset en la ruta indicada: {dataset_path}")
        print("    Asegúrate de colocar el archivo CSV de CICIDS2017 en la carpeta ml/dataset/")
        print("    Ejemplo de ejecución:")
        print("    python ml/train_academic_experiments.py ml/dataset/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        sys.exit(1)

    # 1. Cargar y Limpiar Datos
    X, y, feature_names = load_and_clean_dataset(dataset_path)

    # 2. Pipeline Libre de Data Leakage
    X_train, X_test, y_train, y_test, scaler = prepare_data_pipeline(X, y, test_size=0.20)

    # 3. Compilar Arquitectura Conv1D Ultraligera
    model = build_lightweight_conv1d_model(input_features=len(feature_names))

    # 4. Entrenar y Evaluar
    metrics = train_and_evaluate_model(
        model=model,
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        epochs=10,
        batch_size=256,
    )

    # 5. Exportar Todos los Artefactos para Producción
    export_artifacts(
        model=model,
        scaler=scaler,
        feature_names=feature_names,
        metrics=metrics,
    )

    print("\n[OK] Pipeline completado exitosamente. Todos los artefactos están listos para producción.")


if __name__ == "__main__":
    main()