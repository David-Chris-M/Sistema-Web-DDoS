import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras import layers, models

# --- Configuración de Rutas y Constantes ---
DIRECTORIO_ML = os.path.dirname(os.path.abspath(__file__))
RUTA_CONJUNTO_DATOS = os.path.join(DIRECTORIO_ML, "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
DIRECTORIO_MODELOS = os.path.join(DIRECTORIO_ML, "models")

COLUMNAS_A_DESCARTAR = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
    "External IP",
]


def principal():
    # 1. Carga y depuración de datos
    print("\n[*] 1. Cargando conjunto de datos CICIDS2017...")
    if not os.path.exists(RUTA_CONJUNTO_DATOS):
        raise FileNotFoundError(f"No se encontró el archivo de datos en: {RUTA_CONJUNTO_DATOS}")

    datos_crudos = pd.read_csv(RUTA_CONJUNTO_DATOS, low_memory=False)
    datos_crudos.columns = datos_crudos.columns.str.strip()

    # 2. Separación de características y etiqueta objetivo
    print("[*] 2. Codificando etiquetas binarias (0 = BENIGN, 1 = DDoS)...")
    etiquetas_binarias = datos_crudos["Label"].apply(
        lambda valor: 0 if str(valor).strip().upper() == "BENIGN" else 1
    )

    df_caracteristicas = datos_crudos.drop(columns=["Label"])
    columnas_existentes = [col for col in COLUMNAS_A_DESCARTAR if col in df_caracteristicas.columns]
    if columnas_existentes:
        df_caracteristicas.drop(columns=columnas_existentes, inplace=True)

    # 3. Limpieza de valores numéricos
    print("[*] 3. Depurando valores no numéricos, infinitos e indeterminados...")
    df_caracteristicas = df_caracteristicas.apply(pd.to_numeric, errors="coerce")
    df_caracteristicas.replace([np.inf, -np.inf], np.nan, inplace=True)

    filas_validas = ~df_caracteristicas.isna().any(axis=1)
    matriz_X = df_caracteristicas[filas_validas].values.astype(np.float32)
    vector_y = etiquetas_binarias[filas_validas].values

    print(f"[*] Registros limpios preparados: {matriz_X.shape[0]:,} muestras con {matriz_X.shape[1]} atributos.")

    # 4. Partición de datos (Entrenamiento / Prueba)
    print("[*] 4. Dividiendo en partición estratificada (80% entrenamiento / 20% prueba)...")
    X_entrenamiento, X_prueba, y_entrenamiento, y_prueba = train_test_split(
        matriz_X,
        vector_y,
        test_size=0.20,
        random_state=42,
        stratify=vector_y,
    )

    # 5. Normalización estándar
    print("[*] 5. Normalizando características (StandardScaler)...")
    escalador = StandardScaler()
    X_entrenamiento = escalador.fit_transform(X_entrenamiento)
    X_prueba = escalador.transform(X_prueba)

    os.makedirs(DIRECTORIO_MODELOS, exist_ok=True)
    ruta_escalador = os.path.join(DIRECTORIO_MODELOS, "scaler.pkl")
    joblib.dump(escalador, ruta_escalador)
    print(f"[*] Escalador exportado exitosamente en: {ruta_escalador}")

    # 6. Balanceo sintético con SMOTE
    print("[*] 6. Aplicando balanceo sintético con SMOTE en entrenamiento...")
    print(f"    - Distribución inicial: Benigno={np.sum(y_entrenamiento == 0):,}, DDoS={np.sum(y_entrenamiento == 1):,}")
    from imblearn.over_sampling import SMOTE
    sobremuestreador_smote = SMOTE(random_state=42)
    X_entrenamiento_res, y_entrenamiento = sobremuestreador_smote.fit_resample(X_entrenamiento, y_entrenamiento)
    print(f"    - Distribución balanceada: Benigno={np.sum(y_entrenamiento == 0):,}, DDoS={np.sum(y_entrenamiento == 1):,}")

    # 7. Redimensionamiento tensorial 3D
    X_entrenamiento = X_entrenamiento_res.reshape((X_entrenamiento_res.shape[0], X_entrenamiento_res.shape[1], 1))
    X_prueba = X_prueba.reshape((X_prueba.shape[0], X_prueba.shape[1], 1))

    # 8. Construcción de la arquitectura Conv1D
    print("\n[*] 7. Construyendo arquitectura convolucional Conv1D...")
    modelo = models.Sequential([
        layers.Input(shape=(X_entrenamiento.shape[1], 1)),
        layers.Conv1D(filters=32, kernel_size=3, activation="relu"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.20),

        layers.Conv1D(filters=64, kernel_size=3, activation="relu"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.20),

        layers.Flatten(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.30),
        layers.Dense(1, activation="sigmoid"),
    ], name="Conv1D_Detector_DDoS")

    modelo.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )

    modelo.summary()

    # 9. Entrenamiento del modelo
    print("\n[*] 8. Iniciando ciclo de entrenamiento...")
    modelo.fit(
        X_entrenamiento,
        y_entrenamiento,
        epochs=10,
        batch_size=256,
        validation_split=0.10,
        verbose=1,
    )

    # 10. Evaluación experimental
    print("\n[*] 9. Evaluando desempeño con conjunto de prueba...")
    probabilidades_predichas = modelo.predict(X_prueba, batch_size=256, verbose=0)
    clases_predichas = (probabilidades_predichas >= 0.50).astype(int).flatten()

    print("\n" + "=" * 50)
    print("           MATRIZ DE CONFUSIÓN")
    print("=" * 50)
    print(confusion_matrix(y_prueba, clases_predichas))

    print("\n" + "=" * 50)
    print("        REPORTE DE CLASIFICACIÓN")
    print("=" * 50)
    print(classification_report(y_prueba, clases_predichas, target_names=["BENIGN", "DDoS"]))

    # 11. Exportación del modelo
    ruta_modelo = os.path.join(DIRECTORIO_MODELOS, "ddos_cnn_model.keras")
    modelo.save(ruta_modelo)
    print(f"\n[OK] Modelo exportado exitosamente en: {ruta_modelo}")


if __name__ == "__main__":
    principal()
