import json
import os
import random
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

# --- Semillas reproducibles (Python, NumPy, TensorFlow) ---
SEMILLA = 42
os.environ["PYTHONHASHSEED"] = str(SEMILLA)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
random.seed(SEMILLA)
np.random.seed(SEMILLA)

import tensorflow as tf
from tensorflow.keras import callbacks, layers, models

tf.random.set_seed(SEMILLA)
tf.keras.utils.set_random_seed(SEMILLA)

# --- Configuración de Rutas y Constantes ---
DIRECTORIO_ML = os.path.dirname(os.path.abspath(__file__))
DIRECTORIO_BASE = os.path.dirname(DIRECTORIO_ML)
if DIRECTORIO_BASE not in sys.path:
    sys.path.insert(0, DIRECTORIO_BASE)

from backend.inferencia import CARACTERISTICAS_CANONICAS, MotorConv1DLigero

RUTA_CONJUNTO_DATOS = os.path.join(
    DIRECTORIO_ML, "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)
DIRECTORIO_MODELOS = os.path.join(DIRECTORIO_ML, "models")

COLUMNAS_A_DESCARTAR = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
    "SimillarHTTP",
    "External IP",
    "Source Port",
    "Destination Port",
    "Fwd Header Length.1",
]


def cargar_y_limpiar_datos(ruta_csv: str):
    print(f"\n[*] 1. Cargando conjunto de datos CICIDS2017: {ruta_csv}")
    if not os.path.exists(ruta_csv):
        raise FileNotFoundError(f"No se encontró el archivo de datos en: {ruta_csv}")

    datos_crudos = pd.read_csv(ruta_csv, low_memory=False)
    datos_crudos.columns = datos_crudos.columns.str.strip()

    if "Label" not in datos_crudos.columns:
        raise ValueError("El conjunto de datos no contiene la columna objetivo 'Label'.")

    print("[*] 2. Codificando etiquetas binarias (0 = BENIGN, 1 = DDoS)...")
    etiquetas_texto = datos_crudos["Label"].astype(str).str.strip().str.upper()
    etiquetas_binarias = np.where(etiquetas_texto == "BENIGN", 0, 1).astype(np.int32)

    df_caracteristicas = datos_crudos.drop(columns=["Label"])
    columnas_existentes = [col for col in COLUMNAS_A_DESCARTAR if col in df_caracteristicas.columns]
    if columnas_existentes:
        df_caracteristicas = df_caracteristicas.drop(columns=columnas_existentes)
        print(f"    - Columnas descartadas ({len(columnas_existentes)}): {columnas_existentes}")

    # Preservar orden canónico exacto respecto a CARACTERISTICAS_CANONICAS
    nombres_ordenados = [c for c in CARACTERISTICAS_CANONICAS if c in df_caracteristicas.columns]
    if len(nombres_ordenados) != df_caracteristicas.shape[1]:
        desconocidas = [c for c in df_caracteristicas.columns if c not in CARACTERISTICAS_CANONICAS]
        raise ValueError(f"Columnas fuera del contrato canónico: {desconocidas}")
    df_caracteristicas = df_caracteristicas[nombres_ordenados]

    print("[*] 3. Limpiando no numéricos, +inf/-inf -> NaN y eliminando filas incompletas (dropna)...")
    df_caracteristicas = df_caracteristicas.apply(pd.to_numeric, errors="coerce")
    df_caracteristicas = df_caracteristicas.replace([np.inf, -np.inf], np.nan)

    filas_validas = ~df_caracteristicas.isna().any(axis=1)
    descartadas = int((~filas_validas).sum())
    matriz_X = df_caracteristicas.loc[filas_validas].to_numpy(dtype=np.float32)
    vector_y = etiquetas_binarias[filas_validas.to_numpy()]

    print(
        f"    - Registros limpios: {matriz_X.shape[0]:,} (descartados por NaN/Inf: {descartadas:,}) "
        f"x {matriz_X.shape[1]} características."
    )
    print(
        f"    - Clases limpias: BENIGN={int(np.sum(vector_y == 0)):,} ({np.mean(vector_y == 0) * 100:.2f}%) | "
        f"DDoS={int(np.sum(vector_y == 1)):,} ({np.mean(vector_y == 1) * 100:.2f}%)"
    )
    return matriz_X, vector_y, nombres_ordenados, columnas_existentes


def construir_modelo_conv1d(n_caracteristicas: int) -> models.Sequential:
    modelo = models.Sequential(
        [
            layers.Input(shape=(n_caracteristicas, 1)),
            layers.Conv1D(filters=32, kernel_size=3, padding="same", activation="relu"),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.20),
            layers.Conv1D(filters=64, kernel_size=3, padding="same", activation="relu"),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.20),
            layers.Flatten(),
            layers.Dense(64, activation="relu"),
            layers.Dropout(0.30),
            layers.Dense(1, activation="sigmoid"),
        ],
        name="Conv1D_DDoS_Classifier",
    )
    modelo.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )
    return modelo


def medir_latencia_motor_ligero(
    ruta_modelo: str, escalador: MinMaxScaler, X_test_crudo: np.ndarray
) -> dict:
    motor_ligero = MotorConv1DLigero(ruta_modelo)

    def inferir_e2e(X_bloque: np.ndarray) -> np.ndarray:
        X_s = np.nan_to_num(np.asarray(X_bloque, dtype=np.float64), nan=0.0, posinf=1e12, neginf=-1e12)
        X_s = np.clip(X_s, -1e12, 1e12)
        X_esc = escalador.transform(X_s)
        X_esc = np.nan_to_num(X_esc, nan=0.0, posinf=1.0, neginf=0.0)
        X_esc = np.clip(X_esc, 0.0, 1.0).astype(np.float32, copy=False)
        return motor_ligero(X_esc.reshape(X_esc.shape[0], X_esc.shape[1], 1))

    # 1. Latencia en frío (primer flujo individual)
    t0_frio = time.perf_counter()
    _ = inferir_e2e(X_test_crudo[:1])
    single_flow_cold_ms = (time.perf_counter() - t0_frio) * 1000.0

    # 2. Latencia en caliente por flujo individual (200 flujos secuenciales)
    n_muestras_unit = min(200, len(X_test_crudo))
    latencias_unitarias = []
    for idx in range(n_muestras_unit):
        t0 = time.perf_counter()
        _ = inferir_e2e(X_test_crudo[idx : idx + 1])
        latencias_unitarias.append((time.perf_counter() - t0) * 1000.0)
    single_flow_warm_ms = float(np.mean(latencias_unitarias))
    p95_single_flow_ms = float(np.percentile(latencias_unitarias, 95))

    # 3. Latencia promedio por flujo en lotes de 256 sobre todo el conjunto Test
    probs_ligero = []
    t0_lotes = time.perf_counter()
    for inicio in range(0, len(X_test_crudo), 256):
        probs_ligero.append(inferir_e2e(X_test_crudo[inicio : inicio + 256]))
    duracion_lotes_ms = (time.perf_counter() - t0_lotes) * 1000.0
    avg_per_flow_ms = duracion_lotes_ms / max(1, len(X_test_crudo))

    return {
        "probs_ligero": np.concatenate(probs_ligero),
        "avg_per_flow_ms": round(float(avg_per_flow_ms), 4),
        "single_flow_cold_ms": round(float(single_flow_cold_ms), 4),
        "single_flow_warm_ms": round(float(single_flow_warm_ms), 4),
        "p95_single_flow_ms": round(float(p95_single_flow_ms), 4),
        "he2_limit_ms": 100.0,
        "strict_limit_ms": 50.0,
        "measured_engine": "MotorConv1DLigero",
    }


def principal(ruta_csv: str = None):
    ruta_objetivo = ruta_csv or (sys.argv[1] if len(sys.argv) > 1 else RUTA_CONJUNTO_DATOS)
    matriz_X, vector_y, nombres_caracteristicas, columnas_descartadas = cargar_y_limpiar_datos(ruta_objetivo)
    n_caracteristicas = len(nombres_caracteristicas)
    if n_caracteristicas != 77:
        raise ValueError(f"Se esperaban 77 características efectivas y se obtuvieron {n_caracteristicas}.")

    # 4. Partición estratificada estricta 70% Train / 15% Val / 15% Test (ANTES de escalar/SMOTE)
    print("\n[*] 4. Particionando estratificadamente: 70% Train / 15% Validación / 15% Test...")
    X_train_raw, X_temp_raw, y_train_raw, y_temp = train_test_split(
        matriz_X, vector_y, test_size=0.30, random_state=SEMILLA, stratify=vector_y
    )
    X_val_raw, X_test_raw, y_val, y_test = train_test_split(
        X_temp_raw, y_temp, test_size=0.50, random_state=SEMILLA, stratify=y_temp
    )
    print(f"    - Train (70%): {len(y_train_raw):,} muestras (BENIGN={int(np.sum(y_train_raw == 0)):,}, DDoS={int(np.sum(y_train_raw == 1)):,})")
    print(f"    - Val   (15%): {len(y_val):,} muestras (BENIGN={int(np.sum(y_val == 0)):,}, DDoS={int(np.sum(y_val == 1)):,}) [100% reales]")
    print(f"    - Test  (15%): {len(y_test):,} muestras (BENIGN={int(np.sum(y_test == 0)):,}, DDoS={int(np.sum(y_test == 1)):,}) [100% reales]")

    # 5. MinMaxScaler [0, 1] ajustado EXCLUSIVAMENTE en Train
    print("\n[*] 5. Ajustando MinMaxScaler(0, 1) SOLO sobre Train y transformando Val/Test...")
    escalador = MinMaxScaler(feature_range=(0.0, 1.0))
    X_train_esc = escalador.fit_transform(X_train_raw).astype(np.float32)
    X_val_esc = np.clip(escalador.transform(X_val_raw), 0.0, 1.0).astype(np.float32)
    X_test_esc = np.clip(escalador.transform(X_test_raw), 0.0, 1.0).astype(np.float32)

    # 6. SMOTE EXCLUSIVAMENTE en Train + barajado determinista
    print("\n[*] 6. Aplicando SMOTE(random_state=42) SOLO en Train y barajando antes de entrenar...")
    sobremuestreador_smote = SMOTE(random_state=SEMILLA)
    X_train_bal, y_train_bal = sobremuestreador_smote.fit_resample(X_train_esc, y_train_raw)
    rng = np.random.default_rng(SEMILLA)
    perm = rng.permutation(len(y_train_bal))
    X_train_bal = np.clip(X_train_bal[perm], 0.0, 1.0).astype(np.float32)
    y_train_bal = y_train_bal[perm]
    print(
        f"    - Train tras SMOTE y barajado: {len(y_train_bal):,} muestras "
        f"(BENIGN={int(np.sum(y_train_bal == 0)):,}, DDoS={int(np.sum(y_train_bal == 1)):,})"
    )

    # 7. Redimensionamiento tensorial 3D
    X_train_3d = X_train_bal.reshape((X_train_bal.shape[0], n_caracteristicas, 1))
    X_val_3d = X_val_esc.reshape((X_val_esc.shape[0], n_caracteristicas, 1))
    X_test_3d = X_test_esc.reshape((X_test_esc.shape[0], n_caracteristicas, 1))

    # 8. Construcción y entrenamiento Conv1D con validación 100% real
    print("\n[*] 7. Construyendo arquitectura Conv1D CPU-Only (77 características)...")
    modelo = construir_modelo_conv1d(n_caracteristicas)
    modelo.summary()

    lista_callbacks = [
        callbacks.EarlyStopping(
            monitor="val_loss",
            patience=4,
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

    print("\n[*] 8. Entrenando con validation_data=(X_val, y_val) 100% real...")
    t0_entrenamiento = time.perf_counter()
    historial = modelo.fit(
        X_train_3d,
        y_train_bal,
        epochs=20,
        batch_size=256,
        validation_data=(X_val_3d, y_val),
        shuffle=True,
        callbacks=lista_callbacks,
        verbose=2,
    )
    duracion_entrenamiento_s = round(time.perf_counter() - t0_entrenamiento, 2)
    epocas_ejecutadas = len(historial.history.get("loss", []))

    # 9. Exportación sincronizada de modelo y escalador
    os.makedirs(DIRECTORIO_MODELOS, exist_ok=True)
    ruta_modelo = os.path.join(DIRECTORIO_MODELOS, "ddos_cnn_model.keras")
    ruta_escalador = os.path.join(DIRECTORIO_MODELOS, "scaler.pkl")
    ruta_metadatos = os.path.join(DIRECTORIO_MODELOS, "model_metadata.json")

    modelo.save(ruta_modelo)
    joblib.dump(escalador, ruta_escalador)
    tamano_modelo_kb = round(os.path.getsize(ruta_modelo) / 1024.0, 2)

    # 10. Evaluación real en Test (15%) y paridad + latencia en MotorConv1DLigero
    print("\n[*] 9. Evaluando desempeño real en conjunto Test (15%) y latencia en MotorConv1DLigero...")
    probs_keras = modelo.predict(X_test_3d, batch_size=256, verbose=0).reshape(-1)
    bench_ligero = medir_latencia_motor_ligero(ruta_modelo, escalador, X_test_raw)
    probs_ligero = bench_ligero.pop("probs_ligero")
    max_diff_motor = float(np.max(np.abs(probs_keras - probs_ligero)))

    clases_predichas = (probs_ligero >= 0.50).astype(int)
    mc = confusion_matrix(y_test, clases_predichas, labels=[0, 1])
    tn, fp, fn, tp = mc.ravel()

    exactitud = float(accuracy_score(y_test, clases_predichas))
    precision = float(precision_score(y_test, clases_predichas, zero_division=0))
    sensibilidad = float(recall_score(y_test, clases_predichas, zero_division=0))
    puntuacion_f1 = float(f1_score(y_test, clases_predichas, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    especificidad = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_test, probs_ligero)) if len(np.unique(y_test)) > 1 else 0.0

    print("\n" + "=" * 74)
    print("        EVALUACIÓN REAL EN TEST (15%) - NIDS Conv1D (77 FEATURES)")
    print("=" * 74)
    print(f"Matriz de Confusión [labels=0,1]:\n{mc}")
    print(f"TN={tn:,} | FP={fp:,} | FN={fn:,} | TP={tp:,}")
    print("-" * 74)
    print(f"Accuracy  : {exactitud * 100:.4f}%  [Meta >90% | Exigente >=95%]")
    print(f"Precision : {precision * 100:.4f}%")
    print(f"Recall    : {sensibilidad * 100:.4f}%  [Meta >85% | Exigente >=95%]")
    print(f"F1-Score  : {puntuacion_f1:.4f}")
    print(f"FPR       : {fpr * 100:.4f}%  [Meta <5%  | Exigente <1%]")
    print(f"ROC-AUC   : {roc_auc:.6f}")
    print("-" * 74)
    print(
        f"Latencia MotorConv1DLigero: unitaria_fria={bench_ligero['single_flow_cold_ms']:.4f} ms | "
        f"unitaria_caliente={bench_ligero['single_flow_warm_ms']:.4f} ms | "
        f"p95={bench_ligero['p95_single_flow_ms']:.4f} ms | "
        f"lote_prom={bench_ligero['avg_per_flow_ms']:.4f} ms/flujo"
    )
    print(f"Paridad Keras vs MotorConv1DLigero (max |diff|): {max_diff_motor:.6e}")
    print(f"Tamaño modelo en disco: {tamano_modelo_kb:.2f} KB | Entrenamiento: {duracion_entrenamiento_s:.2f}s ({epocas_ejecutadas} épocas)")
    print("=" * 74)
    print(classification_report(y_test, clases_predichas, target_names=["BENIGN", "DDoS"], digits=4))

    metadatos = {
        "model_name": "Conv1D_DDoS_Classifier",
        "architecture": "Conv1D(32)->BN->MaxPool->Drop->Conv1D(64)->BN->MaxPool->Drop->Flatten->Dense(64)->Drop->Dense(1)",
        "trained_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "dataset": f"CICIDS2017 ({os.path.basename(ruta_objetivo)})",
        "split": {
            "train": 0.70,
            "val": 0.15,
            "test": 0.15,
            "stratified": True,
            "random_state": SEMILLA,
            "train_samples_pre_smote": int(len(y_train_raw)),
            "train_samples_post_smote": int(len(y_train_bal)),
            "val_samples": int(len(y_val)),
            "test_samples": int(len(y_test)),
        },
        "n_features": n_caracteristicas,
        "feature_names": nombres_caracteristicas,
        "dropped_features": columnas_descartadas,
        "scaler": "MinMaxScaler(0, 1)",
        "model_size_kb": tamano_modelo_kb,
        "decision_threshold": 0.5,
        "thesis_alignment": {
            "pe1_smote": "SMOTE(random_state=42) aplicado exclusivamente sobre Train (70%) tras partición 70/15/15 y MinMaxScaler [0,1]",
            "pe2_conv1d": "Conv1D 2 capas convolucionales + BatchNorm + MaxPooling + Dropout + Flatten + Dense(64) sobre 77 features",
            "pe3_fastapi": f"MotorConv1DLigero CPU-Only: {bench_ligero['single_flow_warm_ms']:.3f} ms/flujo (< 50 ms / < 100 ms)",
            "pe4_hardware": f"Modelo {tamano_modelo_kb:.1f} KB en ejecución CPU-Only sin GPU",
        },
        "smote": {
            "applied": True,
            "random_state": SEMILLA,
            "applied_only_to": "train",
        },
        "test_metrics": {
            "accuracy": round(exactitud, 6),
            "precision": round(precision, 6),
            "recall": round(sensibilidad, 6),
            "f1_score": round(puntuacion_f1, 6),
            "fpr": round(fpr, 6),
            "specificity": round(especificidad, 6),
            "roc_auc": round(roc_auc, 6),
            "confusion_matrix": {
                "TN": int(tn),
                "FP": int(fp),
                "FN": int(fn),
                "TP": int(tp),
            },
            "total_test_samples": int(len(y_test)),
            "epochs_trained": epocas_ejecutadas,
            "train_duration_s": duracion_entrenamiento_s,
            "max_engine_parity_diff": round(max_diff_motor, 8),
        },
        "latency": bench_ligero,
    }

    with open(ruta_metadatos, "w", encoding="utf-8") as archivo_meta:
        json.dump(metadatos, archivo_meta, indent=2, ensure_ascii=False)

    print(f"\n[OK] Artefactos sincronizados exportados:")
    print(f"     - Modelo    : {ruta_modelo}")
    print(f"     - Escalador : {ruta_escalador}")
    print(f"     - Metadatos : {ruta_metadatos}")
    return metadatos


if __name__ == "__main__":
    principal()
