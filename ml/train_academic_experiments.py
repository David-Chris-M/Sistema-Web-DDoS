import os
import time
import joblib
import psutil
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, recall_score, precision_score, f1_score
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow.keras import layers, models

def get_resource_usage():
    """Registra uso de CPU y Memoria RAM (PE4 / HE4)"""
    cpu_percent = psutil.cpu_percent(interval=None)
    ram_info = psutil.virtual_memory()
    ram_used_mb = ram_info.used / (1024 * 1024)
    return cpu_percent, ram_used_mb

# --- 1. Carga y Depuración de Datos ---
ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(ML_DIR, "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
MODELS_DIR = os.path.join(ML_DIR, "models")

print("[*] 1. Cargando dataset CICIDS2017...")
df = pd.read_csv(DATASET_PATH)
df.columns = df.columns.str.strip()

# Etiquetas binarias: 0 BENIGN, 1 DDoS
y = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
df_features = df.drop(columns=['Label'])

# Descartar identificadores no numéricos
cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'SimillarHTTP', 'External IP']
df_features.drop(columns=[c for c in cols_to_drop if c in df_features.columns], inplace=True)

# Limpieza numérica
df_features = df_features.apply(pd.to_numeric, errors='coerce')
df_features.replace([np.inf, -np.inf], np.nan, inplace=True)
valid_idx = ~df_features.isna().any(axis=1)

X = df_features[valid_idx].values.astype(np.float32)
y = y[valid_idx].values

print(f"[*] Datos limpios: {X.shape[0]} muestras con {X.shape[1]} características.")

# --- 2. División de Datos y Normalización ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Guardar escalador en MODELS_DIR
os.makedirs(MODELS_DIR, exist_ok=True)
joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))

# --- 3. Aplicación de SMOTE (PE1: Balanceo de Clases) ---
print("[*] 2. Aplicando balanceo con SMOTE...")
print(f"    Distribución antes de SMOTE: Benign={np.sum(y_train==0)}, DDoS={np.sum(y_train==1)}")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
print(f"    Distribución después de SMOTE: Benign={np.sum(y_train_res==0)}, DDoS={np.sum(y_train_res==1)}")

# Redimensionar para Conv1D (muestras, características, 1)
X_train_final = X_train_res.reshape((X_train_res.shape[0], X_train_res.shape[1], 1))
X_test_final = X_test_scaled.reshape((X_test_scaled.shape[0], X_test_scaled.shape[1], 1))

# --- 4. Construcción de Arquitectura Conv1D (PE2) ---
print("[*] 3. Construyendo modelo Conv1D...")
model = models.Sequential([
    layers.Input(shape=(X_train_final.shape[1], 1)),
    layers.Conv1D(filters=32, kernel_size=3, activation='relu'),
    layers.MaxPooling1D(pool_size=2),
    layers.Dropout(0.2),
    layers.Conv1D(filters=64, kernel_size=3, activation='relu'),
    layers.MaxPooling1D(pool_size=2),
    layers.Dropout(0.2),
    layers.Flatten(),
    layers.Dense(64, activation='relu'),
    layers.Dropout(0.3),
    layers.Dense(1, activation='sigmoid')
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy', tf.keras.metrics.Recall(name='recall'), tf.keras.metrics.Precision(name='precision')]
)

# --- 5. Entrenamiento y Monitoreo de Recursos (PE4) ---
print("[*] 4. Entrenando modelo...")
start_train_time = time.time()
cpu_start, ram_start = get_resource_usage()

history = model.fit(
    X_train_final, y_train_res,
    epochs=10,
    batch_size=256,
    validation_split=0.1,
    verbose=1
)

train_duration = time.time() - start_train_time
cpu_end, ram_end = get_resource_usage()

# --- 6. Evaluación de Rendimiento y Latencia de Inferencia (PE2 y PE3) ---
print("\n[*] 5. Evaluando latencia de inferencia...")
start_infer = time.time()
y_pred_prob = model.predict(X_test_final, batch_size=256, verbose=0)
infer_duration = (time.time() - start_infer) * 1000  # En ms

latency_per_sample_ms = infer_duration / len(X_test_final)
y_pred = (y_pred_prob > 0.5).astype(int).flatten()

# Matriz de Confusión y Tasa de Falsos Positivos (FPR)
cm = confusion_matrix(y_test, y_pred)
TN, FP, FN, TP = cm.ravel()
fpr = FP / (FP + TN)
accuracy = accuracy_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\n================ RESULTADOS EXPERIMENTALES (WORD/TESIS) ================")
print(f"Matriz de Confusión:\n{cm}")
print(f"TN: {TN} | FP: {FP} | FN: {FN} | TP: {TP}")
print(f"Accuracy (Exactitud) : {accuracy * 100:.4f} %")
print(f"Recall (Sensibilidad): {recall * 100:.4f} %")
print(f"Precision            : {precision * 100:.4f} %")
print(f"F1-Score             : {f1 * 100:.4f}")
print(f"FPR (Tasa Falsos Pos): {fpr * 100:.4f} % (Meta H1: < 5%)")
print(f"Latencia Total Inf.  : {infer_duration:.2f} ms")
print(f"Latencia por Muestra : {latency_per_sample_ms:.4f} ms (Meta H2: < 100 ms)")
print(f"Tiempo Entrenamiento : {train_duration:.2f} s")
print(f"Uso de RAM Final     : {ram_end:.2f} MB (PE4: Viabilidad en Pyme)")
print("=========================================================================")

# --- 7. Guardar Artefactos ---
model_path = os.path.join(MODELS_DIR, "ddos_cnn_model.keras")
model.save(model_path)
print(f"[*] Modelo actualizado guardado en: {model_path}")