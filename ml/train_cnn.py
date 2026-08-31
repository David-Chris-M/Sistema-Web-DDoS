import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras import layers, models

# 1. Carga de datos
DATASET_PATH = os.path.join("dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
print("[*] Cargando dataset...")
df = pd.read_csv(DATASET_PATH)

# Limpiar espacios en blanco de los nombres de columnas
df.columns = df.columns.str.strip()

# 2. Separacion de etiqueta y caracteristicas
print("[*] Procesando etiquetas...")
y = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

# Eliminar la etiqueta del DataFrame
df_features = df.drop(columns=['Label'])

# 3. Eliminar columnas de identificadores/texto no numericos
columnas_a_descartar = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'SimillarHTTP', 'External IP']
columnas_existentes = [col for col in columnas_a_descartar if col in df_features.columns]
df_features.drop(columns=columnas_existentes, inplace=True)

# 4. Forzar conversion a numerico y limpiar NaN/Infinitos
print("[*] Limpiando valores no numericos e infinitos...")
df_features = df_features.apply(pd.to_numeric, errors='coerce')
df_features.replace([np.inf, -np.inf], np.nan, inplace=True)

# Filtrar tanto caracteristicas como etiquetas donde existan valores nulos
filas_validas = ~df_features.isna().any(axis=1)
X = df_features[filas_validas].values.astype(np.float32)
y = y[filas_validas].values

print(f"[*] Registros limpios listos para entrenar: {X.shape[0]} muestras con {X.shape[1]} caracteristicas.")

# 5. Division en train y test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 6. Normalizacion
print("[*] Normalizando datos...")
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Guardar el scaler para la API REST
os.makedirs("models", exist_ok=True)
joblib.dump(scaler, os.path.join("models", "scaler.pkl"))
print("[*] Escalador guardado en: models/scaler.pkl")

# 7. Redimensionamiento para Conv1D: (muestras, caracteristicas, canales)
X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
X_test = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))

# 8. Construccion de la arquitectura Conv1D
print("[*] Configurando red neuronal Conv1D...")
model = models.Sequential([
    layers.Conv1D(filters=32, kernel_size=3, activation='relu', input_shape=(X_train.shape[1], 1)),
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
    metrics=['accuracy', tf.keras.metrics.Precision(name='precision'), tf.keras.metrics.Recall(name='recall')]
)

model.summary()

# 9. Entrenamiento del modelo
print("[*] Iniciando entrenamiento...")
history = model.fit(
    X_train, y_train,
    epochs=10,
    batch_size=256,
    validation_split=0.1,
    verbose=1
)

# 10. Evaluacion
print("\n[*] Evaluando modelo con el conjunto de prueba...")
y_pred_prob = model.predict(X_test)
y_pred = (y_pred_prob > 0.5).astype(int)

print("\n--- MATRIZ DE CONFUSION ---")
print(confusion_matrix(y_test, y_pred))

print("\n--- REPORTE DE METRICAS ---")
print(classification_report(y_test, y_pred, target_names=['BENIGN', 'DDoS']))

# 11. Guardar modelo entrenado
model_path = os.path.join("models", "ddos_cnn_model.keras")
model.save(model_path)
print(f"[*] Modelo guardado exitosamente en: {model_path}")