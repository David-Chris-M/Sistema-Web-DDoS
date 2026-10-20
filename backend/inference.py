"""Motor de inferencia Conv1D aislado del event loop de FastAPI.

Decisiones de diseño (auditoría):
- `tf.function` con firma fija: evita el overhead del modo eager (p50 medido 8.9 ms -> 0.9 ms).
- Un único hilo dedicado (ThreadPoolExecutor(max_workers=1)): serializa TensorFlow, evita la
  sobre-suscripción de CPU en servidores Pyme y nunca bloquea WebSockets ni otras peticiones.
- Contrato de características explícito: el sensor SIEMPRE envía las 80 columnas canónicas de
  CICFlowMeter; si el modelo se entrenó con un subconjunto (p. ej. sin puertos), se seleccionan aquí.
- Fallo explícito: si faltan artefactos, `ready=False` y la API responde 503 (no 500 silencioso).
"""
import asyncio
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple

import numpy as np

from backend.config import settings

logger = logging.getLogger("cybershield.inference")

# Orden canónico de las 80 características (CICIDS2017 / CICFlowMeter, sin identificadores).
CANONICAL_FEATURES = [
    "Source Port", "Destination Port", "Protocol", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]
N_CANONICAL = len(CANONICAL_FEATURES)  # 80


class InferenceEngine:
    def __init__(self) -> None:
        self.ready = False
        self.error: Optional[str] = None
        self.metadata: dict = {}
        self.n_model_features = 0
        self._feature_idx: Optional[np.ndarray] = None
        self._scaler = None
        self._fn = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tf-infer")

    # ------------------------------------------------------------------ carga
    def load(self) -> None:
        try:
            for p in (settings.model_path, settings.scaler_path):
                if not os.path.exists(p):
                    raise FileNotFoundError(f"No existe el artefacto requerido: {p}")

            import joblib
            import tensorflow as tf

            tf.config.threading.set_intra_op_parallelism_threads(settings.tf_intra_threads)
            tf.config.threading.set_inter_op_parallelism_threads(1)

            model = tf.keras.models.load_model(settings.model_path, compile=False)
            scaler = joblib.load(settings.scaler_path)
            n_in = int(model.input_shape[1])
            n_scaler = int(getattr(scaler, "n_features_in_", n_in))
            if n_scaler != n_in:
                raise ValueError(f"Scaler ({n_scaler}) y modelo ({n_in}) esperan dimensiones distintas")

            if os.path.exists(settings.metadata_path):
                with open(settings.metadata_path, encoding="utf-8") as fh:
                    self.metadata = json.load(fh)
            names = self.metadata.get("feature_names") or (CANONICAL_FEATURES if n_in == N_CANONICAL else None)
            if names is None or len(names) != n_in:
                raise ValueError("model_metadata.json no define 'feature_names' coherentes con el modelo")
            unknown = [n for n in names if n not in CANONICAL_FEATURES]
            if unknown:
                raise ValueError(f"Características desconocidas en metadata: {unknown}")
            idx = np.array([CANONICAL_FEATURES.index(n) for n in names])
            self._feature_idx = None if np.array_equal(idx, np.arange(N_CANONICAL)) else idx

            self._fn = tf.function(
                lambda x: model(x, training=False),
                input_signature=[tf.TensorSpec([None, n_in, 1], tf.float32)],
                reduce_retracing=True,
            )
            self._tf = tf
            self._scaler = scaler
            self.n_model_features = n_in
            for bs in (1, 64):  # warm-up: la primera llamada traza el grafo (~cientos de ms)
                self._predict_sync(np.zeros((bs, N_CANONICAL), dtype=np.float32))
            self.ready = True
            logger.info("Modelo Conv1D listo: %d características, scaler=%s", n_in, type(scaler).__name__)
        except Exception as exc:  # pragma: no cover - ruta de error de arranque
            self.ready = False
            self.error = str(exc)
            logger.critical("El modelo NO está disponible; /api/predict responderá 503: %s", exc)

    # -------------------------------------------------------------- inferencia
    def _predict_sync(self, X: np.ndarray) -> Tuple[np.ndarray, float]:
        if self._feature_idx is not None:
            X = X[:, self._feature_idx]
        Xs = self._scaler.transform(X).astype(np.float32, copy=False)
        t0 = time.perf_counter()
        probs = self._fn(self._tf.constant(Xs.reshape(Xs.shape[0], Xs.shape[1], 1))).numpy().reshape(-1)
        return probs, (time.perf_counter() - t0) * 1000.0

    async def predict(self, X: np.ndarray) -> Tuple[np.ndarray, float]:
        """Devuelve (probabilidades, ms de cómputo del modelo para todo el lote)."""
        if not self.ready:
            raise RuntimeError(self.error or "Modelo no cargado")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._predict_sync, X)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


engine = InferenceEngine()
