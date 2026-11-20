import asyncio
import io
import json
import logging
import os
import socket
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Tuple

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

from backend.configuracion import configuracion

registro_logger = logging.getLogger("cybershield.inference")


def _detectar_ips_locales_inferencia() -> set[str]:
    ips = {"127.0.0.1"}
    ip_env = (os.getenv("LOCAL_HOST_IP") or "").strip()
    if ip_env:
        ips.add(ip_env)
    for destino in (("8.8.8.8", 80), ("1.1.1.1", 80)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(destino)
                ip_local = s.getsockname()[0]
                if ip_local and not ip_local.startswith("169.254."):
                    ips.add(ip_local)
        except Exception:
            pass
    try:
        for ip_local in socket.gethostbyname_ex(socket.gethostname())[2]:
            if ip_local and not ip_local.startswith("169.254."):
                ips.add(ip_local)
    except Exception:
        pass
    return ips


IPS_LOCALES_HOST: set[str] = _detectar_ips_locales_inferencia()

# --- Contrato de Características Canónicas (CICFlowMeter / CICIDS2017) ---
CARACTERISTICAS_CANONICAS = [
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
TOTAL_CANONICAS = len(CARACTERISTICAS_CANONICAS)


# --- Funciones de Activación ---
def _aplicar_activacion(x: np.ndarray, nombre: Optional[str]) -> np.ndarray:
    act = (nombre or "linear").lower()
    if act == "linear":
        return x
    if act == "relu":
        return np.maximum(x, np.float32(0.0), out=x)
    if act == "sigmoid":
        x_acotado = np.clip(x, np.float32(-88.0), np.float32(88.0))
        return (np.float32(1.0) / (np.float32(1.0) + np.exp(-x_acotado))).astype(np.float32, copy=False)
    if act == "tanh":
        return np.tanh(x, out=x)
    if act == "elu":
        return np.where(x >= 0.0, x, np.expm1(np.clip(x, -88.0, 0.0))).astype(np.float32, copy=False)
    if act == "swish" or act == "silu":
        sig = np.float32(1.0) / (np.float32(1.0) + np.exp(-np.clip(x, np.float32(-88.0), np.float32(88.0))))
        return (x * sig).astype(np.float32, copy=False)
    if act == "softmax":
        desplazado = x - np.max(x, axis=-1, keepdims=True)
        exps = np.exp(desplazado)
        return (exps / np.sum(exps, axis=-1, keepdims=True)).astype(np.float32, copy=False)
    raise NotImplementedError(f"Activación '{nombre}' requiere respaldo TensorFlow")


# --- Ejecutor Ligero Conv1D (im2col + BLAS) ---
class MotorConv1DLigero:
    CAPAS_SOPORTADAS = {
        "InputLayer",
        "Conv1D",
        "MaxPooling1D",
        "AveragePooling1D",
        "GlobalAveragePooling1D",
        "GlobalMaxPooling1D",
        "BatchNormalization",
        "Dropout",
        "SpatialDropout1D",
        "Flatten",
        "Dense",
    }
    PREFIJOS_H5_KERAS3 = {
        "Conv1D": "conv1d",
        "MaxPooling1D": "max_pooling1d",
        "AveragePooling1D": "average_pooling1d",
        "GlobalAveragePooling1D": "global_average_pooling1d",
        "GlobalMaxPooling1D": "global_max_pooling1d",
        "BatchNormalization": "batch_normalization",
        "Dropout": "dropout",
        "SpatialDropout1D": "spatial_dropout1d",
        "Flatten": "flatten",
        "Dense": "dense",
    }

    def __init__(self, ruta_keras: str) -> None:
        import h5py

        if not zipfile.is_zipfile(ruta_keras):
            raise NotImplementedError("El archivo de modelo no es un contenedor .keras v3 estándar")

        self._operaciones: List[Callable[[np.ndarray], np.ndarray]] = []
        self.n_entrada: int = 0

        with zipfile.ZipFile(ruta_keras, "r") as archivo_zip:
            nombres_zip = set(archivo_zip.namelist())
            if "config.json" not in nombres_zip or "model.weights.h5" not in nombres_zip:
                raise NotImplementedError("Contenedor .keras sin config.json o model.weights.h5")

            config_modelo = json.loads(archivo_zip.read("config.json").decode("utf-8"))
            if config_modelo.get("class_name") != "Sequential":
                raise NotImplementedError(f"Topología {config_modelo.get('class_name')} requiere respaldo TensorFlow")

            capas_cfg = config_modelo.get("config", {}).get("layers", [])
            if not capas_cfg:
                raise ValueError("El modelo Sequential no contiene capas")

            bytes_h5 = archivo_zip.read("model.weights.h5")

        with h5py.File(io.BytesIO(bytes_h5), "r") as h5:
            grupo_capas = h5.get("layers")
            if grupo_capas is None:
                raise NotImplementedError("Estructura HDF5 de pesos no estándar")

            conteo_clase: dict[str, int] = {}
            for idx, capa in enumerate(capas_cfg):
                clase = capa.get("class_name", "")
                if clase not in self.CAPAS_SOPORTADAS:
                    raise NotImplementedError(f"Capa '{clase}' requiere respaldo TensorFlow")

                cfg = capa.get("config", {})
                nombre_capa = cfg.get("name", "")
                clave_h5 = nombre_capa
                prefijo_h5 = self.PREFIJOS_H5_KERAS3.get(clase)
                if prefijo_h5 is not None:
                    occ = conteo_clase.get(prefijo_h5, 0)
                    conteo_clase[prefijo_h5] = occ + 1
                    clave_keras3 = prefijo_h5 if occ == 0 else f"{prefijo_h5}_{occ}"
                    if clave_keras3 in grupo_capas:
                        clave_h5 = clave_keras3

                if idx == 0:
                    forma_lote = (
                        cfg.get("batch_shape")
                        or cfg.get("batch_input_shape")
                        or capa.get("build_config", {}).get("input_shape")
                    )
                    if forma_lote and len(forma_lote) >= 2 and forma_lote[1] is not None:
                        self.n_entrada = int(forma_lote[1])

                if clase in ("InputLayer", "Dropout", "SpatialDropout1D"):
                    continue

                if clase == "Conv1D":
                    self._agregar_conv1d(cfg, self._leer_vars_capa(grupo_capas, clave_h5))
                elif clase == "MaxPooling1D":
                    self._agregar_pooling1d(cfg, modo="max")
                elif clase == "AveragePooling1D":
                    self._agregar_pooling1d(cfg, modo="avg")
                elif clase == "GlobalAveragePooling1D":
                    self._operaciones.append(lambda x: np.mean(x, axis=1, dtype=np.float32))
                elif clase == "GlobalMaxPooling1D":
                    self._operaciones.append(lambda x: np.max(x, axis=1))
                elif clase == "BatchNormalization":
                    self._agregar_batchnorm(cfg, self._leer_vars_capa(grupo_capas, clave_h5))
                elif clase == "Flatten":
                    if cfg.get("data_format", "channels_last") != "channels_last":
                        raise NotImplementedError("Flatten channels_first requiere respaldo TensorFlow")
                    self._operaciones.append(lambda x: np.ascontiguousarray(x).reshape(x.shape[0], -1))
                elif clase == "Dense":
                    self._agregar_dense(cfg, self._leer_vars_capa(grupo_capas, clave_h5))

        if self.n_entrada <= 0:
            raise ValueError("No fue posible determinar la dimensión de entrada del modelo Conv1D")

    @staticmethod
    def _leer_vars_capa(grupo_capas, nombre_capa: str) -> List[np.ndarray]:
        if nombre_capa not in grupo_capas or "vars" not in grupo_capas[nombre_capa]:
            raise KeyError(f"No se encontraron tensores de pesos para la capa '{nombre_capa}'")
        vars_grp = grupo_capas[nombre_capa]["vars"]
        claves = sorted(vars_grp.keys(), key=lambda k: int(k))
        return [np.asarray(vars_grp[k][()], dtype=np.float32) for k in claves]

    def _agregar_conv1d(self, cfg: dict, pesos: List[np.ndarray]) -> None:
        if cfg.get("data_format", "channels_last") != "channels_last" or int(cfg.get("groups", 1)) != 1:
            raise NotImplementedError("Conv1D con groups != 1 o channels_first requiere respaldo TensorFlow")

        stride = int(cfg.get("strides", [1])[0])
        dilatacion = int(cfg.get("dilation_rate", [1])[0])
        padding = str(cfg.get("padding", "valid")).lower()
        if padding not in ("valid", "same"):
            raise NotImplementedError(f"Padding '{padding}' en Conv1D requiere respaldo TensorFlow")
        usar_sesgo = bool(cfg.get("use_bias", True))
        activacion = cfg.get("activation", "linear")
        _aplicar_activacion(np.zeros((1, 1), dtype=np.float32), activacion)

        kernel = pesos[0]
        k_tam, c_in, c_out = kernel.shape
        kernel_col = np.ascontiguousarray(np.transpose(kernel, (1, 0, 2)).reshape(c_in * k_tam, c_out), dtype=np.float32)
        sesgo = np.ascontiguousarray(pesos[1], dtype=np.float32) if (usar_sesgo and len(pesos) > 1) else None
        k_efectivo = (k_tam - 1) * dilatacion + 1

        def op_conv1d(x: np.ndarray) -> np.ndarray:
            b_tam, longitud, _ = x.shape
            if padding == "same":
                l_salida = (longitud + stride - 1) // stride
                pad_total = max(0, (l_salida - 1) * stride + k_efectivo - longitud)
                pad_izq = pad_total // 2
                pad_der = pad_total - pad_izq
                if pad_izq > 0 or pad_der > 0:
                    x = np.pad(x, ((0, 0), (pad_izq, pad_der), (0, 0)), mode="constant")

            ventanas = sliding_window_view(x, k_efectivo, axis=1)
            if stride > 1 or dilatacion > 1:
                ventanas = ventanas[:, ::stride, :, ::dilatacion]
            l_out = ventanas.shape[1]
            matriz_col = np.ascontiguousarray(ventanas, dtype=np.float32).reshape(b_tam * l_out, c_in * k_tam)
            salida = (matriz_col @ kernel_col).reshape(b_tam, l_out, c_out)
            if sesgo is not None:
                salida += sesgo
            return _aplicar_activacion(salida, activacion)

        self._operaciones.append(op_conv1d)

    def _agregar_pooling1d(self, cfg: dict, modo: str) -> None:
        if cfg.get("data_format", "channels_last") != "channels_last":
            raise NotImplementedError("Pooling1D channels_first requiere respaldo TensorFlow")
        tam_pool = int(cfg.get("pool_size", [2])[0])
        strides_cfg = cfg.get("strides")
        stride = int(strides_cfg[0]) if strides_cfg else tam_pool
        padding = str(cfg.get("padding", "valid")).lower()
        if padding not in ("valid", "same"):
            raise NotImplementedError(f"Padding '{padding}' en Pooling1D requiere respaldo TensorFlow")

        if padding == "valid" and tam_pool == stride:
            if modo == "max":
                def op_pool_rapido(x: np.ndarray) -> np.ndarray:
                    b_tam, longitud, canales = x.shape
                    l_util = (longitud // tam_pool) * tam_pool
                    return np.max(x[:, :l_util, :].reshape(b_tam, l_util // tam_pool, tam_pool, canales), axis=2)
            else:
                def op_pool_rapido(x: np.ndarray) -> np.ndarray:
                    b_tam, longitud, canales = x.shape
                    l_util = (longitud // tam_pool) * tam_pool
                    return np.mean(
                        x[:, :l_util, :].reshape(b_tam, l_util // tam_pool, tam_pool, canales),
                        axis=2,
                        dtype=np.float32,
                    )
            self._operaciones.append(op_pool_rapido)
            return

        def op_pool_general(x: np.ndarray) -> np.ndarray:
            longitud = x.shape[1]
            if padding == "same":
                l_salida = (longitud + stride - 1) // stride
                pad_total = max(0, (l_salida - 1) * stride + tam_pool - longitud)
                pad_izq = pad_total // 2
                pad_der = pad_total - pad_izq
                if modo == "max":
                    if pad_izq > 0 or pad_der > 0:
                        x = np.pad(x, ((0, 0), (pad_izq, pad_der), (0, 0)), mode="constant", constant_values=-np.inf)
                    ventanas = sliding_window_view(x, tam_pool, axis=1)[:, ::stride, :, :]
                    return np.max(ventanas, axis=-1)
                mascara = np.ones((1, longitud, 1), dtype=np.float32)
                if pad_izq > 0 or pad_der > 0:
                    x = np.pad(x, ((0, 0), (pad_izq, pad_der), (0, 0)), mode="constant", constant_values=0.0)
                    mascara = np.pad(mascara, ((0, 0), (pad_izq, pad_der), (0, 0)), mode="constant", constant_values=0.0)
                ventanas = sliding_window_view(x, tam_pool, axis=1)[:, ::stride, :, :]
                conteos = np.maximum(np.sum(sliding_window_view(mascara, tam_pool, axis=1)[:, ::stride, :, :], axis=-1), np.float32(1.0))
                return (np.sum(ventanas, axis=-1, dtype=np.float32) / conteos).astype(np.float32, copy=False)
            ventanas = sliding_window_view(x, tam_pool, axis=1)[:, ::stride, :, :]
            if modo == "max":
                return np.max(ventanas, axis=-1)
            return np.mean(ventanas, axis=-1, dtype=np.float32)

        self._operaciones.append(op_pool_general)

    def _agregar_batchnorm(self, cfg: dict, pesos: List[np.ndarray]) -> None:
        eps = np.float32(cfg.get("epsilon", 1e-3))
        escala_activa = bool(cfg.get("scale", True))
        centro_activo = bool(cfg.get("center", True))
        idx = 0
        gamma = pesos[idx] if escala_activa else np.float32(1.0)
        if escala_activa:
            idx += 1
        beta = pesos[idx] if centro_activo else np.float32(0.0)
        if centro_activo:
            idx += 1
        media = pesos[idx]
        varianza = pesos[idx + 1]
        factor = (gamma / np.sqrt(varianza + eps)).astype(np.float32)
        desplazamiento = (beta - media * factor).astype(np.float32)

        self._operaciones.append(lambda x: x * factor + desplazamiento)

    def _agregar_dense(self, cfg: dict, pesos: List[np.ndarray]) -> None:
        usar_sesgo = bool(cfg.get("use_bias", True))
        activacion = cfg.get("activation", "linear")
        _aplicar_activacion(np.zeros((1, 1), dtype=np.float32), activacion)

        kernel = np.ascontiguousarray(pesos[0], dtype=np.float32)
        sesgo = np.ascontiguousarray(pesos[1], dtype=np.float32) if (usar_sesgo and len(pesos) > 1) else None

        def op_dense(x: np.ndarray) -> np.ndarray:
            salida = x @ kernel
            if sesgo is not None:
                salida += sesgo
            return _aplicar_activacion(salida, activacion)

        self._operaciones.append(op_dense)

    def __call__(self, tensor_3d: np.ndarray) -> np.ndarray:
        x = np.ascontiguousarray(tensor_3d, dtype=np.float32)
        for op in self._operaciones:
            x = op(x)
        return x.reshape(-1)


# --- Motor Principal de Inferencia ---
class MotorInferencia:
    def __init__(self) -> None:
        self.listo = False
        self.error: Optional[str] = None
        self.metadatos: dict = {}
        self.total_caracteristicas_modelo = 0
        self.backend_activo: str = "no_inicializado"
        self._indices_caracteristicas: Optional[np.ndarray] = None
        self._escalador = None
        self._motor_ligero: Optional[MotorConv1DLigero] = None
        self._funcion_grafo_tf = None
        self._tf = None
        self._ejecutor_hilos = ThreadPoolExecutor(max_workers=1, thread_name_prefix="conv1d-infer-hilo")

    @property
    def ready(self) -> bool:
        return self.listo

    @ready.setter
    def ready(self, valor: bool):
        self.listo = valor

    @property
    def n_model_features(self) -> int:
        return self.total_caracteristicas_modelo

    @n_model_features.setter
    def n_model_features(self, valor: int):
        self.total_caracteristicas_modelo = valor

    @property
    def metadata(self) -> dict:
        return self.metadatos

    @metadata.setter
    def metadata(self, valor: dict):
        self.metadatos = valor

    def cargar(self) -> None:
        try:
            for ruta in (configuracion.ruta_modelo, configuracion.ruta_escalador):
                if not os.path.exists(ruta):
                    raise FileNotFoundError(f"No existe el artefacto requerido: {ruta}")

            import joblib

            escalador = joblib.load(configuracion.ruta_escalador)

            # 1. Lectura previa de metadatos
            if os.path.exists(configuracion.ruta_metadatos):
                with open(configuracion.ruta_metadatos, encoding="utf-8") as f_meta:
                    self.metadatos = json.load(f_meta)

            def _configurar_dimensiones(n_entrada_modelo: int) -> None:
                n_escalador = int(getattr(escalador, "n_features_in_", n_entrada_modelo))
                if n_escalador != n_entrada_modelo:
                    raise ValueError(
                        f"Escalador ({n_escalador}) y modelo ({n_entrada_modelo}) esperan dimensiones distintas"
                    )
                nombres = self.metadatos.get("feature_names") or (
                    CARACTERISTICAS_CANONICAS if n_entrada_modelo == TOTAL_CANONICAS else None
                )
                if nombres is None or len(nombres) != n_entrada_modelo:
                    raise ValueError("model_metadata.json no define 'feature_names' coherentes con el modelo")
                desconocidas = [nom for nom in nombres if nom not in CARACTERISTICAS_CANONICAS]
                if desconocidas:
                    raise ValueError(f"Características desconocidas en metadata: {desconocidas}")

                indices = np.array([CARACTERISTICAS_CANONICAS.index(nom) for nom in nombres])
                self._indices_caracteristicas = None if np.array_equal(indices, np.arange(TOTAL_CANONICAS)) else indices
                self._escalador = escalador
                self.total_caracteristicas_modelo = n_entrada_modelo

            # 2. Inicialización y precalentamiento del motor de inferencia (protegido por respaldo TF)
            self._motor_ligero = None
            self._funcion_grafo_tf = None
            self._tf = None
            try:
                motor_ligero = MotorConv1DLigero(configuracion.ruta_modelo)
                n_entrada = int(motor_ligero.n_entrada)
                self._motor_ligero = motor_ligero
                self.backend_activo = "conv1d_blas_ligero"
                _configurar_dimensiones(n_entrada)
                for tamano in (1, 64):
                    self._predecir_sincrono(np.zeros((tamano, TOTAL_CANONICAS), dtype=np.float32))
            except Exception as exc_ligero:
                self._motor_ligero = None
                registro_logger.warning(
                    "Activando respaldo TensorFlow para arquitectura extendida o error en precalentamiento (%s)",
                    exc_ligero,
                )
                os.environ.setdefault("ONEDNN_PRIMITIVE_CACHE_CAPACITY", "16")
                import tensorflow as tf

                tf.config.threading.set_intra_op_parallelism_threads(configuracion.tf_intra_threads)
                tf.config.threading.set_inter_op_parallelism_threads(1)
                modelo = tf.keras.models.load_model(configuracion.ruta_modelo, compile=False)
                n_entrada = int(modelo.input_shape[1])
                self._funcion_grafo_tf = tf.function(
                    lambda x: modelo(x, training=False),
                    input_signature=[tf.TensorSpec([None, n_entrada, 1], tf.float32)],
                    reduce_retracing=True,
                )
                self._tf = tf
                self.backend_activo = "tensorflow_fallback"
                _configurar_dimensiones(n_entrada)
                for tamano in (1, 64):
                    self._predecir_sincrono(np.zeros((tamano, TOTAL_CANONICAS), dtype=np.float32))

            self.listo = True
            registro_logger.info(
                "Modelo Conv1D listo (%s): %d características, escalador=%s",
                self.backend_activo,
                n_entrada,
                type(escalador).__name__,
            )
        except Exception as exc:
            self.listo = False
            self.error = str(exc)
            registro_logger.critical("El modelo NO está disponible; /api/predict responderá 503: %s", exc)

    load = cargar

    def _predecir_sincrono(
        self,
        matriz_X: np.ndarray,
        ips_origen: Optional[List[str]] = None,
    ) -> Tuple[np.ndarray, float]:
        t0 = time.perf_counter()
        matriz_X = np.asarray(matriz_X, dtype=np.float64)
        if matriz_X.ndim == 1:
            matriz_X = matriz_X.reshape(1, -1)
        if self._indices_caracteristicas is not None:
            if matriz_X.shape[1] == TOTAL_CANONICAS:
                matriz_X = matriz_X[:, self._indices_caracteristicas]
            elif matriz_X.shape[1] != self.total_caracteristicas_modelo:
                raise ValueError(
                    f"Dimensión inesperada ({matriz_X.shape[1]}): se esperaban {TOTAL_CANONICAS} canónicas o {self.total_caracteristicas_modelo} del modelo"
                )

        # 1. Sanitización de entrada
        matriz_X = np.nan_to_num(matriz_X, nan=0.0, posinf=1e12, neginf=-1e12)
        matriz_X = np.clip(matriz_X, -1e12, 1e12)

        # 2. Normalización (Escalador) con acotamiento estricto [0.0, 1.0] para MinMaxScaler
        matriz_escalada = self._escalador.transform(matriz_X)
        if type(self._escalador).__name__ == "MinMaxScaler" or hasattr(self._escalador, "feature_range"):
            matriz_escalada = np.nan_to_num(matriz_escalada, nan=0.0, posinf=1.0, neginf=0.0)
            matriz_escalada = np.clip(matriz_escalada, 0.0, 1.0).astype(np.float32, copy=False)
        else:
            matriz_escalada = np.nan_to_num(matriz_escalada, nan=0.0, posinf=1e6, neginf=-1e6)
            matriz_escalada = np.clip(matriz_escalada, -1e6, 1e6).astype(np.float32, copy=False)

        # 3. Evaluación pura Conv1D (sin heurísticas ni reglas acopladas a puertos/IPs)
        tensor_3d = matriz_escalada.reshape(matriz_escalada.shape[0], matriz_escalada.shape[1], 1)
        if self._motor_ligero is not None:
            probabilidades = self._motor_ligero(tensor_3d)
        else:
            probabilidades = self._funcion_grafo_tf(self._tf.constant(tensor_3d)).numpy().reshape(-1)

        probabilidades = np.nan_to_num(probabilidades, nan=0.0, posinf=1.0, neginf=0.0)
        probabilidades = np.clip(probabilidades, 0.0, 1.0)

        latencia_ms = (time.perf_counter() - t0) * 1000.0
        return probabilidades, latencia_ms

    _predict_sync = _predecir_sincrono

    async def predecir(
        self,
        matriz_X: np.ndarray,
        ips_origen: Optional[List[str]] = None,
    ) -> Tuple[np.ndarray, float]:
        if not self.listo:
            raise RuntimeError(self.error or "Modelo no cargado")
        bucle = asyncio.get_running_loop()
        return await bucle.run_in_executor(self._ejecutor_hilos, self._predecir_sincrono, matriz_X, ips_origen)

    predict = predecir

    def apagar(self) -> None:
        self._ejecutor_hilos.shutdown(wait=False, cancel_futures=True)

    shutdown = apagar


# --- Instancia y Aliases ---
motor_inferencia = MotorInferencia()
InferenceEngine = MotorInferencia
engine = motor_inferencia
CANONICAL_FEATURES = CARACTERISTICAS_CANONICAS
N_CANONICAL = TOTAL_CANONICAS
logger = registro_logger
