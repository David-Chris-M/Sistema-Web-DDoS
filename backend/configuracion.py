import os
from dataclasses import dataclass, field
from typing import List, Optional

# --- Rutas Base y Carga de Entorno (.env) ---
DIRECTORIO_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = DIRECTORIO_BASE

_archivo_env = os.path.join(DIRECTORIO_BASE, ".env")
if os.path.exists(_archivo_env):
    try:
        with open(_archivo_env, encoding="utf-8") as _manejador_env:
            for _linea in _manejador_env:
                _linea = _linea.strip()
                if _linea and not _linea.startswith("#") and "=" in _linea:
                    _clave, _valor = _linea.split("=", 1)
                    os.environ.setdefault(_clave.strip(), _valor.strip())
    except Exception:
        pass


def _cadena_a_booleano(nombre_var: str, valor_predeterminado: bool) -> bool:
    return os.getenv(nombre_var, str(valor_predeterminado)).strip().lower() in ("1", "true", "yes", "on")


def _cadena_a_lista(nombre_var: str, valor_predeterminado: str) -> List[str]:
    return [item.strip() for item in os.getenv(nombre_var, valor_predeterminado).split(",") if item.strip()]


_bool = _cadena_a_booleano
_list = _cadena_a_lista


# --- Estructura de Configuración ---
@dataclass(frozen=True)
class Configuracion:
    # --- Persistencia y Base de Datos ---
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(DIRECTORIO_BASE, "backend", "ddos_records.db").replace(os.sep, "/"),
    )
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))
    max_db_log_rows: int = int(os.getenv("MAX_DB_LOG_ROWS", "50000"))
    persist_benign: bool = _cadena_a_booleano("PERSIST_BENIGN", True)

    # --- Artefactos de Machine Learning (Conv1D) ---
    model_path: str = os.getenv(
        "MODEL_PATH", os.path.join(DIRECTORIO_BASE, "ml", "models", "ddos_cnn_model.keras")
    )
    scaler_path: str = os.getenv(
        "SCALER_PATH", os.path.join(DIRECTORIO_BASE, "ml", "models", "scaler.pkl")
    )
    metadata_path: str = os.getenv(
        "MODEL_METADATA_PATH", os.path.join(DIRECTORIO_BASE, "ml", "models", "model_metadata.json")
    )
    dataset_path: str = os.getenv(
        "DATASET_PATH", os.path.join(DIRECTORIO_BASE, "ml", "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    )
    decision_threshold: float = float(os.getenv("DECISION_THRESHOLD", "0.5"))
    tf_intra_threads: int = int(os.getenv("TF_INTRA_THREADS", "2"))

    # --- Seguridad, Autenticación Web y TLS/HTTPS ---
    sensor_api_key: Optional[str] = os.getenv("SENSOR_API_KEY") or None
    admin_user: str = os.getenv("ADMIN_USER", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "CyberShield2026!")
    session_secret_key: str = os.getenv("SESSION_SECRET_KEY", "CyberShield_Pyme_HMAC_SessionKey_2026_Secure")
    session_duration_hours: int = int(os.getenv("SESSION_DURATION_HOURS", "12"))
    ssl_certfile: Optional[str] = os.getenv("SSL_CERTFILE") or None
    ssl_keyfile: Optional[str] = os.getenv("SSL_KEYFILE") or None
    cors_origins: List[str] = field(
        default_factory=lambda: _cadena_a_lista("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
    )
    enable_simulation: bool = _cadena_a_booleano("ENABLE_SIMULATION", True)

    # --- Parámetros Operativos del Servidor Web y WebSockets ---
    max_batch_size: int = int(os.getenv("MAX_BATCH_SIZE", "500"))
    ws_send_timeout_s: float = float(os.getenv("WS_SEND_TIMEOUT_S", "2.0"))
    ws_max_flows_per_message: int = int(os.getenv("WS_MAX_FLOWS_PER_MESSAGE", "10"))
    tz_offset_hours: int = int(os.getenv("TZ_OFFSET_HOURS", "-5"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_max_bytes: int = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))
    log_backup_count: int = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    logs_dir: str = os.path.join(DIRECTORIO_BASE, "logs")
    frontend_dir: str = os.path.join(DIRECTORIO_BASE, "frontend")

    # --- Propiedades en Español ---
    @property
    def url_base_datos(self) -> str:
        return self.database_url

    @property
    def dias_retencion(self) -> int:
        return self.retention_days

    @property
    def max_filas_historial_bd(self) -> int:
        return self.max_db_log_rows

    @property
    def persistir_benignos(self) -> bool:
        return self.persist_benign

    @property
    def ruta_modelo(self) -> str:
        return self.model_path

    @property
    def ruta_escalador(self) -> str:
        return self.scaler_path

    @property
    def ruta_metadatos(self) -> str:
        return self.metadata_path

    @property
    def ruta_conjunto_datos(self) -> str:
        return self.dataset_path

    @property
    def umbral_decision(self) -> float:
        return self.decision_threshold

    @property
    def clave_api_sensor(self) -> Optional[str]:
        return self.sensor_api_key

    @property
    def origenes_cors(self) -> List[str]:
        return self.cors_origins

    @property
    def permitir_simulacion(self) -> bool:
        return self.enable_simulation

    @property
    def directorio_frontend(self) -> str:
        return self.frontend_dir

    @property
    def usuario_admin(self) -> str:
        return self.admin_user

    @property
    def clave_admin(self) -> str:
        return self.admin_password

    @property
    def clave_secreta_sesion(self) -> str:
        return self.session_secret_key

    @property
    def duracion_sesion_horas(self) -> int:
        return self.session_duration_hours

    @property
    def archivo_certificado_ssl(self) -> Optional[str]:
        return self.ssl_certfile

    @property
    def archivo_clave_ssl(self) -> Optional[str]:
        return self.ssl_keyfile

    @property
    def directorio_logs(self) -> str:
        return self.logs_dir

    @property
    def tamano_maximo_log_bytes(self) -> int:
        return self.log_max_bytes

    @property
    def cantidad_respaldos_log(self) -> int:
        return self.log_backup_count


# --- Instancia y Aliases ---
configuracion = Configuracion()
Settings = Configuracion
settings = configuracion
