import os
import secrets
from dataclasses import dataclass, field
from typing import List, Optional

# --- Rutas Base y Carga de Entorno (.env) ---
DIRECTORIO_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = DIRECTORIO_BASE


def _limpiar_valor_env(valor_crudo: str) -> str:
    valor = valor_crudo.strip()
    if not valor:
        return ""
    if valor[0] in ("'", '"'):
        comilla = valor[0]
        idx_cierre = valor.find(comilla, 1)
        if idx_cierre != -1:
            return valor[1:idx_cierre].strip()
        return valor[1:].strip()
    if "#" in valor:
        valor = valor.split("#", 1)[0].strip()
    return valor


_archivo_env = os.path.join(DIRECTORIO_BASE, ".env")
if os.path.exists(_archivo_env):
    try:
        with open(_archivo_env, encoding="utf-8") as _manejador_env:
            for _linea in _manejador_env:
                _linea = _linea.strip()
                if _linea and not _linea.startswith("#") and "=" in _linea:
                    _clave, _valor = _linea.split("=", 1)
                    _clave_limpia = _clave.strip()
                    if _clave_limpia:
                        os.environ.setdefault(_clave_limpia, _limpiar_valor_env(_valor))
    except Exception:
        pass


def _cadena_a_booleano(nombre_var: str, valor_predeterminado: bool) -> bool:
    return os.getenv(nombre_var, str(valor_predeterminado)).strip().lower() in ("1", "true", "yes", "on")


def _cadena_a_lista(nombre_var: str, valor_predeterminado: str) -> List[str]:
    return [item.strip() for item in os.getenv(nombre_var, valor_predeterminado).split(",") if item.strip()]


def _resolver_ruta_relativa(ruta_cruda: Optional[str]) -> Optional[str]:
    if not ruta_cruda:
        return None
    limpia = ruta_cruda.strip()
    if not limpia:
        return None
    if os.path.isabs(limpia):
        return limpia
    return os.path.normpath(os.path.join(DIRECTORIO_BASE, limpia))


def _resolver_url_base_datos(url_cruda: Optional[str]) -> str:
    predeterminada = "sqlite:///" + os.path.join(DIRECTORIO_BASE, "backend", "ddos_records.db").replace(os.sep, "/")
    if not url_cruda or not url_cruda.strip():
        return predeterminada
    url = url_cruda.strip()
    if url.startswith("sqlite:///"):
        ruta_sqlite = url[len("sqlite:///") :]
        if ruta_sqlite == ":memory:" or not ruta_sqlite:
            return url
        # En POSIX rutas absolutas llevan 4 barras (sqlite:////...), en Windows unidad (C:/...)
        es_abs_windows = len(ruta_sqlite) >= 2 and ruta_sqlite[1] == ":"
        es_abs_posix = ruta_sqlite.startswith("/")
        if not es_abs_windows and not es_abs_posix:
            ruta_abs = os.path.normpath(os.path.join(DIRECTORIO_BASE, ruta_sqlite)).replace(os.sep, "/")
            return "sqlite:///" + ruta_abs
    return url


_SESSION_SECRET_ENV = (os.getenv("SESSION_SECRET_KEY") or "").strip()
_SESSION_SECRET_EFIMERA = not bool(_SESSION_SECRET_ENV)
_SESSION_SECRET_EFECTIVA = _SESSION_SECRET_ENV or secrets.token_hex(32)


_bool = _cadena_a_booleano
_list = _cadena_a_lista


# --- Estructura de Configuración ---
@dataclass(frozen=True)
class Configuracion:
    # --- Persistencia y Base de Datos ---
    database_url: str = _resolver_url_base_datos(os.getenv("DATABASE_URL"))
    retention_days: int = int(os.getenv("RETENTION_DAYS", "30"))
    max_db_log_rows: int = int(os.getenv("MAX_DB_LOG_ROWS", "50000"))
    persist_benign: bool = _cadena_a_booleano("PERSIST_BENIGN", True)
    anonymize_ips: bool = _cadena_a_booleano("ANONYMIZE_IPS", True)

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

    # --- Seguridad, Autenticación Web y TLS/HTTPS (Fail-Closed sin secretos hardcodeados) ---
    sensor_api_key: Optional[str] = (os.getenv("SENSOR_API_KEY") or "").strip() or None
    admin_user: str = (os.getenv("ADMIN_USER", "admin") or "admin").strip()
    admin_password: str = (os.getenv("ADMIN_PASSWORD") or "").strip()
    session_secret_key: str = _SESSION_SECRET_EFECTIVA
    session_secret_ephemeral: bool = _SESSION_SECRET_EFIMERA
    soar_master_password: str = (os.getenv("SOAR_MASTER_PASSWORD") or "").strip()
    edl_api_token: Optional[str] = (os.getenv("EDL_API_TOKEN") or "").strip() or None
    soar_enable_external_enrichment: bool = _cadena_a_booleano("SOAR_ENABLE_EXTERNAL_ENRICHMENT", True)
    session_duration_hours: int = int(os.getenv("SESSION_DURATION_HOURS") or os.getenv("SESSION_EXPIRE_HOURS") or "12")
    ssl_certfile: Optional[str] = _resolver_ruta_relativa(os.getenv("SSL_CERTFILE"))
    ssl_keyfile: Optional[str] = _resolver_ruta_relativa(os.getenv("SSL_KEYFILE"))
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
    def anonimizar_ips(self) -> bool:
        return self.anonymize_ips

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
    def clave_sesion_efimera(self) -> bool:
        return self.session_secret_ephemeral

    @property
    def clave_maestra_soar(self) -> str:
        return self.soar_master_password

    @property
    def token_edl(self) -> Optional[str]:
        return self.edl_api_token

    @property
    def habilitar_enriquecimiento_externo_soar(self) -> bool:
        return self.soar_enable_external_enrichment

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
