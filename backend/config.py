"""Configuración centralizada del backend (12-factor: todo vía variables de entorno)."""
import os
from dataclasses import dataclass, field
from typing import List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Cargar .env automáticamente si existe (sin sobreescribir variables del sistema)
_env_file = os.path.join(BASE_DIR, ".env")
if os.path.exists(_env_file):
    try:
        with open(_env_file, encoding="utf-8") as _fh:
            for _line in _fh:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())
    except Exception:
        pass


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str) -> List[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    # --- Persistencia ---
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "backend", "ddos_records.db").replace(os.sep, "/"),
    )
    # Purga de flujos crudos (los agregados por minuto se conservan). 0 = desactivada (por defecto,
    # para no borrar evidencia de la tesis). En producción 24/7 definir p. ej. RETENTION_DAYS=30.
    retention_days: int = int(os.getenv("RETENTION_DAYS", "0"))
    persist_benign: bool = _bool("PERSIST_BENIGN", True)                   # False = sólo se guardan ataques (+ agregados)

    # --- Artefactos del modelo ---
    model_path: str = os.getenv("MODEL_PATH", os.path.join(BASE_DIR, "ml", "models", "ddos_cnn_model.keras"))
    scaler_path: str = os.getenv("SCALER_PATH", os.path.join(BASE_DIR, "ml", "models", "scaler.pkl"))
    metadata_path: str = os.getenv("MODEL_METADATA_PATH", os.path.join(BASE_DIR, "ml", "models", "model_metadata.json"))
    dataset_path: str = os.getenv(
        "DATASET_PATH", os.path.join(BASE_DIR, "ml", "dataset", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    )
    decision_threshold: float = float(os.getenv("DECISION_THRESHOLD", "0.5"))
    tf_intra_threads: int = int(os.getenv("TF_INTRA_THREADS", "2"))         # Evita sobre-suscripción de CPU en la Pyme

    # --- Seguridad ---
    sensor_api_key: Optional[str] = os.getenv("SENSOR_API_KEY") or None    # Protege los endpoints de ingesta
    cors_origins: List[str] = field(default_factory=lambda: _list("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"))
    enable_simulation: bool = _bool("ENABLE_SIMULATION", True)             # Debe ser False en producción

    # --- Operación ---
    max_batch_size: int = int(os.getenv("MAX_BATCH_SIZE", "500"))
    ws_send_timeout_s: float = float(os.getenv("WS_SEND_TIMEOUT_S", "2.0"))
    ws_max_flows_per_message: int = int(os.getenv("WS_MAX_FLOWS_PER_MESSAGE", "10"))
    tz_offset_hours: int = int(os.getenv("TZ_OFFSET_HOURS", "-5"))         # Lima (UTC-5, sin horario de verano)
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    frontend_dir: str = os.path.join(BASE_DIR, "frontend")


settings = Settings()
