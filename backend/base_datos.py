import logging
import os
import sqlite3
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from backend.configuracion import configuracion

registro_logger = logging.getLogger("cybershield.db")

# --- Configuración del Motor de Base de Datos ---
URL_BASE_DATOS = configuracion.url_base_datos
if URL_BASE_DATOS.startswith("postgresql://"):
    URL_BASE_DATOS = URL_BASE_DATOS.replace("postgresql://", "postgresql+psycopg2://", 1)

ES_SQLITE = URL_BASE_DATOS.startswith("sqlite")

if ES_SQLITE:
    motor_bd = create_engine(
        URL_BASE_DATOS,
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_size=15,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
    )

    @event.listens_for(motor_bd, "connect")
    def establecer_pragma_sqlite(conexion_dbapi, registro_conexion):
        cursor = conexion_dbapi.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.execute("PRAGMA wal_autocheckpoint=1000;")
        cursor.execute("PRAGMA journal_size_limit=16777216;")
        cursor.execute("PRAGMA temp_store=FILE;")
        cursor.execute("PRAGMA cache_size=-1500;")
        cursor.execute("PRAGMA mmap_size=0;")
        cursor.close()

else:
    motor_bd = create_engine(
        URL_BASE_DATOS,
        pool_size=10,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
    )

# --- Sesiones y Base ORM ---
SesionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    bind=motor_bd,
)

Base = declarative_base()


def obtener_bd():
    sesion = SesionLocal()
    try:
        yield sesion
    finally:
        sesion.close()


# --- Mantenimiento y Esquema de Base de Datos ---
def compactar_y_activar_auto_vacuum_sqlite() -> None:
    if not ES_SQLITE:
        return
    ruta_db = motor_bd.url.database
    if not ruta_db or ruta_db == ":memory:" or not os.path.exists(ruta_db):
        return
    try:
        motor_bd.dispose()
        con = sqlite3.connect(ruta_db, timeout=30.0, isolation_level=None)
        try:
            modo_actual = con.execute("PRAGMA auto_vacuum;").fetchone()[0]
            paginas_libres = con.execute("PRAGMA freelist_count;").fetchone()[0]
            if modo_actual != 2 or paginas_libres > 5000:
                tamano_antes_mb = os.path.getsize(ruta_db) / (1024 * 1024)
                con.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                con.execute("PRAGMA auto_vacuum = INCREMENTAL;")
                con.execute("VACUUM;")
                con.execute("PRAGMA journal_mode = WAL;")
                modo_nuevo = con.execute("PRAGMA auto_vacuum;").fetchone()[0]
                tamano_despues_mb = os.path.getsize(ruta_db) / (1024 * 1024)
                registro_logger.info(
                    "SQLite compactado exitosamente: %.2f MB -> %.2f MB (auto_vacuum=%d [2=INCREMENTAL])",
                    tamano_antes_mb,
                    tamano_despues_mb,
                    modo_nuevo,
                )
        finally:
            con.close()
    except sqlite3.OperationalError as exc:
        registro_logger.warning("Compactación inicial diferida (conexión externa activa): %s", exc)
    except Exception:
        registro_logger.exception("Error inesperado verificando auto_vacuum incremental en SQLite")


def asegurar_esquema() -> None:
    try:
        from backend import modelos  # noqa: F401
    except ImportError:
        from backend import models as modelos  # noqa: F401

    Base.metadata.create_all(bind=motor_bd)
    inspeccion = inspect(motor_bd)
    columnas_existentes = {col["name"] for col in inspeccion.get_columns("traffic_logs")}

    with motor_bd.begin() as conexion:
        if "source" not in columnas_existentes:
            registro_logger.warning("Actualizando esquema de BD: agregando columna traffic_logs.source")
            conexion.execute(text("ALTER TABLE traffic_logs ADD COLUMN source VARCHAR(16) DEFAULT 'sensor'"))
            conexion.execute(text("UPDATE traffic_logs SET source = 'simulation' WHERE src_ip LIKE '203.0.113.%'"))
            conexion.execute(text("UPDATE traffic_logs SET source = 'sensor' WHERE source IS NULL"))

    for tabla in Base.metadata.sorted_tables:
        for indice in tabla.indexes:
            indice.create(bind=motor_bd, checkfirst=True)

    compactar_y_activar_auto_vacuum_sqlite()


# --- Aliases de Compatibilidad ---
DATABASE_URL = URL_BASE_DATOS
IS_SQLITE = ES_SQLITE
engine = motor_bd
SessionLocal = SesionLocal
get_db = obtener_bd
ensure_schema = asegurar_esquema
set_sqlite_pragma = establecer_pragma_sqlite
logger = registro_logger
