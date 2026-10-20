import logging
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from backend.config import settings

logger = logging.getLogger("cybershield.db")

DATABASE_URL = settings.database_url
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

IS_SQLITE = DATABASE_URL.startswith("sqlite")

# SQLite para desarrollo local, PostgreSQL con Pool de conexiones para producción
if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.close()
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
Base = declarative_base()


def get_db():
    """Generador de sesiones de base de datos para inyección de dependencias en FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ensure_schema() -> None:
    """Crea tablas/índices faltantes y aplica migraciones mínimas idempotentes.

    `create_all` no altera tablas existentes; esta función añade la columna `source`
    (para separar tráfico real de simulaciones) y los índices nuevos en BDs ya pobladas.
    Para evolución mayor del esquema se recomienda Alembic.
    """
    from backend import models  # noqa: F401  (registra los modelos en Base)

    Base.metadata.create_all(bind=engine)
    insp = inspect(engine)
    cols = {c["name"] for c in insp.get_columns("traffic_logs")}
    with engine.begin() as conn:
        if "source" not in cols:
            logger.warning("Migrando esquema: añadiendo columna traffic_logs.source")
            conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN source VARCHAR(16) DEFAULT 'sensor'"))
            conn.execute(text("UPDATE traffic_logs SET source = 'simulation' WHERE src_ip LIKE '203.0.113.%'"))
            conn.execute(text("UPDATE traffic_logs SET source = 'sensor' WHERE source IS NULL"))
    for table in Base.metadata.sorted_tables:
        for idx in table.indexes:
            idx.create(bind=engine, checkfirst=True)