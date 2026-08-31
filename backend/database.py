import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Lee la variable de entorno de Docker/PostgreSQL o usa SQLite local por defecto
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite:///./backend/ddos_records.db"
)

# SQLite para desarrollo local, PostgreSQL con Pool de conexiones para producción
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, 
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Generador de sesiones de base de datos para inyección de dependencias en FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()