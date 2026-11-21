from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, Index, Integer, String

from backend.base_datos import Base


def obtener_utc_ingenuo() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


utcnow_naive = obtener_utc_ingenuo


# --- Modelos ORM ---
class RegistroTrafico(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=obtener_utc_ingenuo, index=True)
    src_ip = Column(String(50), default="127.0.0.1", index=True)
    dst_ip = Column(String(50), default="127.0.0.1")
    protocol = Column(String(10), default="TCP", index=True)
    duration_ms = Column(Float, default=0.0)
    total_bytes = Column(BigInteger, default=0)
    prediction = Column(String(20), index=True)
    is_attack = Column(Boolean, index=True)
    probability = Column(Float)
    confidence_percentage = Column(Float, index=True)
    source = Column(String(16), default="sensor", index=True)

    __table_args__ = (
        Index("ix_traffic_attack_id", "is_attack", "id"),
        Index("ix_traffic_attack_ts", "is_attack", "timestamp"),
        Index("ix_traffic_attack_conf", "is_attack", "confidence_percentage"),
        Index("ix_traffic_attack_protocol", "is_attack", "protocol"),
    )


class EstadisticaMinutoTrafico(Base):
    __tablename__ = "traffic_minute_stats"

    bucket = Column(DateTime, primary_key=True)
    source = Column(String(16), primary_key=True, default="sensor")
    benign = Column(Integer, nullable=False, default=0)
    ddos = Column(Integer, nullable=False, default=0)
    confidence_sum = Column(Float, nullable=False, default=0.0)


# --- Aliases de Compatibilidad ---
TrafficLog = RegistroTrafico
TrafficMinuteStat = EstadisticaMinutoTrafico
