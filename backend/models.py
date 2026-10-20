from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Index, Integer, String

from backend.database import Base


def utcnow_naive() -> datetime:
    """UTC 'naive' (compatible con los registros existentes y con SQLite)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow_naive, index=True)
    src_ip = Column(String(50), default="127.0.0.1", index=True)
    dst_ip = Column(String(50), default="127.0.0.1")
    protocol = Column(String(10), default="TCP", index=True)
    duration_ms = Column(Float, default=0.0)
    total_bytes = Column(Integer, default=0)
    prediction = Column(String(20), index=True)
    is_attack = Column(Boolean, index=True)
    probability = Column(Float)
    confidence_percentage = Column(Float, index=True)
    # Origen del registro: 'sensor' (tráfico real), 'api' (cliente externo) o 'simulation' (demo).
    # Imprescindible para no mezclar simulaciones con la validación pasiva de la tesis.
    source = Column(String(16), default="sensor", index=True)

    __table_args__ = (
        Index("ix_traffic_attack_id", "is_attack", "id"),
        Index("ix_traffic_attack_ts", "is_attack", "timestamp"),
    )


class TrafficMinuteStat(Base):
    """Agregado por minuto: hace O(1) los KPIs del dashboard aunque la tabla cruda tenga millones de filas
    y conserva el histórico aunque la política de retención purgue los flujos individuales."""
    __tablename__ = "traffic_minute_stats"

    bucket = Column(DateTime, primary_key=True)          # minuto UTC truncado
    source = Column(String(16), primary_key=True, default="sensor")
    benign = Column(Integer, nullable=False, default=0)
    ddos = Column(Integer, nullable=False, default=0)
    confidence_sum = Column(Float, nullable=False, default=0.0)


class BlockedIP(Base):
    """Registro de direcciones IP mitigadas y listas de bloqueo del firewall."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(50), unique=True, index=True, nullable=False)
    blocked_at = Column(DateTime, default=utcnow_naive, index=True)
    reason = Column(String(200), default="Ataque DDoS clasificado por Conv1D")
    severity = Column(String(20), default="Crítica")
    confidence = Column(Float, default=99.0)
    status = Column(String(20), default="ACTIVE", index=True)