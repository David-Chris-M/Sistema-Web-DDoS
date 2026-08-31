from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from datetime import datetime
from backend.database import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(50), default="127.0.0.1")
    dst_ip = Column(String(50), default="127.0.0.1")
    protocol = Column(String(10), default="TCP")
    duration_ms = Column(Float, default=0.0)
    total_bytes = Column(Integer, default=0)
    prediction = Column(String(20))
    is_attack = Column(Boolean)
    probability = Column(Float)
    confidence_percentage = Column(Float)