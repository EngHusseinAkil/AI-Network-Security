import datetime
from sqlalchemy import String, Integer, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin

class TrafficRecord(Base, IDMixin):
    __tablename__ = "traffic_records"

    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    packet_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flow_duration: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    
    # Store extracted features for ML, not raw packet payloads
    extracted_features: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    
    captured_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    # Relationships
    threat_logs: Mapped[list["ThreatLog"]] = relationship("ThreatLog", back_populates="traffic_record")
