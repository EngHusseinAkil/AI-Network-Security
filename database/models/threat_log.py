import datetime
from sqlalchemy import String, Float, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class ThreatLog(Base, IDMixin, TimestampMixin):
    __tablename__ = "threat_logs"

    threat_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    
    source_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    traffic_record_id: Mapped[int | None] = mapped_column(ForeignKey("traffic_records.id"), nullable=True)
    
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    detected_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="threat_logs")
    traffic_record: Mapped["TrafficRecord"] = relationship("TrafficRecord", back_populates="threat_logs")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="threat_log")
