import datetime
from sqlalchemy import String, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class Device(Base, IDMixin, TimestampMixin):
    __tablename__ = "devices"

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    last_seen: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    threat_logs: Mapped[list["ThreatLog"]] = relationship("ThreatLog", back_populates="device")
    blocked_devices: Mapped[list["BlockedDevice"]] = relationship("BlockedDevice", back_populates="device")
