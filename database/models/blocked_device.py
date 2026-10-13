import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class BlockedDevice(Base, IDMixin, TimestampMixin):
    __tablename__ = "blocked_devices"

    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(17), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    blocked_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="blocked_devices")
