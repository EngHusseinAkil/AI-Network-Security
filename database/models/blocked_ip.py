import datetime
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class BlockedIP(Base, IDMixin, TimestampMixin):
    __tablename__ = "blocked_ips"

    ip_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    blocked_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
