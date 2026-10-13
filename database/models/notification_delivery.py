from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.mixins import IDMixin, TimestampMixin


class NotificationDelivery(Base, IDMixin, TimestampMixin):
    __tablename__ = "notification_deliveries"

    public_delivery_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, nullable=False
    )
    alert_public_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.public_alert_id", ondelete="CASCADE"),
        index=True, nullable=False,
    )
    request_identity: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    provider_category: Mapped[str] = mapped_column(String(20), nullable=False)
    masked_recipient_label: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    safe_error_category: Mapped[str | None] = mapped_column(String(64))
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    notification_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_message_reference: Mapped[str | None] = mapped_column(String(128))
