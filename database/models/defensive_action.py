from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.mixins import IDMixin, TimestampMixin


class DefensiveAction(Base, IDMixin, TimestampMixin):
    __tablename__ = "defensive_actions"

    public_action_id: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, nullable=False
    )
    alert_public_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("alerts.public_alert_id", ondelete="CASCADE"),
        index=True, nullable=False,
    )
    request_identity: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_category: Mapped[str] = mapped_column(String(32), nullable=False)
    target_reference_id: Mapped[str] = mapped_column(String(128), nullable=False)
    masked_target_label: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_category: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_reference: Mapped[str | None] = mapped_column(String(128))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    safe_error_category: Mapped[str | None] = mapped_column(String(64))
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    action_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    removal_request_identity: Mapped[str | None] = mapped_column(
        String(64), unique=True, index=True
    )
