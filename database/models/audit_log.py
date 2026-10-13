import datetime
from sqlalchemy import String, ForeignKey, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class AuditLog(Base, IDMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    public_event_id: Mapped[str | None] = mapped_column(String(36), unique=True, index=True)
    actor_public_user_id: Mapped[str | None] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(32), index=True)
    safe_error_category: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    request_id: Mapped[str | None] = mapped_column(String(36), index=True)
    schema_version: Mapped[str | None] = mapped_column(String(64))

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="audit_logs")
