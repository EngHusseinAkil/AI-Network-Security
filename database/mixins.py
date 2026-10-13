import datetime
from sqlalchemy import Integer, DateTime, Boolean, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

class IDMixin:
    """Mixin for adding an integer primary key."""
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

class TimestampMixin:
    """Mixin for adding created_at and updated_at timestamps."""
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )

class SoftDeleteMixin:
    """Mixin for supporting soft deletes."""
    deleted_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class AuditMixin:
    """Mixin for tracking who created or updated a record."""
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
