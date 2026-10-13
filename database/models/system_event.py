from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class SystemEvent(Base, IDMixin, TimestampMixin):
    __tablename__ = "system_events"

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    level: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
