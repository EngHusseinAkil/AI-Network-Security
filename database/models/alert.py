from sqlalchemy import String, ForeignKey, Float, Integer, CheckConstraint, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.base import Base
from database.mixins import IDMixin, TimestampMixin

class Alert(Base, IDMixin, TimestampMixin):
    __tablename__ = "alerts"

    threat_log_id: Mapped[int | None] = mapped_column(ForeignKey("threat_logs.id", ondelete="SET NULL"), nullable=True)
    public_alert_id: Mapped[str] = mapped_column(String(36), index=True, unique=True, nullable=False)

    alert_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), index=True, nullable=False, default="new")

    title: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    source_category: Mapped[str] = mapped_column(String(50), nullable=False)

    predicted_canonical_label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    schema_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(50), nullable=True)

    deduplication_key: Mapped[str] = mapped_column(String(64), index=True, unique=True, nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    acknowledged_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dismissed_at: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Safe bounded metadata
    safe_metadata: Mapped[str] = mapped_column(JSON, nullable=False, default='{}')

    # Relationships
    threat_log: Mapped["ThreatLog"] = relationship("ThreatLog", back_populates="alerts")

    __table_args__ = (
        CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='chk_alert_confidence_bounds'),
        CheckConstraint('risk_score >= 0.0 AND risk_score <= 1.0', name='chk_alert_risk_bounds'),
        CheckConstraint('occurrence_count > 0', name='chk_alert_occurrence_positive'),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name='chk_alert_severity_enum'
        ),
        CheckConstraint(
            "status IN ('new', 'acknowledged', 'resolved', 'dismissed')",
            name='chk_alert_status_enum'
        ),
    )
