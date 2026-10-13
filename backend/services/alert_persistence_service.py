from typing import Dict, Any, Optional
import json
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from alerts.models import Alert as DomainAlert
from database.models.alert import Alert as PersistenceAlert
from database.repositories.alert_repository import AlertRepository
from database.session import session_scope
from backend.schemas.database import build_pagination_meta
from utils.exceptions import DatabaseError, ApplicationError, NotFoundError, ConflictError
from utils.logger import get_logger

logger = get_logger(__name__)

class AlertPersistenceService:
    """
    Handles mapping between pure Alert domain objects and database persistence.
    Does not evaluate policy rules. Does not trigger monitoring/inference.
    Manages database transactions explicitly using session_scope().
    """

    def store_alert(self, domain_alert: DomainAlert, policy_version: str, reason_code: str) -> Dict[str, Any]:
        """
        Stores an already validated domain alert into the database.
        Includes defensive JSON metadata checks.
        Rolls back on error. Returns the safe dictionary of the stored alert.
        """
        # Validate metadata size (e.g., max 4000 bytes)
        safe_meta_str = "{}"
        if domain_alert.safe_metadata:
            try:
                # Defensive copy and serialization
                copied_meta = dict(domain_alert.safe_metadata)
                safe_meta_str = json.dumps(copied_meta)
                if len(safe_meta_str) > 4000:
                    raise ApplicationError("Alert metadata exceeds safe persistence size.")
            except (TypeError, ValueError) as e:
                logger.error(f"Failed to serialize alert metadata: {e}")
                raise ApplicationError("Failed to serialize alert metadata.")

        # Map to persistence model
        persistence_alert = PersistenceAlert(
            public_alert_id=domain_alert.alert_id,
            alert_type=domain_alert.type.value,
            severity=domain_alert.severity.value,
            status=domain_alert.status.value,
            title=domain_alert.title,
            description=domain_alert.description,
            source_category=domain_alert.source_category,
            predicted_canonical_label=domain_alert.predicted_canonical_label,
            confidence_score=domain_alert.confidence_score,
            risk_score=domain_alert.risk_score,
            model_version=domain_alert.model_version,
            schema_version=domain_alert.schema_version,
            policy_version=policy_version,
            reason_code=reason_code,
            deduplication_key=domain_alert.deduplication_key,
            occurrence_count=1, # Default initially
            version=domain_alert.version,
            created_at=domain_alert.created_at,
            safe_metadata=safe_meta_str
        )

        # Explicit timestamp formatting
        if domain_alert.acknowledged_at:
            persistence_alert.acknowledged_at = domain_alert.acknowledged_at.isoformat()
        if domain_alert.resolved_at:
            persistence_alert.resolved_at = domain_alert.resolved_at.isoformat()
        if domain_alert.dismissed_at:
            persistence_alert.dismissed_at = domain_alert.dismissed_at.isoformat()

        try:
            with session_scope() as session:
                repo = AlertRepository(session)
                session.add(persistence_alert)
                session.flush() # Flush to catch integrity errors early

                from backend.schemas.alerts import serialize_alert_detail
                return serialize_alert_detail(persistence_alert)
        except IntegrityError as e:
            logger.warning(f"Integrity error (possible duplicate deduplication_key): {e}")
            raise ConflictError("Alert could not be stored due to integrity constraint (duplicate).")
        except SQLAlchemyError as e:
            logger.error(f"Database error storing alert: {e}")
            raise DatabaseError("Failed to persist alert safely.")

    def find_by_deduplication_key(self, deduplication_key: str) -> Optional[Dict[str, Any]]:
        """
        Looks up an alert by deduplication key and returns its view model if found.
        """
        try:
            with session_scope() as session:
                repo = AlertRepository(session)
                alert = repo.get_by_deduplication_key(deduplication_key)
                if alert:
                    from backend.schemas.alerts import serialize_alert_detail
                    return serialize_alert_detail(alert)
                return None
        except SQLAlchemyError as e:
            logger.error(f"Database error finding duplicate alert: {e}")
            raise DatabaseError("Failed to find alert safely.")

    def get_alerts(self, page: int, page_size: int, filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retrieves a paginated list of alerts and maps to view models.
        """
        try:
            with session_scope() as session:
                repo = AlertRepository(session)
                alerts_db = repo.get_alerts(
                    page=page,
                    page_size=page_size,
                    status=filters.get('status'),
                    severity=filters.get('severity'),
                    alert_type=filters.get('alert_type')
                )

                total_count = repo.count_alerts(
                    status=filters.get('status'),
                    severity=filters.get('severity'),
                    alert_type=filters.get('alert_type')
                )

                from backend.schemas.alerts import serialize_alert_summary

                summaries = [serialize_alert_summary(a) for a in alerts_db]
                meta = build_pagination_meta(page, page_size, total_count)
                meta['filters'] = {k: v for k, v in filters.items() if v is not None}

                return {
                    "alerts": summaries,
                    "pagination": meta
                }
        except SQLAlchemyError as e:
            logger.error(f"Database error getting alerts list: {e}")
            raise DatabaseError("Failed to fetch alerts safely.")

    def get_alert(self, public_alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a single alert mapped to its detail view model.
        """
        try:
            with session_scope() as session:
                repo = AlertRepository(session)
                alert = repo.get_by_public_id(public_alert_id)
                if not alert:
                    return None

                from backend.schemas.alerts import serialize_alert_detail
                return serialize_alert_detail(alert)
        except SQLAlchemyError as e:
            logger.error(f"Database error getting alert by public id: {e}")
            raise DatabaseError("Failed to fetch alert safely.")

    def transition_alert(self, public_alert_id: str, target_status: str, timestamp: str, expected_version: int) -> Dict[str, Any]:
        from alerts.constants import AlertStatus
        from alerts.exceptions import AlertValidationError
        from datetime import datetime

        try:
            target_enum = AlertStatus(target_status)
        except ValueError:
            raise ApplicationError(f"Invalid target status: {target_status}")

        try:
            ts = datetime.fromisoformat(timestamp)
        except ValueError:
            raise ApplicationError("Invalid timestamp format.")

        try:
            with session_scope() as session:
                repo = AlertRepository(session)
                alert_db = repo.get_by_public_id(public_alert_id)
                if not alert_db:
                    raise NotFoundError("Alert not found.")

                if alert_db.version != expected_version:
                    raise ConflictError("Alert has been modified. Please refresh and try again.")

                # We need to map to domain model to validate transition rules
                from alerts.constants import AlertType, AlertSeverity

                # Check aware UTC parsing
                from datetime import timezone
                def parse_ts(t):
                    if not t: return None
                    if isinstance(t, datetime):
                        parsed = t
                    else:
                        try:
                            parsed = datetime.fromisoformat(t)
                        except:
                            return None
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed

                domain_alert = DomainAlert(
                    alert_id=alert_db.public_alert_id,
                    type=AlertType(alert_db.alert_type),
                    severity=AlertSeverity(alert_db.severity),
                    status=AlertStatus(alert_db.status),
                    title=alert_db.title,
                    description=alert_db.description,
                    source_category=alert_db.source_category,
                    predicted_canonical_label=alert_db.predicted_canonical_label,
                    confidence_score=alert_db.confidence_score,
                    risk_score=alert_db.risk_score,
                    model_version=alert_db.model_version,
                    schema_version=alert_db.schema_version,
                    created_at=parse_ts(alert_db.created_at) or datetime.now(timezone.utc),
                    acknowledged_at=parse_ts(alert_db.acknowledged_at),
                    resolved_at=parse_ts(alert_db.resolved_at),
                    dismissed_at=parse_ts(alert_db.dismissed_at),
                    deduplication_key=alert_db.deduplication_key,
                    version=alert_db.version
                )

                try:
                    updated_domain = domain_alert.transition_to(target_enum, ts)
                except AlertValidationError as e:
                    raise ConflictError(str(e))

                # Apply changes
                alert_db.status = updated_domain.status.value
                alert_db.version = updated_domain.version

                if updated_domain.acknowledged_at:
                    alert_db.acknowledged_at = updated_domain.acknowledged_at.isoformat()
                if updated_domain.resolved_at:
                    alert_db.resolved_at = updated_domain.resolved_at.isoformat()
                if updated_domain.dismissed_at:
                    alert_db.dismissed_at = updated_domain.dismissed_at.isoformat()

                session.flush()
                from backend.schemas.alerts import serialize_alert_detail
                return serialize_alert_detail(alert_db)

        except (NotFoundError, ConflictError, ApplicationError):
            raise
        except SQLAlchemyError as e:
            logger.error(f"Database error transitioning alert: {e}")
            raise DatabaseError("Failed to transition alert safely.")
