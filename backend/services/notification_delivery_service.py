from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from database.models.notification_delivery import NotificationDelivery
from database.session import get_session, session_scope
from utils.exceptions import ConflictError


def _safe(row):
    return {
        "delivery_id": row.public_delivery_id,
        "alert_id": row.alert_public_id,
        "provider_category": row.provider_category,
        "masked_recipient_label": row.masked_recipient_label,
        "requested_at": row.requested_at,
        "completed_at": row.completed_at,
        "status": row.status,
        "safe_error_category": row.safe_error_category,
        "attempt_number": row.attempt_number,
        "schema_version": row.notification_schema_version,
        "provider_message_reference": row.provider_message_reference,
    }


class NotificationDeliveryService:
    def create_pending(self, **values):
        row = NotificationDelivery(**values)
        session = get_session()
        try:
            session.add(row)
            session.flush()
            result = _safe(row)
            session.commit()
            return result
        except IntegrityError as exc:
            session.rollback()
            raise ConflictError("Duplicate notification request") from exc
        finally:
            session.close()

    def find_by_request_identity(self, identity):
        with session_scope() as session:
            row = session.execute(select(NotificationDelivery).where(
                NotificationDelivery.request_identity == identity
            )).scalars().first()
            return _safe(row) if row else None

    def complete(self, delivery_id, status, completed_at, safe_error_category=None,
                 provider_message_reference=None):
        with session_scope() as session:
            row = session.execute(select(NotificationDelivery).where(
                NotificationDelivery.public_delivery_id == delivery_id
            )).scalars().first()
            if row is None:
                raise LookupError("Delivery attempt not found")
            row.status = status
            row.completed_at = completed_at
            row.safe_error_category = safe_error_category
            row.provider_message_reference = provider_message_reference
            session.flush()
            return _safe(row)

    def for_alert(self, alert_id, limit=20):
        with session_scope() as session:
            rows = session.execute(
                select(NotificationDelivery)
                .where(NotificationDelivery.alert_public_id == alert_id)
                .order_by(NotificationDelivery.requested_at.desc())
                .limit(limit)
            ).scalars().all()
            return tuple(_safe(row) for row in rows)

    def status(self):
        with session_scope() as session:
            counts = dict(session.execute(
                select(NotificationDelivery.status, func.count(NotificationDelivery.id))
                .group_by(NotificationDelivery.status)
            ).all())
            latest = session.execute(
                select(NotificationDelivery)
                .order_by(NotificationDelivery.requested_at.desc()).limit(1)
            ).scalars().first()
            return {
                "notification_attempt_count": sum(counts.values()),
                "successful_notification_count": counts.get("sent", 0),
                "failed_notification_count": sum(
                    counts.get(key, 0)
                    for key in ("failed", "unavailable", "timeout", "unknown")
                ),
                "latest_notification_at": (
                    latest.completed_at or latest.requested_at
                ) if latest else None,
            }
