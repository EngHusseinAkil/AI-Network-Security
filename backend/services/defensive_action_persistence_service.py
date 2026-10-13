from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from database.models.defensive_action import DefensiveAction
from database.session import get_session, session_scope
from utils.exceptions import ConflictError


def _safe(row):
    return {
        "action_id": row.public_action_id,
        "alert_id": row.alert_public_id,
        "request_identity": row.request_identity,
        "action_type": row.action_type,
        "target_category": row.target_category,
        "target_reference_id": row.target_reference_id,
        "masked_target_label": row.masked_target_label,
        "provider_category": row.provider_category,
        "provider_reference": row.provider_reference,
        "requested_at": row.requested_at,
        "applied_at": row.applied_at,
        "expires_at": row.expires_at,
        "removed_at": row.removed_at,
        "status": row.status,
        "safe_error_category": row.safe_error_category,
        "reason_code": row.reason_code,
        "duration_seconds": row.duration_seconds,
        "schema_version": row.action_schema_version,
        "removal_request_identity": row.removal_request_identity,
    }


class DefensiveActionPersistenceService:
    def create_pending(self, **values):
        session = get_session()
        try:
            row = DefensiveAction(**values)
            session.add(row)
            session.flush()
            result = _safe(row)
            session.commit()
            return result
        except IntegrityError as exc:
            session.rollback()
            raise ConflictError("Duplicate defensive action request") from exc
        finally:
            session.close()

    def find_by_request_identity(self, identity):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.request_identity == identity
            )).scalars().first()
            return _safe(row) if row else None

    def get(self, action_id):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.public_action_id == action_id
            )).scalars().first()
            return _safe(row) if row else None

    def active_for_target(self, reference_id):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.target_reference_id == reference_id,
                DefensiveAction.status == "applied",
            )).scalars().first()
            return _safe(row) if row else None

    def complete_apply(self, action_id, status, now, expires_at=None,
                       error=None, provider_reference=None):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.public_action_id == action_id
            )).scalars().one()
            row.status = status
            row.applied_at = now if status == "applied" else None
            row.expires_at = expires_at if status == "applied" else None
            row.safe_error_category = error
            row.provider_reference = provider_reference
            session.flush()
            return _safe(row)

    def complete_remove(self, action_id, identity, status, now, error=None):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.public_action_id == action_id
            )).scalars().one()
            if row.removal_request_identity and row.removal_request_identity != identity:
                raise ConflictError("Removal already requested")
            row.removal_request_identity = identity
            if status == "removed":
                row.status = "removed"
                row.removed_at = now
            row.safe_error_category = error
            session.flush()
            return _safe(row)

    def reserve_remove(self, action_id, identity):
        with session_scope() as session:
            row = session.execute(select(DefensiveAction).where(
                DefensiveAction.public_action_id == action_id
            )).scalars().one()
            if row.removal_request_identity == identity:
                return _safe(row), True
            if row.removal_request_identity:
                if row.status == "applied" and row.safe_error_category:
                    row.removal_request_identity = identity
                    row.safe_error_category = None
                    session.flush()
                    return _safe(row), False
                return _safe(row), False
            row.removal_request_identity = identity
            session.flush()
            return _safe(row), False

    def for_alert(self, alert_id, limit=20):
        with session_scope() as session:
            rows = session.execute(
                select(DefensiveAction)
                .where(DefensiveAction.alert_public_id == alert_id)
                .order_by(DefensiveAction.requested_at.desc()).limit(limit)
            ).scalars().all()
            return tuple(_safe(row) for row in rows)

    def status(self):
        with session_scope() as session:
            counts = dict(session.execute(
                select(DefensiveAction.status, func.count(DefensiveAction.id))
                .group_by(DefensiveAction.status)
            ).all())
            latest = session.execute(
                select(DefensiveAction)
                .order_by(DefensiveAction.requested_at.desc()).limit(1)
            ).scalars().first()
            return {
                "pending_defensive_action_count": counts.get("pending", 0),
                "active_temporary_action_count": counts.get("applied", 0),
                "failed_defensive_action_count": sum(
                    counts.get(key, 0)
                    for key in ("failed", "timeout", "unavailable", "unknown")
                ),
                "expired_defensive_action_count": counts.get("expired", 0),
                "removed_defensive_action_count": counts.get("removed", 0),
                "latest_defensive_action_at": (
                    latest.applied_at or latest.requested_at
                ) if latest else None,
            }
