from datetime import datetime, timedelta, timezone
import uuid

from sqlalchemy import func, or_, select

from auth.models import AuthenticatedUser, Role
from auth.passwords import hash_password, verify_password
from database.models.user import User
from database.session import session_scope
from utils.exceptions import ConflictError


def normalize_login(value):
    if not isinstance(value, str):
        return ""
    normalized = value.strip().casefold()
    if not normalized or len(normalized) > 255 or any(ord(ch) < 32 for ch in normalized):
        return ""
    return normalized


class UserAccountService:
    def __init__(self, authorization, utc_clock=None):
        self._authorization = authorization
        self._utc = utc_clock or (lambda: datetime.now(timezone.utc))

    def authenticate(self, login, password):
        normalized = normalize_login(login)
        now = self._utc()
        with session_scope() as session:
            user = session.execute(select(User).where(
                or_(User.normalized_login == normalized, func.lower(User.email) == normalized),
                User.is_deleted == False,
            )).scalars().first()
            locked_until = self._as_utc(user.locked_until) if user else None
            if not user or not user.is_active or (
                locked_until and locked_until > now
            ) or not verify_password(user.password_hash if user else "", password):
                if user and user.is_active:
                    user.failed_login_count += 1
                    if user.failed_login_count >= 5:
                        user.locked_until = now + timedelta(minutes=15)
                return None
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = now
            return self._safe(user)

    def get_active(self, public_user_id):
        with session_scope() as session:
            user = session.execute(select(User).where(
                User.public_user_id == public_user_id,
                User.is_active == True, User.is_deleted == False,
            )).scalars().first()
            return self._safe(user) if user else None

    def provision(self, login, email, password, role):
        normalized = normalize_login(login)
        normalized_email = normalize_login(email)
        if (
            not normalized or not normalized_email or "@" not in normalized_email
            or role not in {item.value for item in Role}
        ):
            raise ValueError("Invalid login or role")
        with session_scope() as session:
            exists = session.execute(select(User).where(or_(
                User.normalized_login == normalized,
                User.normalized_login == normalized_email,
                func.lower(User.email) == normalized,
                func.lower(User.email) == normalized_email,
            ))).scalars().first()
            if exists:
                raise ConflictError("Login identity already exists")
            now = self._utc()
            user = User(
                public_user_id=str(uuid.uuid4()), username=login.strip(),
                normalized_login=normalized, email=normalized_email,
                role=role, password_hash=hash_password(password), is_active=True,
                failed_login_count=0, password_changed_at=now, version=1,
            )
            session.add(user)
            session.flush()
            return self._safe(user)

    def list_users(self):
        with session_scope() as session:
            users = session.execute(
                select(User).where(User.is_deleted == False).order_by(User.username)
            ).scalars().all()
            return tuple(self._safe(user) for user in users)

    def set_active(self, public_user_id, active):
        with session_scope() as session:
            user = self._require_user(session, public_user_id)
            if not active:
                self._protect_final_admin(session, user)
            user.is_active = bool(active)
            user.version += 1
            session.flush()
            return self._safe(user)

    def change_role(self, public_user_id, role):
        if role not in {item.value for item in Role}:
            raise ValueError("Invalid role")
        with session_scope() as session:
            user = self._require_user(session, public_user_id)
            if user.role == Role.ADMIN.value and role != Role.ADMIN.value:
                self._protect_final_admin(session, user)
            user.role = role
            user.version += 1
            session.flush()
            return self._safe(user)

    def reset_password(self, public_user_id, password):
        password_hash = hash_password(password)
        with session_scope() as session:
            user = self._require_user(session, public_user_id)
            user.password_hash = password_hash
            user.password_changed_at = self._utc()
            user.failed_login_count = 0
            user.locked_until = None
            user.version += 1

    @staticmethod
    def _require_user(session, public_user_id):
        user = session.execute(select(User).where(
            User.public_user_id == public_user_id,
            User.is_deleted == False,
        )).scalars().first()
        if not user:
            raise ValueError("User not found")
        return user

    @staticmethod
    def _protect_final_admin(session, user):
        if user.role != Role.ADMIN.value or not user.is_active:
            return
        # PostgreSQL/MySQL serialize competing admin changes; SQLite serializes
        # writes at the database level and safely ignores FOR UPDATE.
        session.execute(select(User.id).where(
            User.role == Role.ADMIN.value,
            User.is_active == True,
            User.is_deleted == False,
        ).with_for_update()).all()
        active_admins = session.scalar(select(func.count()).select_from(User).where(
            User.role == Role.ADMIN.value,
            User.is_active == True,
            User.is_deleted == False,
        ))
        if active_admins <= 1:
            raise ConflictError("At least one active administrator must remain")

    @staticmethod
    def _as_utc(value):
        if value is None or value.tzinfo is not None:
            return value
        return value.replace(tzinfo=timezone.utc)

    def _safe(self, user):
        permissions = tuple(sorted(self._authorization.permissions_for(user.role)))
        return AuthenticatedUser(
            user.public_user_id, user.username, user.role, permissions
        )
