from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from auth.authorization import AuthorizationService
from backend.services.user_account_service import UserAccountService, normalize_login
from database.base import Base
from database.models import User
import database.session as database_session
from utils.exceptions import ConflictError


@pytest.fixture()
def accounts(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(database_session, "_SessionFactory", factory)
    return UserAccountService(AuthorizationService())


def test_normalize_login_is_bounded_and_casefolded():
    assert normalize_login("  Operator  ") == "operator"
    assert normalize_login("\n") == ""
    assert normalize_login("x" * 256) == ""


def test_provision_and_authenticate_by_login_or_email(accounts):
    created = accounts.provision(
        "Alice", "Alice@example.test", "correct horse battery staple", "operator"
    )
    assert created.login_label == "Alice"
    assert accounts.authenticate("ALICE", "correct horse battery staple") == created
    assert accounts.authenticate(
        "alice@EXAMPLE.test", "correct horse battery staple"
    ).public_user_id == created.public_user_id
    assert accounts.authenticate("alice", "wrong password") is None


def test_duplicate_identity_and_invalid_role_are_rejected(accounts):
    accounts.provision("alice", "alice@example.test", "correct horse battery staple", "admin")
    with pytest.raises(ConflictError):
        accounts.provision("ALICE", "other@example.test", "another secure password", "viewer")
    with pytest.raises(ValueError):
        accounts.provision("bob", "bob@example.test", "another secure password", "owner")


def test_inactive_user_and_durable_lockout(accounts):
    user = accounts.provision(
        "alice", "alice@example.test", "correct horse battery staple", "viewer"
    )
    for _ in range(5):
        assert accounts.authenticate("alice", "wrong password") is None
    assert accounts.authenticate("alice", "correct horse battery staple") is None
    accounts.set_active(user.public_user_id, False)
    assert accounts.get_active(user.public_user_id) is None


def test_success_updates_login_metadata(accounts):
    user = accounts.provision(
        "alice", "alice@example.test", "correct horse battery staple", "viewer"
    )
    assert accounts.authenticate("alice", "correct horse battery staple")
    with database_session.session_scope() as session:
        stored = session.scalar(select(User).where(User.public_user_id == user.public_user_id))
        assert stored.last_login_at is not None
        assert stored.failed_login_count == 0


def test_final_active_admin_cannot_be_deactivated_or_demoted(accounts):
    admin = accounts.provision(
        "admin", "admin@example.test", "correct horse battery staple", "admin"
    )
    with pytest.raises(ConflictError):
        accounts.set_active(admin.public_user_id, False)
    with pytest.raises(ConflictError):
        accounts.change_role(admin.public_user_id, "operator")
    second = accounts.provision(
        "admin2", "admin2@example.test", "correct horse battery staple", "admin"
    )
    accounts.change_role(admin.public_user_id, "viewer")
    assert accounts.get_active(second.public_user_id).role == "admin"
