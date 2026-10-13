from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app_factory import create_app
from database.base import Base
from database.models import AuditLog, User
import database.session as database_session


def test_cli_provisions_hashed_user_and_audits(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(database_session, "_SessionFactory", factory)
    app = create_app({"TESTING": True})
    result = app.test_cli_runner().invoke(
        args=["users", "create", "--login", "admin", "--email",
              "admin@example.test", "--role", "admin"],
        input="correct horse battery staple\ncorrect horse battery staple\n",
    )
    assert result.exit_code == 0
    with factory() as session:
        user = session.scalar(select(User))
        event = session.scalar(select(AuditLog))
        assert user.password_hash != "correct horse battery staple"
        assert event.action == "user_provision"
        assert event.details is None
