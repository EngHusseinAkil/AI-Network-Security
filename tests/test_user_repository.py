import pytest
from database.models import User
from database.repositories.user_repository import UserRepository

def test_user_repository_get_by_username(db_session):
    repo = UserRepository(db_session)
    repo.add(User(username="alice", email="a@test.com", password_hash="h"))
    
    user = repo.get_by_username("alice")
    assert user is not None
    assert user.username == "alice"
    
    missing = repo.get_by_username("bob")
    assert missing is None

def test_user_repository_get_by_email(db_session):
    repo = UserRepository(db_session)
    repo.add(User(username="bob", email="bob@test.com", password_hash="h"))
    
    user = repo.get_by_email("bob@test.com")
    assert user is not None
    assert user.email == "bob@test.com"

def test_user_repository_list_active_users(db_session):
    repo = UserRepository(db_session)
    repo.add(User(username="active1", email="a1@test.com", password_hash="h", is_active=True))
    repo.add(User(username="inactive1", email="i1@test.com", password_hash="h", is_active=False))
    
    active_users = repo.list_active_users()
    assert len(active_users) == 1
    assert active_users[0].username == "active1"
