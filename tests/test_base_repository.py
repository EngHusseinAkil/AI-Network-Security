import pytest
from database.models import User
from database.repositories.base_repository import BaseRepository

def test_base_repository_add_and_get(db_session):
    repo = BaseRepository(User, db_session)
    user = User(username="test_base", email="base@test.com", password_hash="hash")
    
    # Add
    repo.add(user)
    assert user.id is not None
    
    # Get by ID
    fetched = repo.get_by_id(user.id)
    assert fetched is not None
    assert fetched.username == "test_base"

def test_base_repository_get_all_and_count(db_session):
    repo = BaseRepository(User, db_session)
    repo.add(User(username="user1", email="1@test.com", password_hash="h"))
    repo.add(User(username="user2", email="2@test.com", password_hash="h"))
    
    assert repo.count() == 2
    
    users = repo.get_all(limit=1)
    assert len(users) == 1
    
    users_offset = repo.get_all(limit=1, offset=1)
    assert len(users_offset) == 1
    assert users[0].id != users_offset[0].id

def test_base_repository_delete(db_session):
    repo = BaseRepository(User, db_session)
    user = User(username="del_user", email="del@test.com", password_hash="h")
    repo.add(user)
    
    assert repo.count() == 1
    repo.delete(user)
    assert repo.count() == 0
