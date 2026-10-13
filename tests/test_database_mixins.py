import pytest
import datetime
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from database.base import Base
from database.mixins import IDMixin, TimestampMixin, SoftDeleteMixin, AuditMixin

class DummyModel(Base, IDMixin, TimestampMixin, SoftDeleteMixin, AuditMixin):
    __tablename__ = 'dummy_test_model'
    name: Mapped[str] = mapped_column(String(50))

def test_mixins_columns_exist():
    """Test that the dummy model has the expected columns from mixins."""
    columns = DummyModel.__table__.columns
    
    assert 'id' in columns
    assert 'created_at' in columns
    assert 'updated_at' in columns
    assert 'deleted_at' in columns
    assert 'is_deleted' in columns
    assert 'created_by' in columns
    assert 'updated_by' in columns

def test_mixins_primary_key():
    """Test that the IDMixin provides a primary key."""
    columns = DummyModel.__table__.columns
    assert columns['id'].primary_key is True

def test_mixins_nullable_defaults():
    """Test nullability of some key columns."""
    columns = DummyModel.__table__.columns
    
    assert columns['created_at'].nullable is False
    assert columns['updated_at'].nullable is False
    assert columns['deleted_at'].nullable is True
    assert columns['is_deleted'].nullable is False
    
    assert columns['created_at'].default is not None
    assert columns['updated_at'].default is not None
