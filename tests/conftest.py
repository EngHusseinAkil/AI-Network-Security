import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from database.base import Base
# Ensure all models are imported to populate Base.metadata
from database.models import *

@pytest.fixture(scope="function")
def db_session() -> Session:
    """Provides an isolated SQLAlchemy session connected to an in-memory SQLite DB."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    # Create tables safely only in memory
    Base.metadata.create_all(engine)
    
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    
    yield session
    
    session.close()
    Base.metadata.drop_all(engine)
