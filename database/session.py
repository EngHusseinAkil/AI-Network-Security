from contextlib import contextmanager
from typing import Generator
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError

from database.connection import get_engine
from utils.logger import get_logger
from utils.exceptions import DatabaseError

logger = get_logger("DatabaseSession")

_SessionFactory = None

def get_session_factory() -> sessionmaker:
    """Returns the singleton sessionmaker instance."""
    global _SessionFactory
    if _SessionFactory is None:
        engine = get_engine()
        _SessionFactory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return _SessionFactory

def get_session() -> Session:
    """Returns a new SQLAlchemy Session."""
    factory = get_session_factory()
    return factory()

@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """
    Provide a transactional scope around a series of operations.
    Safely commits on success, rolls back on error, and closes the session.
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database transaction failed, rolling back. Error: {e}")
        raise DatabaseError(f"Transaction failed: {e}")
    except Exception as e:
        session.rollback()
        logger.error(f"Unexpected error in transaction, rolling back. Error: {e}")
        raise
    finally:
        session.close()
