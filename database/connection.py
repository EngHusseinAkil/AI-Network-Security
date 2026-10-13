from sqlalchemy import create_engine, Engine, text, event
from sqlalchemy.exc import SQLAlchemyError

from config import settings
from utils.logger import get_logger
from utils.exceptions import DatabaseError

logger = get_logger("DatabaseConnection")

_engine = None

def dispose_engine() -> bool:
    """Dispose the existing engine without creating one during shutdown."""
    global _engine
    if _engine is None:
        return True
    _engine.dispose()
    _engine = None
    return True

def get_engine() -> Engine:
    """
    Creates and returns the SQLAlchemy Engine.
    Uses singleton pattern to avoid multiple engine instances.
    """
    global _engine
    if _engine is not None:
        return _engine

    try:
        uri = settings.DATABASE_URI
        
        connect_args = {}
        # If SQLite, add check_same_thread=False for concurrency handling
        if uri.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            
        engine_options = {
            "connect_args": connect_args,
            "echo": settings.DEBUG,
            "pool_pre_ping": True,
        }
        if not uri.startswith("sqlite"):
            engine_options.update(
                pool_size=getattr(settings, "DATABASE_POOL_SIZE", 5),
                max_overflow=getattr(settings, "DATABASE_MAX_OVERFLOW", 10),
            )
        _engine = create_engine(uri, **engine_options)
        
        # Enforce SQLite foreign keys
        if uri.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        logger.info(f"Database engine created for URI starting with: {uri.split('://')[0]}")
        return _engine
    except Exception:
        logger.error("Database engine creation failed safely.")
        raise DatabaseError("Failed to create database engine")

def test_connection() -> bool:
    """
    Tests the database connection by executing a simple query.
    """
    engine = get_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            logger.debug("Database connection test successful.")
            return True
    except SQLAlchemyError as e:
        logger.error(f"Database connection test failed: {e}")
        return False
