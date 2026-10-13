from typing import List, Set
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import inspect

from database.base import Base
# ensure models are loaded so Base.metadata is populated
import database.models
from database.connection import get_engine
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

def get_registered_tables() -> List[str]:
    """Returns a list of table names registered with the declarative Base."""
    return list(Base.metadata.tables.keys())

def create_schema(engine=None) -> None:
    """Creates all registered tables in the database."""
    try:
        db_engine = engine or get_engine()
        Base.metadata.create_all(db_engine)
        logger.info("Database schema created successfully.")
    except SQLAlchemyError as e:
        logger.error(f"Error creating database schema: {e}")
        raise DatabaseError("Error creating database schema", details={"error": str(e)})

def drop_schema(confirm: bool = False, engine=None) -> None:
    """Drops all registered tables in the database. Requires confirm=True."""
    if not confirm:
        logger.warning("Attempted to drop schema without confirmation.")
        raise DatabaseError("Safety abort: confirm=True is required to drop schema.")
    
    try:
        db_engine = engine or get_engine()
        Base.metadata.drop_all(db_engine)
        logger.info("Database schema dropped successfully.")
    except SQLAlchemyError as e:
        logger.error(f"Error dropping database schema: {e}")
        raise DatabaseError("Error dropping database schema", details={"error": str(e)})

def reset_schema(confirm: bool = False, engine=None) -> None:
    """Drops and recreates all registered tables. Requires confirm=True."""
    if not confirm:
        logger.warning("Attempted to reset schema without confirmation.")
        raise DatabaseError("Safety abort: confirm=True is required to reset schema.")
    
    logger.info("Resetting database schema...")
    drop_schema(confirm=True, engine=engine)
    create_schema(engine=engine)
    logger.info("Database schema reset successfully.")

def verify_schema(engine=None) -> bool:
    """Verifies that all registered tables exist in the database."""
    try:
        db_engine = engine or get_engine()
        inspector = inspect(db_engine)
        existing_tables = set(inspector.get_table_names())
        registered_tables = set(get_registered_tables())
        
        # Check if all registered tables are in existing tables
        missing_tables = registered_tables - existing_tables
        
        if missing_tables:
            logger.warning(f"Schema verification failed. Missing tables: {missing_tables}")
            return False
            
        logger.info("Schema verification passed.")
        return True
    except SQLAlchemyError as e:
        logger.error(f"Error verifying database schema: {e}")
        raise DatabaseError("Error verifying database schema", details={"error": str(e)})
