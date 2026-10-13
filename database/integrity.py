from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import inspect, text

from database.connection import get_engine, test_connection
from database.schema import get_registered_tables
from utils.logger import get_logger

logger = get_logger(__name__)

def check_database_connectivity() -> bool:
    """Checks if the database is reachable."""
    return test_connection()

def check_required_tables() -> dict:
    """
    Checks if all registered tables exist in the database.
    Returns a dictionary with status and details.
    """
    if not check_database_connectivity():
        return {"status": "failed", "message": "Database unreachable"}

    try:
        engine = get_engine()
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
        registered_tables = set(get_registered_tables())
        
        missing_tables = registered_tables - existing_tables
        if missing_tables:
            if existing_tables:
                return {
                    "status": "warning", 
                    "message": f"Schema partially missing. Missing tables: {', '.join(missing_tables)}"
                }
            else:
                return {
                    "status": "warning", 
                    "message": "Database reachable but schema not initialized"
                }
        
        return {"status": "success", "message": "All required tables are present"}
    except SQLAlchemyError as e:
        logger.error(f"Error checking required tables: {e}")
        return {"status": "failed", "message": f"Error inspecting schema"}

def check_schema_integrity() -> bool:
    """
    Performs a deep integrity check of the schema, checking if tables exist
    and can be queried simply. Does not modify data.
    """
    status_report = check_required_tables()
    if status_report["status"] != "success":
        return False
        
    engine = get_engine()
    try:
        with engine.connect() as conn:
            # simple rollback-only sanity check
            with conn.begin():
                for table in get_registered_tables():
                    conn.execute(text(f"SELECT * FROM {table} LIMIT 1"))
                # Rollback ensures no accidental modifications
                conn.rollback()
        return True
    except Exception as e:
        logger.error(f"Schema integrity check failed: {e}")
        return False

def get_database_status_report() -> dict:
    """Returns a comprehensive database status report."""
    return {
        "connectivity": "success" if check_database_connectivity() else "failed",
        "tables_status": check_required_tables(),
        "schema_integrity": "success" if check_schema_integrity() else "failed"
    }
