from database.base import Base
from sqlalchemy.orm import DeclarativeBase

def test_base_is_declarative_base():
    """Test that Base is importable and is a DeclarativeBase."""
    assert issubclass(Base, DeclarativeBase)
    
def test_base_metadata_exists():
    """Test that Base has a metadata attribute."""
    assert hasattr(Base, "metadata")
