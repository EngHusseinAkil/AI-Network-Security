from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """
    Project declarative base.
    All application ORM models should inherit from this class.
    """
    pass
