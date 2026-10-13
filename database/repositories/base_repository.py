from typing import TypeVar, Generic, Type, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError

from database.base import Base
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

ModelType = TypeVar("ModelType", bound=Base)

class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], session: Session):
        self.model = model
        self.session = session

    def get_by_id(self, id: Any) -> Optional[ModelType]:
        try:
            return self.session.get(self.model, id)
        except SQLAlchemyError as e:
            logger.error(f"Error fetching {self.model.__name__} by id: {e}")
            raise DatabaseError(f"Error fetching {self.model.__name__} by id", details={"error": str(e)})

    def get_all(self, limit: int = 100, offset: int = 0) -> List[ModelType]:
        try:
            stmt = select(self.model).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error fetching all {self.model.__name__}: {e}")
            raise DatabaseError(f"Error fetching all {self.model.__name__}", details={"error": str(e)})

    def add(self, obj: ModelType) -> ModelType:
        try:
            self.session.add(obj)
            self.session.flush()
            return obj
        except SQLAlchemyError as e:
            logger.error(f"Error adding {self.model.__name__}: {e}")
            raise DatabaseError(f"Error adding {self.model.__name__}", details={"error": str(e)})

    def delete(self, obj: ModelType) -> None:
        try:
            self.session.delete(obj)
            self.session.flush()
        except SQLAlchemyError as e:
            logger.error(f"Error deleting {self.model.__name__}: {e}")
            raise DatabaseError(f"Error deleting {self.model.__name__}", details={"error": str(e)})

    def count(self) -> int:
        try:
            stmt = select(func.count()).select_from(self.model)
            result = self.session.execute(stmt)
            return result.scalar_one()
        except SQLAlchemyError as e:
            logger.error(f"Error counting {self.model.__name__}: {e}")
            raise DatabaseError(f"Error counting {self.model.__name__}", details={"error": str(e)})
