from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from database.models import User
from database.repositories.base_repository import BaseRepository
from utils.exceptions import DatabaseError
from utils.logger import get_logger

logger = get_logger(__name__)

class UserRepository(BaseRepository[User]):
    def __init__(self, session: Session):
        super().__init__(User, session)

    def get_by_username(self, username: str) -> Optional[User]:
        try:
            stmt = select(User).where(User.username == username, User.is_deleted == False)
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching user by username: {e}")
            raise DatabaseError("Error fetching user by username", details={"error": str(e)})

    def get_by_email(self, email: str) -> Optional[User]:
        try:
            stmt = select(User).where(User.email == email, User.is_deleted == False)
            result = self.session.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error(f"Error fetching user by email: {e}")
            raise DatabaseError("Error fetching user by email", details={"error": str(e)})

    def list_active_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        try:
            stmt = select(User).where(User.is_active == True, User.is_deleted == False).limit(limit).offset(offset)
            result = self.session.execute(stmt)
            return list(result.scalars().all())
        except SQLAlchemyError as e:
            logger.error(f"Error listing active users: {e}")
            raise DatabaseError("Error listing active users", details={"error": str(e)})
