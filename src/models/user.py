from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, ForeignKey

from src.models.base import Base
from src.models.schemas.user.roles import Roles


class User(Base):
    """User database model."""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    password_hashed = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True  # self registration case
    )
    role = Column(String, default=Roles.viewer.value)
