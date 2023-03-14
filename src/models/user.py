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
    role = Column(String, default=Roles.VIEWER.value)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True  # self registration case
    )
    modified_at = Column(
        DateTime,
        onupdate=datetime.now,
        nullable=True
    )
    modified_by = Column(
        Integer,
        ForeignKey('users.id'),
        nullable=True  # self registration case
    )
