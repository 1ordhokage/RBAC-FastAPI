from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.handlers.pbkdf2 import pbkdf2_sha256
from sqlalchemy.orm import Session

from src.core.db_settings import settings
from src.db.db import get_session
from src.models.schemas.user.roles import Roles
from src.models.schemas.user.user_request import UserRequest, UserUpdate
from src.models.user import User
from src.models.schemas.utils.jwt_token import JwtToken


oauth2_schema = OAuth2PasswordBearer(tokenUrl='/users/authorize')


def get_current_user_id(token: str = Depends(oauth2_schema)) -> int:
    return UsersService.verify_token(token)


class UsersService:
    def __init__(self, session: Session = Depends(get_session)) -> None:
        self.session = session

    @staticmethod
    def hash_password(password: str) -> str:
        """str password -> hashed password

        Args:
            password (str): string password

        Returns:
            str: hashed password
        """
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def check_password(password_text: str, password_hash: str) -> bool:
        return pbkdf2_sha256.verify(password_text, password_hash)

    @staticmethod
    def verify_token(token: str) -> int | None:
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return payload.get('sub')

    @staticmethod
    def create_token(user_id: int) -> JwtToken:
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + timedelta(seconds=settings.jwt_expires_seconds),
            'sub': str(user_id),
        }
        token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        return JwtToken(access_token=token)

    def register(self, username: str, password_text: str) -> None:
        if self.get_user_by_name(username):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Already exists")
        user = User(
            username=username,
            password_hashed=self.hash_password(password_text),
        )
        self.session.add(user)
        self.session.commit()

    def authorize(self, username: str, password_text: str) -> JwtToken | None:
        user = (
            self.session
            .query(User)
            .filter(User.username == username)
            .first()
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user")

        if not self.check_password(password_text, user.password_hashed):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid password")

        return self.create_token(user.id)

    def get_all_users(self) -> list[User]:
        users = (
            self.session
            .query(User)
            .order_by(
                User.id.desc()
            )
            .all()
        )
        return users

    def get_user_by_id(self, user_id: int) -> User:
        user = (
            self.session
            .query(User)
            .filter(
                User.id == user_id
            )
            .first()
        )
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="User not found")
        return user

    def get_user_by_name(self, username: str) -> User:
        user = (
            self.session
            .query(User)
            .filter(
                User.username == username
            )
            .first()
        )
        return user

    def add_user(self, user_schema: UserRequest, super_user_id: int) -> User:
        if self.get_user_by_name(user_schema.username):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Already existst")
        user = User(
            username=user_schema.username,
            password_hashed=self.hash_password(user_schema.password_text),
            role=user_schema.role,
            created_by=super_user_id
        )
        self.session.add(user)
        self.session.commit()
        return user

    def update_user(self, user_id: int, user_schema: UserUpdate, super_user_id: int) -> User:
        user = self.get_user_by_id(user_id)
        was_modified = False
        for field, value in user_schema:
            if value:
                if field == "password_text":
                    setattr(user, field, self.hash_password(value))
                else:
                    setattr(user, field, value)
                was_modified = True
        if was_modified:
            user.modified_by = super_user_id
        self.session.commit()
        return user

    def delete_user(self, user_id: int) -> None:
        user = self.get_user_by_id(user_id)
        self.session.delete(user)
        self.session.commit()

    def check_permission(self, user_id: int) -> None:
        user = self.get_user_by_id(user_id)
        if user.role != Roles.admin.value:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not an admin")
