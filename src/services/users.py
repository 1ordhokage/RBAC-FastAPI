from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.handlers.pbkdf2 import pbkdf2_sha256
from sqlalchemy.orm import Session

from src.core.jwt_settings import jwt_settings
from src.db.db import get_session
from src.models.schemas.user.user_request import UserRequest, UserUpdateRequest
from src.models.user import User
from src.models.schemas.utils.jwt import JwToken


oauth2_schema = OAuth2PasswordBearer(tokenUrl='/users/authorize')


def get_current_user_info(token: str = Depends(oauth2_schema)) -> (int, str):
    return UsersService.verify_token(token)


class UsersService:
    """User's service for interacting with the database."""

    def __init__(self, session: Session = Depends(get_session)) -> None:
        self.session = session

    @staticmethod
    def hash_password(password: str) -> str:
        """Converts text password to hash.
        Args:
            password: string password.
        Returns:
            str: hashed password.
        """
        return pbkdf2_sha256.hash(password)

    @staticmethod
    def check_password(password_text: str, password_hash: str) -> bool:
        """Compares hashed and text passwords.
        Args:
            password_text: string password.
            password_hash: hashed password.
        Returns:
            bool: comparison result.
        """
        return pbkdf2_sha256.verify(password_text, password_hash)

    @staticmethod
    def verify_token(token: str) -> (int, str):
        """Validates JWT.
        Args:
            token: given token.
        Returns:
            (int, str): user id and role.
        """
        try:
            payload = jwt.decode(
                token,
                jwt_settings.secret_key,
                algorithms=[jwt_settings.algorithm]
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid token'
            )
        return payload.get('sub'), payload.get('role')

    @staticmethod
    def create_token(user_id: int, user_role: str) -> JwToken:
        """Creates JWT.
        Args:
            user_id: user id.
            user_role: user role.
        Returns:
            JwToken: JWT.
        """
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + timedelta(seconds=jwt_settings.jwt_expires_seconds),
            'sub': str(user_id),
            'role': user_role
        }
        token = jwt.encode(
            payload,
            jwt_settings.jwt_secret,
            algorithm=jwt_settings.jwt_algorithm
        )
        return JwToken(access_token=token)

    def check_username_conflict(self, username: str) -> None:
        """Checks if there exists user with given username.
        Args:
            username: username.
        """
        try:
            self.get_user_by_name(username)
        except HTTPException:
            return
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='Already exists'
            )

    def register(self, username: str, password_text: str) -> None:
        """Adds new user to the database.
        Args:
            username: username.
            password_text: string password.
        """
        self.check_username_conflict(username)
        user = User(
            username=username,
            password_hashed=self.hash_password(password_text),
        )
        self.session.add(user)
        self.session.commit()

    def authorize(self, username: str, password_text: str) -> JwToken | None:
        """Authorizes user and creates JWT.
        Args:
            username: username.
            password_text: string password.
        Returns:
            JwToken: JWT.
        """
        user = self.get_user_by_name(username)
        if not self.check_password(password_text, user.password_hashed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid password"
            )
        return self.create_token(user.id, user.role)

    def get_all_users(self) -> list[User]:
        """Returns all users.
        Returns:
            list[User]: list of users.
        """
        users = (
            self.session
            .query(User)
            .order_by(User.id.desc())
            .all()
        )
        return users

    def get_user_by_id(self, user_id: int) -> User:
        """Finds user by given user_id.
        Args:
            user_id: user id.
        Returns:
            User: found user.
        """
        user = (
            self.session
            .query(User)
            .filter(User.id == user_id)
            .first()
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user

    def get_user_by_name(self, username: str) -> User:
        """Finds user by given username.
        Args:
            username: username.
        Returns:
            User: found user.
        """
        user = (
            self.session
            .query(User)
            .filter(User.username == username)
            .first()
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user

    def add_user(self, user_schema: UserRequest, super_user_id: int) -> User:
        """Creates user by given user schema and saves it in database.
        Args:
            user_schema: user request schema.
            super_user_id: creator user id.
        Returns:
            User: created user.
        """
        self.check_username_conflict(user_schema.username)
        user = User(
            username=user_schema.username,
            password_hashed=self.hash_password(user_schema.password_text),
            role=user_schema.role,
            created_by=super_user_id
        )
        self.session.add(user)
        self.session.commit()
        return user

    def update_user(self, user_id: int, user_schema: UserUpdateRequest,
                    super_user_id: int) -> User:
        """Updates user by given user schema.
        Args:
            user_id: changeable user id.
            user_schema: user update schema.
            super_user_id: changer user id.
        Returns:
            User: updated user.
        """
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
        """Deletes user by given id.
        Args:
            user_id: user id.
        """
        user = self.get_user_by_id(user_id)
        self.session.delete(user)
        self.session.commit()
