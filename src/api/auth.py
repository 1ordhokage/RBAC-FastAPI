from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from src.models.schemas.utils.jwt import JwToken

from src.services.users import UsersService

router = APIRouter(
    tags=['auth'],
)


@router.post(
    '/register',
    status_code=status.HTTP_201_CREATED,
    name='Registration'
)
def register(
    username: str,
    password_text: str,
    user_service: UsersService = Depends()
):
    return user_service.register(username, password_text)


@router.post(
    '/authorize',
    status_code=status.HTTP_200_OK,
    response_model=JwToken,
    name='Authorization'
)
def authorize(
    auth_schema: OAuth2PasswordRequestForm = Depends(),
    users_service: UsersService = Depends()
):
    return users_service.authorize(auth_schema.username, auth_schema.password)
