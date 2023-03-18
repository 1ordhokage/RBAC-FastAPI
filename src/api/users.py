from fastapi import APIRouter, Depends, HTTPException, status

from src.models.schemas.user.roles import Roles
from src.models.schemas.user.user_request import UserRequest, UserUpdateRequest
from src.models.schemas.user.user_response import UserResponse

from src.services.users import UsersService, get_current_user_info


router = APIRouter(
    prefix='/users',
    tags=['users'],
)


class RoleChecker:
    """Permission-checker implementation."""
    def __init__(self, roles: list):
        self.roles = roles

    def __call__(self, payload: dict = Depends(get_current_user_info)):
        if payload.get('role') not in self.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='You are not an admin'
            )


allowed_roles = RoleChecker([Roles.ADMIN.value])


@router.post(
    '/create',
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(allowed_roles)],
    name='User creation'
)
def create_user(
    user_schema: UserRequest,
    user_service: UsersService = Depends(),
    super_user_info: dict = Depends(get_current_user_info)
):
    return user_service.add_user(user_schema, super_user_info.get('sub'))


@router.get(
    '/all',
    response_model=list[UserResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(allowed_roles)],
    name='Get all users'
)
def get_all_users(user_service: UsersService = Depends()):
    return user_service.get_all_users()


@router.get(
    '/get/{user_id}',
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(allowed_roles)],
    name='Get user by id'
)
def get_user_by_id(user_id: int, user_service: UsersService = Depends()):
    return user_service.get_user_by_id(user_id)


@router.put(
    '/update/{user_id}',
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(allowed_roles)],
    name='Update user'
)
def update_user(
    user_id: int, user_schema: UserUpdateRequest,
    user_service: UsersService = Depends(),
    super_user_info: dict = Depends(get_current_user_info)
):
    return user_service.update_user(
        user_id,
        user_schema,
        super_user_info.get('sub')
    )


@router.delete(
    '/delete/{user_id}',
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(allowed_roles)],
    name='Delete user'
)
def delete_user(user_id: int, user_service: UsersService = Depends()):
    return user_service.delete_user(user_id)
