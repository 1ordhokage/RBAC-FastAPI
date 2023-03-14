from pydantic import BaseModel

from src.models.schemas.user.roles import Roles


class UserRequest(BaseModel):
    """User request schema."""
    username: str
    password_text: str
    role: Roles = Roles.VIEWER

    class Config:
        use_enum_values = True


class UserUpdateRequest(BaseModel):
    username: str | None
    password_text: str | None
    role: Roles | None

    class Config:
        use_enum_values = True
