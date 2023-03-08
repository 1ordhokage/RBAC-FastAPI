from pydantic import BaseModel

from src.models.schemas.user.roles import Roles


class UserRequest(BaseModel):
    """User request schema."""
    username: str
    password_text: str
    role: Roles = Roles.viewer

    class Config:
        use_enum_values = True
