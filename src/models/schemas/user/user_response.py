from pydantic import BaseModel

from src.models.schemas.user.roles import Roles


class UserResponse(BaseModel):
    """User response schema."""
    id: int
    username: str
    password_hashed: str
    role: Roles

    class Config:
        orm_mode = True
        use_enum_values = True
