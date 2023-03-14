from pydantic import BaseModel


class JwToken(BaseModel):
    """Auxiliary data schema for object with token."""
    access_token: str
