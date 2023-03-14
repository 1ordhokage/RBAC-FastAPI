from pydantic import BaseSettings


class JwtSettings(BaseSettings):
    """JWT config class."""
    algorithm: str
    expires_seconds: str
    secret_key: str

    class Config:
        env_file = '../.env'
        env_prefix = "JWT_"


jwt_settings = JwtSettings()
