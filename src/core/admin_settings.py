from pydantic import BaseSettings


class AdminSettings(BaseSettings):
    """Admin config class."""
    login: str
    password: str

    class Config:
        env_file = '../.env'
        env_prefix = 'ADMIN_'


admin_settings = AdminSettings()
