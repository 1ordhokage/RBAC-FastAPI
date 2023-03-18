from pydantic import BaseSettings


class DBSettings(BaseSettings):
    """Database config class."""
    connection_string: str

    class Config:
        env_file = '../.env'
        env_prefix = 'DB_'


db_settings = DBSettings()
