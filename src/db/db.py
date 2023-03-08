from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.core.db_settings import db_settings


engine = create_engine(
    db_settings.db_connection_string
)

Session = sessionmaker(
    engine,
    autocommit=False,
    autoflush=False
)


def get_session():
    session = Session()
    try:
        yield session
    finally:
        session.close()
