from fastapi import FastAPI
from passlib.handlers.pbkdf2 import pbkdf2_sha256

from src.api.base_router import router
from src.core.admin_settings import admin_settings
from src.db.db import Session
from src.models.schemas.user.roles import Roles
from src.models.user import User


tags_dict = [
    {
        'name': 'users',
        'description': 'User handlers.'
    },
    {
        'name': 'auth',
        'description': 'Authentication handlers.'
    },
]

app = FastAPI(
    title='Backend API',
    description='That is backend API.',
    version='0.0.1',
    openapi_tags=tags_dict
)


@app.on_event('startup')
def user_on_startup(session: Session = Session()):
    users = (
        session
        .query(User)
        .filter(User.role == Roles.ADMIN.value)
        .order_by(
            User.id.desc()
        )
        .all()
    )
    if not users:
        user = User(
            username=admin_settings.login,
            password_hashed=pbkdf2_sha256.hash(admin_settings.password),
            role=Roles.ADMIN.value,
        )
        session.add(user)
        session.commit()
        return user
    return None


app.include_router(router)
