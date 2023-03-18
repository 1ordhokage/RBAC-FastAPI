from fastapi import APIRouter

from src.api import auth, users


router = APIRouter()
handlers = [auth, users]

for handler in handlers:
    router.include_router(handler.router)
