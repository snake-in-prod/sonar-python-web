from fastapi import FastAPI

from todo.notify import init_notifications
from todo.vision import router


def test_routers():
    app = FastAPI()
    app.include_router(router)
    init_notifications(app)
