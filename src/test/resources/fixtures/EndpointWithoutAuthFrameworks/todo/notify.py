from fastapi import APIRouter, FastAPI

from . import crud
from .deps import SessionDependency


def build_router() -> APIRouter:
    router = APIRouter(prefix="/notifications")

    @router.delete("/clear")
    async def clear_notifications(session: SessionDependency):
        await crud.delete_item(session, None)

    return router


def init_notifications(app: FastAPI) -> None:
    # only tests call this: the router is never served
    app.include_router(build_router())
