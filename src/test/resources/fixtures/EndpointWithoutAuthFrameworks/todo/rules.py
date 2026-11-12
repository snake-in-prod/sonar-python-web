from fastapi import APIRouter, FastAPI

from . import crud
from .deps import SessionDependency


def build_router() -> APIRouter:
    router = APIRouter(prefix="/rules")

    @router.delete("/{rule_id}")
    async def delete_rule(rule_id: int, session: SessionDependency):  # Noncompliant
        await crud.delete_item(session, rule_id)

    return router


def register(app: FastAPI) -> None:
    # called by server.py: the router is served
    app.include_router(build_router())
