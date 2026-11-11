from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session


def get_db():
    yield Session()


def open_session(tenant: str) -> Session:
    return Session()


async def get_async_db():
    yield None


SessionDep = Annotated[Session, Depends(get_db)]
