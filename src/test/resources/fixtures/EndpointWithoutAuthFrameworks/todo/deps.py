from typing import Annotated

from fastapi import Depends, Header, HTTPException


def get_session():
    yield object()


SessionDependency = Annotated[object, Depends(get_session)]


def get_token(x_token: Annotated[str, Header()], session: SessionDependency):
    if not x_token:
        raise HTTPException(401, "Invalid token")
    return x_token


TokenDependency = Annotated[object, Depends(get_token)]
