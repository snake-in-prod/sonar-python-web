from typing import Annotated

from fastapi import Cookie, Depends
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    yield None


def get_current_user(token: str = Depends(oauth2_scheme)):
    return {"token": token}


CurrentUser = Annotated[dict, Depends(get_current_user)]


def require_admin(user=Depends(get_current_user)):
    return user


def lookup(t=Depends(oauth2_scheme)):
    return t


def who_is_calling(session_id: str | None = Cookie(default=None)):
    return session_id
