from fastapi import Depends, Header
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    yield None


def get_current_user(token: str = Depends(oauth2_scheme)):
    return token


def load_owner(x_owner: str = Header(...)):
    return x_owner
