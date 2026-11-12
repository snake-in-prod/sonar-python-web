from fastapi import FastAPI, HTTPException

from . import crud, rules
from .deps import SessionDependency, TokenDependency
from .security import hash_password

app = FastAPI()
rules.register(app)


@app.post("/v1/todo/")
async def create_todo(session: SessionDependency, token: TokenDependency):
    await crud.add_item(session, token)


@app.delete("/v1/todo/{todo_id}")
async def delete_todo(todo_id: int, session: SessionDependency):  # Noncompliant {{DELETE /v1/todo/{todo_id} has no authentication: add an auth dependency (Depends(get_current_user)) on the route or its router, as other endpoints of this app do.}}
    await crud.delete_item(session, todo_id)


@app.patch("/v1/todo/{todo_id}")
async def update_todo(todo_id: int, session: SessionDependency, token=TokenDependency):
    todo = await crud.get_item(session, todo_id)
    if todo.user_id != token.user_id:
        raise HTTPException(403, "not authorized")
    await crud.add_item(session, todo)


@app.post("/v1/user/")
async def create_user(session: SessionDependency, name: str, password: str):
    user = {"name": name, "password": hash_password(password)}
    await crud.add_item(session, user)


@app.post("/v1/accounts")
async def open_account(session: SessionDependency, name: str, password: str):
    await crud.add_user(session, name, password)


@app.post("/v1/admin/users")
async def admin_create_user(session: SessionDependency, name: str, password: str):  # Noncompliant
    await crud.add_item(session, {"name": name, "password": hash_password(password)})


@app.patch("/v1/user/{user_id}")
async def update_user(user_id: int, session: SessionDependency, password: str):  # Noncompliant
    await crud.update_item(session, user_id, {"password": hash_password(password)})
