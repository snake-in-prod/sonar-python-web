import asyncio
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, Request, UploadFile, WebSocket
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from .services import Item, Mailer, get_session, get_sync_session, log_event, notify_user, retrying_notify, stream_rows

app = FastAPI()


@app.post("/users/{user_id}/notify")
async def notify(user_id: int):
    notify_user(user_id)  # Noncompliant {{Add await before notify_user(): the coroutine never runs in POST /users/{user_id}/notify}}
    return {"ok": True}


@app.post("/echo")
async def echo(request: Request):
    data = request.json()  # Noncompliant {{request.json()}}
    return {"name": data["name"]}


@app.post("/upload")
async def upload(file: UploadFile):
    content = await file.read()
    file.close()  # Noncompliant
    return {"size": len(content)}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    websocket.send_text("hello")  # Noncompliant


@app.post("/pause")
async def pause():
    asyncio.sleep(1)  # Noncompliant
    return {}


@app.post("/mail")
async def mail():
    mailer = Mailer()
    await mailer.send_all()
    pending = notify_user(1)  # Noncompliant
    return {}


# compliant near misses


@app.post("/notify/awaited")
async def notify_awaited(user_id: int, background_tasks: BackgroundTasks):
    await notify_user(user_id)
    asyncio.create_task(notify_user(user_id))
    background_tasks.add_task(notify_user, user_id)
    log_event("notified")
    return {"ok": True}


@app.post("/notify/later")
async def notify_later(user_id: int):
    task = notify_user(user_id)
    await task
    return notify_user(user_id)


@app.post("/notify/gathered")
async def notify_gathered():
    first = notify_user(1)
    second = notify_user(2)
    await asyncio.gather(first, second)


@app.get("/rows")
async def rows():
    stream_rows()
    retrying_notify(1)
    return [row async for row in stream_rows()]


@app.post("/upload/sync")
async def upload_sync(file: UploadFile, request):
    file.file.read()
    request.json()
    return {}


async def run_with(notify_user):
    notify_user(3)


SessionDep = Annotated[AsyncSession, Depends(get_session)]


@app.post("/items")
async def create_item(name: str, db: AsyncSession = Depends(get_session)):
    item = Item(name=name)
    db.add(item)
    db.commit()  # Noncompliant {{Add await before db.commit()}}
    await db.refresh(item)
    return item


@app.delete("/items/{item_id}")
async def delete_item(item_id: int, session: SessionDep):
    item = await session.get(Item, item_id)
    session.delete(item)  # Noncompliant
    await session.commit()
    return {}


@app.get("/items/sync")
def list_items_sync(db: Session = Depends(get_sync_session)):
    db.commit()
    return []
