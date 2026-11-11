from fastapi import Depends, FastAPI

from .deps import get_current_user
from .routers import items, users

app = FastAPI(title="shop")
app.include_router(items.router, prefix="/api")
app.include_router(users.router, prefix="/api", dependencies=[Depends(get_current_user)])


@app.get("/health")
async def health():
    return {"ok": True}
