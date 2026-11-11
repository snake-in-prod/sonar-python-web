from fastapi import Depends, FastAPI, Request

from .deps import get_current_user, get_db
from .routers import admin, items

app = FastAPI()
app.include_router(items.router, prefix="/api")
app.include_router(admin.router, prefix="/admin", dependencies=[Depends(get_current_user)])


@app.post("/token")
def login_for_token(form: dict, db=Depends(get_db)):
    db.add(form)
    return {"access_token": "x"}


@app.post("/predict")
def predict(features: list[float]):
    return {"score": sum(features)}


@app.post("/notes")
def create_note(text: str, db=Depends(get_db)):  # Noncompliant {{POST /notes has no authentication}} [[1]]
    db.add(text)
    db.commit()


@app.put("/notes/{note_id}")
def replace_note(note_id: int, request: Request, db=Depends(get_db)):
    if request.headers.get("Authorization") != "expected":
        return None
    db.merge(note_id)


@app.get("/notes")
def list_notes(db=Depends(get_db)):
    return []
