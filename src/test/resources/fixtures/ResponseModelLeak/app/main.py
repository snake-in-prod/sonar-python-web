from fastapi import Depends, FastAPI
from sqlalchemy import select

from . import crud
from .models import Device, Integration, Item, User
from .schemas import Credentials, Login, PaymentIntent, UserInDB, UserOut, WebhookEndpoint

app = FastAPI()


def get_db():
    yield None


def get_current_user():
    return None


@app.get("/users/{user_id}")
def read_user(user_id: int, db=Depends(get_db)):
    return db.get(User, user_id)  # Noncompliant {{GET /users/{user_id} returns User with its field hashed_password}} [[1]]


@app.get("/users/by-email/{email}")
def read_user_by_email(email: str, db=Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        return {"detail": "not found"}
    return user  # Noncompliant


@app.get("/me")
async def read_me(current_user: User = Depends(get_current_user)):
    return current_user  # Noncompliant


@app.post("/users", response_model=UserInDB)  # Noncompliant {{POST /users responds with UserInDB, which has the field hashed_password}}
def create_user(user: UserOut, db=Depends(get_db)):
    return user


@app.get("/users/{user_id}/raw")
def read_raw(user_id: int, db=Depends(get_db)):
    u = db.get(User, user_id)
    return {"id": u.id, "password": u.hashed_password}  # Noncompliant {{returns the key "password"}}


@app.get("/lookup")
def lookup(email: str, db=Depends(get_db)):
    return crud.get_user_by_email(db, email)  # Noncompliant


@app.get("/users/{user_id}/full")
def read_full(user_id: int, db=Depends(get_db)) -> UserInDB:  # Noncompliant
    return db.get(User, user_id)


@app.get("/users/{user_id}/scalar")
async def read_scalar(user_id: int, db=Depends(get_db)):
    return await db.scalar(select(User).where(User.id == user_id))  # Noncompliant


@app.get("/safe/{user_id}", response_model=UserOut)
def safe_model(user_id: int, db=Depends(get_db)):
    return db.get(User, user_id)


@app.get("/safe/{user_id}/annotated")
def safe_annotation(user_id: int, db=Depends(get_db)) -> UserOut:
    return db.get(User, user_id)


@app.get("/safe/{user_id}/excluded", response_model_exclude={"hashed_password"})
def safe_excluded(user_id: int, db=Depends(get_db)):
    return db.get(User, user_id)


@app.get("/stats/users")
def user_count(db=Depends(get_db)):
    return db.query(User).count()


@app.get("/stats/users/crud")
def user_count_crud(db=Depends(get_db)):
    return crud.count_users(db)


@app.post("/token")
def login(form: Login):
    return {"access_token": "x", "token_type": "bearer", "password": "changed"}


@app.post("/credentials")
def echo_credentials(c: Credentials):
    return c


@app.post("/login-echo")
def echo_login(c: Login):
    return c


@app.get("/emails")
def emails(db=Depends(get_db)):
    return db.query(User.email).all()


@app.get("/items")
def items(db=Depends(get_db)):
    return db.query(Item).all()


@app.get("/devices/{device_id}")
def device(device_id: int, db=Depends(get_db)):
    return db.get(Device, device_id)


@app.get("/users/{user_id}/email")
def user_email(user_id: int, db=Depends(get_db)):
    return db.get(User, user_id).email


# a schema that declares a client secret or a webhook secret is made to send it


@app.post("/payments", response_model=PaymentIntent)
def create_payment(db=Depends(get_db)):
    return PaymentIntent(id=1, client_secret="x")


@app.get("/webhooks/{id}", response_model=WebhookEndpoint)
def read_webhook(id: int, db=Depends(get_db)):
    return None


@app.get("/integrations/{id}")
def read_integration(id: int, db=Depends(get_db)):
    return db.get(Integration, id)
