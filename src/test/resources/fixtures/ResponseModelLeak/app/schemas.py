from pydantic import BaseModel, Field, SecretStr


class UserOut(BaseModel):
    id: int
    email: str


class UserInDB(UserOut):
    hashed_password: str


class Credentials(BaseModel):
    login: str
    password: SecretStr


class Login(BaseModel):
    email: str
    password: str = Field(exclude=True)


class PaymentIntent(BaseModel):
    id: int
    client_secret: str


class WebhookEndpoint(BaseModel):
    url: str
    secret: str
