from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base, deferred

Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    hashed_password = Column(String)
    password_changed_at = Column(String)


class Item(Base):
    __tablename__ = "item"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    content_hash = Column(String)


class Device(Base):
    __tablename__ = "device"
    id = Column(Integer, primary_key=True)
    secret = deferred(Column(String))


class Integration(Base):
    __tablename__ = "integration"
    id = Column(Integer, primary_key=True)
    client_secret_last_4 = Column(String)
