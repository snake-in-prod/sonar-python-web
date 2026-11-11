from dataclasses import dataclass, field
from typing import ClassVar

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

app = FastAPI()


class ItemIn(BaseModel):
    name: str
    tags: list[str] = []
    attrs: dict = Field(default={})


@dataclass
class Settings:
    hosts: list = []  # Noncompliant {{dataclass Settings raise ValueError at import; use field(default_factory=list)}}
    headers: dict = field(default={"a": "b"})  # Noncompliant {{field(default_factory=a function building it)}}
    plugins: list = field(default_factory=list)
    registry: ClassVar[list] = []
    cache = {}
    name: str = "app"
    ports: tuple = (80, 443)


@dataclass(frozen=True)
class Limits:
    sizes: set = set()  # Noncompliant


@app.post("/items")
def create_item(item: ItemIn, tags: list[str] = Query([]), extra: dict = {}):
    tags.append(item.name)
    extra["seen"] = True
    return {"tags": tags}


def collect(values, out=[]):
    out.extend(values)
    return out
