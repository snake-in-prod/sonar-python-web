import os
from pathlib import Path

import aiofiles
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator

app = FastAPI()
BASE = Path("/srv/files")


@app.get("/download")
def download(name: str):
    return FileResponse(os.path.join("/srv/files", name))  # Noncompliant {{parameter name of GET /download}}


@app.post("/upload")
async def upload(file: UploadFile):
    data = await file.read()
    target = BASE / file.filename
    target.write_bytes(data)  # Noncompliant
    return {"ok": True}


@app.post("/upload-async")
async def upload_async(file: UploadFile):
    async with aiofiles.open(f"/srv/files/{file.filename}", "wb") as out:  # Noncompliant
        await out.write(await file.read())
    return {"ok": True}


@app.get("/view/{name}")
def view(name: str):
    # a path parameter without the path converter holds no "/"
    return FileResponse(BASE / name)


@app.get("/checked")
def checked(name: str):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError(name)
    return FileResponse(target)


@app.get("/numbered")
def numbered(page: int):
    return FileResponse(f"/srv/files/page-{page}.html")


class Export(BaseModel):
    name: str


class Build(BaseModel):
    slug: str

    @field_validator("slug")
    @classmethod
    def snake_case(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError(v)
        return v


@app.post("/exports")
def create_export(body: Export):
    with open(BASE / body.name, "w") as out:  # Noncompliant
        out.write("")


@app.post("/builds")
def create_build(body: Build):
    # the model validates its fields: what it allows is out of sight
    with open(BASE / body.slug, "w") as out:
        out.write("")
