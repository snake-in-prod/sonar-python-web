import asyncio
import os
import subprocess

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Job(BaseModel):
    name: str
    retries: int = 0


@app.get("/disk")
def disk(mount: str):
    return os.popen(f"df -h {mount}").read()  # Noncompliant {{parameter mount of GET /disk}}


@app.post("/jobs")
async def start_job(job: Job):
    proc = await asyncio.create_subprocess_shell("run-job --name " + job.name)  # Noncompliant
    await proc.wait()
    return {"ok": True}


@app.get("/top")
def top(n: int):
    return os.popen(f"top -b -n {n}").read()


@app.get("/user")
def user(login: str):
    if not login.isalnum():
        return {"error": "bad login"}
    return subprocess.run(f"id {login}", shell=True, capture_output=True).stdout


@app.get("/echo")
def echo(text: str):
    return subprocess.run(["echo", text], shell=False, capture_output=True).stdout
