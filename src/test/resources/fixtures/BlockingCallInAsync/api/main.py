import asyncio
import subprocess
import time
from pathlib import Path

import httpx
import requests
from fastapi import APIRouter, Depends, FastAPI
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from .db import SessionDep, get_async_db, get_db, open_session
from .services import fetch_rates, load_report, notify_async, read_config

app = FastAPI()
router = APIRouter(prefix="/v1")

RATES_URL = "https://rates.example/latest"


@app.get("/rate")
async def rate():
    return requests.get(RATES_URL).json()  # Noncompliant {{requests.get() blocks the event loop of async GET /rate}}


@app.post("/slow")
async def slow():
    time.sleep(2)  # Noncompliant {{use await asyncio.sleep()}}
    return {}


@app.get("/config")
async def config():
    with open("config.json") as f:  # Noncompliant {{aiofiles}}
        return f.read()


@app.get("/readme")
async def readme():
    return Path("README.md").read_text()  # Noncompliant


@router.get("/items")
async def items(db: Session = Depends(get_db)):
    return db.query(Item).all()  # Noncompliant {{db.query() blocks the event loop of async GET /v1/items}}


@router.get("/items/count")
async def count_items(db: SessionDep):
    return db.execute("SELECT count(*) FROM item").scalar()  # Noncompliant


@router.get("/proxy")
async def proxy(url: str):
    with httpx.Client() as client:
        return client.get(RATES_URL).text  # Noncompliant {{client.get()}}


@router.post("/build")
async def build():
    subprocess.run(["make", "all"])  # Noncompliant


@router.get("/rates/sync")
async def rates_sync():
    return fetch_rates()  # Noncompliant {{fetch_rates() makes a blocking call (requests.get()) in async GET /v1/rates/sync}} [[1]]


@router.get("/report")
async def report():
    return load_report("daily")  # Noncompliant [[2]]


def load_tenant_items(tenant):
    session = open_session(tenant)
    return session.query(Item).all()


@router.get("/tenants/{tenant}/items")
async def tenant_items(tenant: str):
    return load_tenant_items(tenant)  # Noncompliant {{load_tenant_items() makes a blocking call (session.query())}} [[1]]


@router.post("/notify")
async def notify():
    await notify_async("hello")
    return {}


# compliant near misses


@app.get("/rate/sync")
def rate_sync_endpoint():
    return requests.get(RATES_URL).json()


@app.post("/wait")
async def wait():
    await asyncio.sleep(2)
    time.sleep(0)
    return {}


@app.get("/rate/thread")
async def rate_in_thread():
    response = await asyncio.to_thread(requests.get, RATES_URL)
    return response.json()


@app.get("/rate/pool")
async def rate_in_pool():
    return await run_in_threadpool(fetch_rates)


@app.get("/rate/executor")
async def rate_in_executor():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: requests.get(RATES_URL).json())


@app.get("/rate/async")
async def rate_async():
    async with httpx.AsyncClient() as client:
        response = await client.get(RATES_URL)
    return response.json()


@router.get("/items/async")
async def items_async(db: AsyncSession = Depends(get_async_db)):
    result = await db.execute("SELECT * FROM item")
    return result.all()


@router.get("/config/thread")
async def config_in_thread():
    def work():
        with open("config.json") as f:
            return f.read()

    return await asyncio.to_thread(work)


@router.get("/config/pool")
async def config_pool():
    return await run_in_threadpool(read_config, "app.json")


@router.get("/config/helper")
async def config_helper():
    # a helper's local file read is not reported, only network, sleep, database and process calls are
    return read_config("app.json")


async def refresh_cache():
    time.sleep(5)
    requests.get(RATES_URL)


app.include_router(router)
