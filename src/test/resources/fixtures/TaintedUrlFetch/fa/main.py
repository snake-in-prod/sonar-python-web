import aiohttp
import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel

app = FastAPI()
REGION = "eu-west-1"


class Hook(BaseModel):
    url: str


@app.post("/hooks/test")
async def test_hook(hook: Hook):
    async with httpx.AsyncClient() as client:
        r = await client.post(hook.url, json={})  # Noncompliant {{parameter hook of POST /hooks/test}}
    return {"status": r.status_code}


@app.get("/fetch")
def fetch(url: str):
    return httpx.get(url).text  # Noncompliant {{parameter url of GET /fetch}}


@app.get("/mirror")
async def mirror(src: str):
    async with aiohttp.ClientSession() as s:
        async with s.get(src) as r:  # Noncompliant
            return await r.text()


@app.get("/items/{item_id}")
async def item(item_id: str):
    async with httpx.AsyncClient(base_url="https://inventory.internal") as client:
        r = await client.get(f"/items/{item_id}")
    return r.json()


@app.get("/rates")
def rates(currency: str):
    return httpx.get("https://rates.example/latest?base=" + currency).json()


@app.get("/page")
def page(n: int):
    return httpx.get(f"{n}").text


@app.get("/keys/{kid}")
def key(kid: str):
    return httpx.get(f"https://keys.{REGION}.example/{kid}").text


def get_admin_user():
    return None


@app.post("/admin/connections/verify")
def verify_connection(url: str, user=Depends(get_admin_user)):
    # administrators configure the URLs the server calls
    return httpx.get(url).status_code


def validate_url(url):
    if url.startswith("http://169.254."):
        raise ValueError(url)


@app.get("/unfurl")
def unfurl(url: str):
    validate_url(url)
    return httpx.get(url).text
