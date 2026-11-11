import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hello", response_class=HTMLResponse)
def hello(name: str):
    return f"<h1>Hello {name}</h1>"  # Noncompliant {{parameter name of GET /hello}} [[1]]


@app.get("/bye")
def bye(name: str):
    return HTMLResponse(content=f"<p>Bye {name}</p>")  # Noncompliant


@app.get("/page", response_class=HTMLResponse)
def page(title: str):
    body = "<h1>" + title + "</h1>"
    return body  # Noncompliant


@app.get("/hello/safe", response_class=HTMLResponse)
def hello_safe(name: str):
    return f"<h1>Hello {html.escape(name)}</h1>"


@app.get("/count", response_class=HTMLResponse)
def count(n: int):
    return f"<p>{n} items</p>"


@app.get("/plain")
def plain(name: str):
    return f"Hello {name}"
