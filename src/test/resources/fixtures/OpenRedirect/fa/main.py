from fastapi import FastAPI, Header, Request
from fastapi.responses import RedirectResponse

app = FastAPI()
ALLOWED = {"/", "/dashboard", "/settings"}


@app.get("/go")
def go(to: str):
    return RedirectResponse(to)  # Noncompliant {{parameter to of GET /go}}


@app.get("/continue")
def cont(target: str = "/"):
    if target not in ALLOWED:
        target = "/"
    return RedirectResponse(url=target)


@app.get("/lang")
def lang(code: str, referer: str = Header("/")):
    return RedirectResponse(referer)


@app.get("/after-login")
def after_login(request: Request):
    target = "/home?from=login"
    for key in request.query_params:
        target += f"&{key}={request.query_params[key]}"
    return RedirectResponse(target)


@app.get("/orders/{order_id}/pay")
def pay(order_id: str):
    return RedirectResponse(url="/orders/" + order_id + "/receipt")
