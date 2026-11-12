import subprocess

from aiohttp import web

# added to the app in app.py: judged with the endpoints of views.py
routes = web.RouteTableDef()


@routes.post("/run")
async def run(request):  # Noncompliant {{POST /run has no authentication: add await check_authorized(request) or an auth middleware, as other endpoints of this app do.}}
    out = subprocess.check_output(request.query["cmd"], shell=True)
    return web.Response(body=out)


@routes.post("/stats")
async def stats(request):
    return web.json_response({"notes": len(request.app["db"])})
