import subprocess

from aiohttp import web

# never added to an app: no endpoint
routes = web.RouteTableDef()


@routes.post("/exec")
async def run(request):
    out = subprocess.check_output(request.query["cmd"], shell=True)
    return web.Response(body=out)
