from aiohttp import web
from aiohttp_security import check_authorized

from . import panel


@web.middleware
async def session_middleware(request, handler):
    # an aiohttp middleware that reads the token: it says nothing about the FastAPI apps
    request["token"] = request.headers.get("Authorization")
    return await handler(request)


async def delete_chat(request):
    await check_authorized(request)
    request.app["chats"].pop(request.match_info["id"])
    return web.Response()


def make_app():
    app = web.Application(middlewares=[session_middleware])
    app.router.add_delete("/chats/{id}", delete_chat)
    panel.mount(app)
    return app
