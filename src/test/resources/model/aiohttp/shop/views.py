from aiohttp import web
from aiohttp_security import check_authorized, authorized_userid
from aiohttp_session import get_session

from .auth import owner

routes = web.RouteTableDef()


@routes.get("/items")
async def list_items(request):
    return web.json_response([])


@routes.post("/items")
async def create_item(request):
    await check_authorized(request)
    data = await request.post()
    await request.app["db"].insert(data["name"])
    return web.json_response({})


@routes.delete("/items/{id}")
async def delete_item(request):
    await request.app["db"].delete(request.match_info["id"])
    return web.Response()


@routes.put("/items/{id}")
async def rename_item(request):
    await owner(request)
    return web.Response()


@routes.get("/login")
async def login_page(request):
    # a login page sends a known user away: not a check
    if await authorized_userid(request) is not None:
        raise web.HTTPFound("/")
    return web.Response()


@routes.post("/cart")
async def add_to_cart(request):
    session = await get_session(request)
    if "user_id" not in session:
        raise web.HTTPFound("/login")
    return web.Response()


@routes.view("/orders")
class OrderView(web.View):
    async def get(self):
        return web.json_response([])

    async def post(self):
        await check_authorized(self.request)
        return web.json_response({})


async def ping(request):
    return web.Response(text="pong")


async def upload(request):
    return web.Response()


class ReportView(web.View):
    async def get(self):
        return web.Response()

    async def delete(self):
        return web.Response()


class Api:
    def register(self, app):
        app.add_routes([web.get("/api/status", self.status), web.post("/api/jobs", self.submit)])

    async def status(self, request):
        return web.json_response({})

    async def submit(self, request):
        return web.json_response({})
