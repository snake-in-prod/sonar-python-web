from aiohttp import web
from aiohttp_security import check_authorized

from .auth import require_user

routes = web.RouteTableDef()


@routes.post("/notes")
async def create_note(request):
    await check_authorized(request)
    await request.app["db"].create_note(await request.json())
    return web.Response(status=201)


@routes.delete("/notes/{id}")
async def delete_note(request):  # Noncompliant {{DELETE /notes/{id} has no authentication: add await check_authorized(request) or an auth middleware, as other endpoints of this app do.}}
    await request.app["db"].delete_note(request.match_info["id"])
    return web.Response()


@routes.put("/notes/{id}")
async def update_note(request):
    await require_user(request)
    await request.app["db"].update_note(request.match_info["id"], await request.json())
    return web.Response()


@routes.post("/login")
async def login(request):
    await request.app["db"].save_login(await request.post())
    return web.Response()


@routes.post("/preview")
async def preview(request):
    return web.Response(text=(await request.post())["text"])


class Tags(web.View):
    async def get(self):
        return web.json_response([])

    async def post(self):  # Noncompliant
        await self.request.app["db"].add_tag(await self.request.json())
        return web.Response()


def setup(app):
    app.add_routes(routes)
    app.router.add_view("/tags", Tags)
