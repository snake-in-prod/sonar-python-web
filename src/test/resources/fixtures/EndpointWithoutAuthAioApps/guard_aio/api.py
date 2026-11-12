from aiohttp import web

routes = web.RouteTableDef()


@routes.delete("/items/{id}")
async def delete_item(request):
    await request.app["db"].delete_item(request.match_info["id"])
    return web.Response()


async def purge(request):
    await request.app["db"].purge()
    return web.Response()


def make_v2():
    # mounted in the guarded app: its middleware runs for these routes too
    v2 = web.Application()
    v2.router.add_delete("/items", purge)
    return v2
