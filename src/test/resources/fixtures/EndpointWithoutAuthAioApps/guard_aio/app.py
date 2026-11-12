from aiohttp import web

from . import admin, api


@web.middleware
async def token_auth(request, handler):
    if request.headers.get("Authorization") != request.app["token"]:
        raise web.HTTPUnauthorized()
    return await handler(request)


async def clear_cache(request):  # Noncompliant {{DELETE /cache has no authentication: add await check_authorized(request) or an auth middleware, as other endpoints of this app do.}}
    request.app["cache"].clear()
    return web.Response()


def make_app():
    root = web.Application()
    guarded = web.Application(middlewares=[token_auth])
    guarded.add_routes(api.routes)
    guarded.add_subapp("/v2", api.make_v2())
    # the middleware of the /api sub-app runs neither for the root's routes nor for the /admin sibling
    root.add_subapp("/api", guarded)
    root.add_subapp("/admin", admin.make_admin())
    root.router.add_delete("/cache", clear_cache)
    return root
