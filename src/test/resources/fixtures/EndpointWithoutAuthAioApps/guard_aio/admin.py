from aiohttp import web


async def drop_user(request):  # Noncompliant
    await request.app["db"].drop_user(request.match_info["id"])
    return web.Response()


def make_admin():
    admin = web.Application()
    admin.router.add_delete("/users/{id}", drop_user)
    return admin
