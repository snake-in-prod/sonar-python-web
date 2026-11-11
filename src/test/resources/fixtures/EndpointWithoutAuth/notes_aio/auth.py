from aiohttp import web
from aiohttp_security import authorized_userid


async def require_user(request):
    user = await authorized_userid(request)
    if user is None:
        raise web.HTTPUnauthorized()
    return user
