from aiohttp import web
from aiohttp_security import authorized_userid


async def current_user(request):
    user_id = await authorized_userid(request)
    if user_id is None:
        raise web.HTTPUnauthorized()
    return user_id


async def owner(request):
    return await current_user(request)
