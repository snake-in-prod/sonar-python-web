from aiohttp import web

from . import ops, tools, views

app = web.Application()
views.setup(app)
app.add_routes(ops.routes)
