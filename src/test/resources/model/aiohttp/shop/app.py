import os

from aiohttp import web

from . import views

base = os.environ.get("BASE", "")


def make_app():
    app = web.Application()
    app.add_routes(views.routes)
    app.router.add_get("/ping", views.ping)
    app.router.add_post(f"{base}/uploads/{{name}}", views.upload)
    app.router.add_route("*", "/reports/{id}", views.ReportView)
    app.router.add_view("/reports", views.ReportView)
    app.add_routes([web.post("/ping", views.ping)])

    async def health(request):
        return web.Response()

    app.router.add_route("GET", "/health", health)
    views.Api().register(app)
    return app
