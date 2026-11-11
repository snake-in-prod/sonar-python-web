from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/students/{id}")
async def student(request):
    async with request.app["db"].acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM students WHERE id = " + request.match_info["id"])  # Noncompliant {{request.match_info of GET /students/{id}}}
            await cur.execute("SELECT * FROM students WHERE id = %s" % int(request.match_info["id"]))
            await cur.execute("SELECT * FROM students WHERE id = %s", (request.match_info["id"],))
    return web.Response()


@routes.post("/students")
async def add_student(request):
    data = await request.post()
    async with request.app["db"].acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("INSERT INTO students (name) VALUES ('%s')" % data["name"])  # Noncompliant
    return web.Response()


@routes.get("/search")
async def search(request):
    term = request.rel_url.query.get("q", "")
    rows = await request.app["db"].fetch(f"SELECT * FROM students WHERE name LIKE '%{term}%'")  # Noncompliant
    return web.json_response(rows)
