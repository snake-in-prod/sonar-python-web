from django.db import connection
from django.http import JsonResponse

from .db import fetch, fetch_with
from .models import Item
from .schema import schema

ORDER_COLUMNS = {"name": "name", "price": "price"}
ALLOWED_DIRECTIONS = {"asc", "desc"}


def search(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM shop_item WHERE name = '{q}'")  # Noncompliant {{Pass request.GET of ANY /search/ to cursor.execute() as a query parameter}}
        cursor.execute("SELECT * FROM shop_item WHERE name = %s", [q])
        return JsonResponse({"rows": cursor.fetchall()})


def by_name(request):
    name = request.POST["name"]
    rows = Item.objects.raw("SELECT * FROM shop_item WHERE name = '%s'" % name)  # Noncompliant
    same = Item.objects.raw("SELECT * FROM shop_item WHERE name = %s", [name])
    return JsonResponse({"n": len(list(rows)) + len(list(same))})


def filtered(request):
    owner = request.GET["owner"]
    rows = Item.objects.extra(where=["owner = '" + owner + "'"])  # Noncompliant
    fine = Item.objects.extra(where=["owner = %s"], params=[owner])
    return JsonResponse({"n": rows.count() + fine.count()})


def report(request):
    year = request.GET["year"]
    sql = "SELECT * FROM shop_sale WHERE year = '{}'".format(year)
    return JsonResponse({"rows": fetch(sql)})


def item(request, item_id):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM shop_item WHERE id = {item_id}")
        cursor.execute(f"SELECT * FROM shop_item WHERE id = {int(request.GET['other'])}")
        return JsonResponse({"row": cursor.fetchone()})


def sorted_items(request):
    column = ORDER_COLUMNS[request.GET.get("sort", "name")]
    direction = request.GET.get("dir", "asc")
    if direction not in ALLOWED_DIRECTIONS:
        direction = "asc"
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM shop_item ORDER BY {column} {direction}")
        return JsonResponse({"rows": cursor.fetchall()})


def safe_search(request):
    terms = request.GET.getlist("t")
    clauses = []
    params = []
    for t in terms:
        clauses.append("name LIKE %s")
        params.append(f"%{t}%")
    sql = "SELECT * FROM shop_item WHERE " + " OR ".join(clauses)
    return JsonResponse({"rows": fetch_with(sql, params)})


def graph(request):
    result = schema.execute(request.POST["query"])
    return JsonResponse({"data": result.data})


def name_check(request):
    first = request.POST["first"]
    last = request.POST["last"]
    with connection.cursor() as cursor:
        # two inputs, one sink: one issue
        cursor.execute("SELECT id FROM shop_person WHERE first = '" + first + "' AND last = '" + last + "'")  # Noncompliant
