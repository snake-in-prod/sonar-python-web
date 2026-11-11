from .db import fetch


def items(request):
    name = request.GET["name"]
    return fetch("SELECT * FROM item WHERE name = '%s'" % name)
