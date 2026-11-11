from django.http import JsonResponse
from django.views import View

from .models import Post


def counter(request, hits={}):  # Noncompliant {{Default dict of parameter hits of ANY /counter/ is one object shared by every request}} [[1]]
    hits[request.user.pk] = hits.get(request.user.pk, 0) + 1
    return JsonResponse(hits)


def options(request, defaults={"page": 1}):
    return JsonResponse({"page": request.GET.get("page", defaults["page"])})


def copied(request, cache={}):
    cache = dict(cache)
    cache["path"] = request.path
    return JsonResponse(cache)


def optional(request, seen=None):
    seen = seen or {}
    seen["x"] = 1
    return JsonResponse(seen)


def helper(rows, acc=[]):
    acc.append(rows)
    return acc


class ItemView(View):
    def post(self, request, items=[]):  # Noncompliant {{items of POST /items/}}
        items.append(request.POST["name"])
        return JsonResponse({"items": items})

    def get(self, request, order=("name",)):
        return JsonResponse({"order": list(order)})
