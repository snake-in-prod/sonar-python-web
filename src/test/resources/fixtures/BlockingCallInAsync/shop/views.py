import requests
from asgiref.sync import sync_to_async
from django.http import JsonResponse
from django.views import View

from .models import Item

PRICES_URL = "https://prices.example/latest"


async def item_detail(request, pk):
    item = Item.objects.get(pk=pk)  # Noncompliant {{Item.objects.get() blocks the event loop of async ANY /shop/items/<int:pk>/; use aget() or sync_to_async}}
    return JsonResponse({"name": item.name})


async def item_list(request):
    names = []
    for item in Item.objects.filter(name__startswith="a"):  # Noncompliant {{async for}}
        names.append(item.name)
    return JsonResponse({"names": names})


async def item_total(request):
    return JsonResponse({"total": Item.objects.filter(name__startswith="a").count()})  # Noncompliant {{Item.objects...count()}}


class PriceView(View):
    async def get(self, request):
        return JsonResponse(requests.get(PRICES_URL).json())  # Noncompliant {{async GET /shop/prices/}}


# compliant near misses


async def item_detail_async(request, pk):
    item = await Item.objects.aget(pk=pk)
    return JsonResponse({"name": item.name})


async def item_list_async(request):
    names = [item.name async for item in Item.objects.filter(name__startswith="a")]
    async for item in Item.objects.all():
        names.append(item.name)
    return JsonResponse({"names": names})


async def item_list_wrapped(request):
    names = await sync_to_async(lambda: [i.name for i in Item.objects.all()])()
    count = await sync_to_async(Item.objects.count)()
    return JsonResponse({"names": names, "count": count})


def item_detail_sync(request, pk):
    item = Item.objects.get(pk=pk)
    return JsonResponse({"name": item.name, "price": requests.get(PRICES_URL).json()})


async def item_lazy(request):
    queryset = Item.objects.filter(name__startswith="a")
    return JsonResponse({"n": await queryset.acount()})


async def item_by_reference(request, pk):
    item = await sync_to_async(Item.objects.get)(pk=pk)
    return JsonResponse({"name": item.name})
