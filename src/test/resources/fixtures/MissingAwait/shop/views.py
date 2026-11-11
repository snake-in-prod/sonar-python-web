from django.http import JsonResponse

from .tasks import send_receipt


async def checkout(request):
    send_receipt(request.user.email)  # Noncompliant {{ANY /shop/checkout/}}
    return JsonResponse({"ok": True})


async def checkout_awaited(request):
    await send_receipt(request.user.email)
    return JsonResponse({"ok": True})
