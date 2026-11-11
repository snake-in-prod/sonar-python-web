from django.db.models import prefetch_related_objects
from django.http import JsonResponse

from . import models
from .models import Customer, Invoice, Order


def order_names(request):
    out = []
    for o in Order.objects.all():
        out.append(o.customer.name)  # Noncompliant {{Each Order of this loop of ANY /orders/ queries its "customer" again; add select_related("customer")}} [[1]]
        out.append(o.customer.pk)
    return JsonResponse(out, safe=False)


def order_tags(request):
    rows = []
    for o in Order.objects.filter(paid=True).order_by("-id")[:20]:
        rows.append([t.label for t in o.tags.all()])  # Noncompliant {{prefetch_related("tags")}}
        o.tags.add(1)
    return JsonResponse(rows, safe=False)


def emails(request):
    return JsonResponse([o.customer.name for o in models.Order.objects.exclude(paid=False)], safe=False)  # Noncompliant


def item_counts(request):
    orders = Order.objects.filter(paid=True)
    return JsonResponse({o.pk: o.items.count() for o in orders})  # Noncompliant {{"items"}}


def owners_twice(request):
    orders = Order.objects.filter(paid=True)
    first = [o.customer for o in orders]  # Noncompliant
    # the queryset and each order's customer are cached by the first loop
    second = [o.customer for o in orders]
    return JsonResponse({"n": len(first) + len(second)})


def customer_orders(request):
    data = {}
    for c in Customer.objects.all():
        data[c.pk] = c.order_set.count()  # Noncompliant
        data[c.name] = c.profile.pk  # Noncompliant {{select_related("profile")}}
    return JsonResponse(data)


def with_joins(request):
    out = []
    for o in Order.objects.select_related("customer").prefetch_related("tags"):
        out.append((o.customer.name, [t.label for t in o.tags.all()]))
    return JsonResponse(out, safe=False)


def ids_only(request):
    return JsonResponse([o.customer_id for o in Order.objects.all()], safe=False)


def as_values(request):
    return JsonResponse([o["customer"] for o in Order.objects.values("customer")], safe=False)


def invoices(request):
    return JsonResponse([i.customer.name for i in Invoice.objects.all()], safe=False)


def joined_later(request):
    qs = Order.objects.all()
    qs = qs.select_related("customer")
    return JsonResponse([o.customer.name for o in qs], safe=False)


def prefetched(request):
    orders = Order.objects.all()
    prefetch_related_objects(orders, "tags")
    return JsonResponse([o.tags.count() for o in orders], safe=False)


def reassign(request):
    new = Customer.objects.first()
    for o in Order.objects.all():
        o.customer = new
        o.customer.save()
        o.tags.filter(label="x").delete()
    return JsonResponse({})


def from_list(request, orders):
    return JsonResponse([o.customer.name for o in orders], safe=False)


def custom_method(request):
    return JsonResponse([o.customer.name for o in Order.objects.paid_only()], safe=False)


def inherited_fk(request):
    return JsonResponse([o.created_by.name for o in Order.objects.all()], safe=False)  # Noncompliant
