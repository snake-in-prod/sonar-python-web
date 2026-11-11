from fastapi import FastAPI

from shop.models import Order

app = FastAPI()


@app.get("/orders")
def list_orders():
    return [{"customer": o.customer.name} for o in Order.objects.filter(paid=True)]  # Noncompliant {{of GET /orders queries}}


@app.get("/orders/joined")
def list_joined():
    return [{"customer": o.customer.name} for o in Order.objects.select_related("customer").filter(paid=True)]


@app.get("/orders/{order_id}")
def one_order(order_id: int):
    o = Order.objects.get(pk=order_id)
    return {"customer": o.customer.name, "tags": [t.label for t in o.tags.all()]}
