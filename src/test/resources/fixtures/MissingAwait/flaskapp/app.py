from flask import Flask

app = Flask(__name__)


async def audit(event):
    return event


@app.post("/flask/orders")
async def create_order():
    audit("order created")  # Noncompliant {{POST /flask/orders}}
    return {"ok": True}


@app.post("/flask/orders/awaited")
async def create_order_awaited():
    await audit("order created")
    return {"ok": True}


@app.post("/flask/orders/sync")
def create_order_sync():
    return {"ok": True}
