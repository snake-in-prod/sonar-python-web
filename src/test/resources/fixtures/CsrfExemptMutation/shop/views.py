import hmac

from flask import request
from flask_login import current_user, login_required

from . import app, csrf
from .db import db


@app.post("/cart/checkout")
@csrf.exempt
@login_required
def checkout():  # Noncompliant {{POST /cart/checkout}}
    db.session.commit()


@app.post("/hooks/paypal")
@csrf.exempt
def paypal_hook():
    if not hmac.compare_digest(request.headers["X-Sig"], "x"):
        return None
    db.session.commit()


@app.post("/cart/clear")
@login_required
def clear_cart():
    db.session.commit()
