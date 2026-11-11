import attr
import attrs
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/visit")
def visit(seen={}):  # Noncompliant
    seen[request.remote_addr] = True
    return jsonify(sorted(seen))


@app.post("/tally")
def tally(counts=[]):  # Noncompliant
    counts += [1]
    return jsonify(len(counts))


@app.get("/read")
def read(defaults={"limit": 10}):
    return jsonify(defaults)


@app.get("/fresh")
def fresh(acc=None):
    if acc is None:
        acc = []
    acc.append(1)
    return jsonify(acc)


@attrs.define
class Cart:
    items: list = []  # Noncompliant {{shared by every Cart; use attrs.field(factory=list)}}
    owners: list = attrs.field(factory=list)
    notes: dict = attrs.Factory(dict)


@attr.s
class Order:
    lines = attr.ib(default=[])  # Noncompliant {{shared by every Order; use factory=list}}
    tags = attr.ib([])  # Noncompliant
    flags = attr.ib(factory=dict)
    hint: list = []


@attr.s(auto_attribs=True)
class Basket:
    items: list = []  # Noncompliant


class Plain:
    items: list = []
