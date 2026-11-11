import sqlite3

import pandas as pd
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
db = SQLAlchemy(app)


def connect():
    return sqlite3.connect("app.db")


@app.route("/users")
def users():
    q = request.args.get("q", "")
    rows = db.session.execute(text("SELECT * FROM users WHERE name = '%s'" % q))  # Noncompliant
    return jsonify([dict(r) for r in rows])


@app.route("/users", methods=["POST"])
def add_user():
    name = request.form["name"]
    conn = connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (name) VALUES ('" + name + "')")  # Noncompliant {{request.form of POST /users}}
    cur.execute("INSERT INTO users (name) VALUES (?)", (name,))
    conn.commit()
    return "", 201


@app.route("/stats/<region>")
def stats(region):
    return pd.read_sql(f"SELECT * FROM sales WHERE region = '{region}'", db.engine).to_json()  # Noncompliant


@app.route("/stats/<int:year>/total")
def total(year):
    return pd.read_sql(f"SELECT sum(amount) FROM sales WHERE year = {year}", db.engine).to_json()


@app.route("/orders")
def orders():
    order_id = request.args.get("id", "")
    if not order_id.isdigit():
        return "bad id", 400
    rows = db.session.execute(text(f"SELECT * FROM orders WHERE id = {order_id}"))
    return jsonify([dict(r) for r in rows])


@app.route("/lookup")
def lookup():
    key = request.args["key"]
    message = f"looking up {key} in the cache"
    app.logger.info(message)
    return jsonify(db.session.execute(text("SELECT * FROM cache WHERE k = :k"), {"k": key}).first())
