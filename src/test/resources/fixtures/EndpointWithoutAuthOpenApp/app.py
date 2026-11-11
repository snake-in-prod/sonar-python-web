from flask import Flask, request

app = Flask(__name__)
items = []


@app.post("/items")
def add_item():
    items.append(request.form["name"])
    db.session.add(request.form["name"])


@app.delete("/items/<int:i>")
def delete_item(i):
    items.pop(i)
