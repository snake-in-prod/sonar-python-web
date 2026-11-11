from flask import Flask, request

# a separate app of the same repository that has no authentication at all: it is not judged by the others
app = Flask(__name__)
items = []


@app.route("/upload", methods=["POST"])
def upload():
    items.append(request.form["item"])
    return "ok"


@app.route("/items/<int:i>", methods=["DELETE"])
def remove_item(i):
    items.pop(i)
    return "ok"
