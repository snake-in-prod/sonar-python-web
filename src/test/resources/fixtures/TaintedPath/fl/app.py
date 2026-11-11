import os

from flask import Flask, abort, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def _target(name):
    return os.path.join(UPLOADS, name)


@app.route("/files/<path:name>")
def download(name):
    return send_file(_target(name))  # Noncompliant {{parameter name of GET /files/<path:name>}}


@app.post("/remove")
def remove():
    os.remove(os.path.join(UPLOADS, request.form["name"]))  # Noncompliant
    return "removed"


@app.post("/save")
def save():
    f = request.files["doc"]
    f.save(os.path.join(UPLOADS, secure_filename(f.filename)))
    with open(os.path.join(UPLOADS, secure_filename(f.filename))) as fh:
        return fh.read()


@app.route("/notes")
def notes():
    name = request.args.get("name", "")
    if ".." in name:
        abort(400)
    with open(os.path.join(UPLOADS, name)) as fh:
        return fh.read()


@app.route("/static-copy")
def static_copy():
    path = os.path.realpath(os.path.join(UPLOADS, request.args["p"]))
    if os.path.commonpath([path, UPLOADS]) != UPLOADS:
        abort(400)
    return send_file(path)
