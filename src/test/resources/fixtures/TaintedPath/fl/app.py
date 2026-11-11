import codecs
import hashlib
import os

from flask import Flask, abort, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
Image = None
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


def clean_path(p):
    return os.path.normpath("/" + p).lstrip("/")


@app.get("/conf")
def conf():
    name = request.args["sensor"]
    if not name:
        return "missing", 400
    with open(os.path.join(UPLOADS, clean_path(name))) as fh:
        return fh.read()


@app.get("/reports/<jobid>")
def report(jobid):
    key = hashlib.md5(request.args["sensor"].encode()).hexdigest()
    with open(os.path.join(UPLOADS, "%s-%s" % (key, "report"))) as fh:
        return fh.read()


def assert_is_local_path(base, path):
    if not os.path.realpath(path).startswith(os.path.join(UPLOADS, base)):
        abort(400)


@app.get("/avatars/<path:path>")
def avatar(path):
    local = os.path.join(UPLOADS, "avatars", path)
    assert_is_local_path("avatars", local)
    return send_file(local)


@app.get("/image")
def image():
    image_id = request.args.get("id")
    img = Image.query.filter_by(image_id=image_id).first()
    if not img:
        abort(404)
    # the id names a stored image, not a path the caller made up
    return send_file(os.path.join(UPLOADS, "images", image_id + ".webp"))


@app.get("/poster")
def poster():
    video_id = request.args["id"]
    return send_file(os.path.join(UPLOADS, "derived", video_id, "poster.jpg"))  # Noncompliant


@app.post("/notes")
def notes():
    with codecs.open(request.form["file"], "w", encoding="utf-8") as fh:  # Noncompliant
        fh.write(request.form["content"])
    return "ok"
