from urllib.parse import urlparse

from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/login", methods=["GET", "POST"])
def login():
    next_page = request.args.get("next")
    if not next_page or urlparse(next_page).netloc != "":
        next_page = url_for("index")
    return redirect(next_page)


@app.route("/out")
def out():
    return redirect(request.args.get("url") or url_for("index"))  # Noncompliant


@app.route("/jump")
def jump():
    dest = request.values.get("dest", "/")
    if not dest.startswith("/"):
        dest = "/"
    return redirect(dest)  # Noncompliant: a target starting with two slashes passes


@app.route("/hop")
def hop():
    dest = request.values.get("dest", "/")
    if not dest.startswith("/") or dest.startswith("//"):
        dest = "/"
    return redirect(dest)


@app.route("/search")
def search():
    return redirect(url_for("results", q=request.args.get("q")))


@app.route("/page")
def page():
    return redirect("/docs/" + request.args.get("p", ""))


@app.route("/proxy/<channel>/<file>")
def proxy(channel, file):
    # the server's own scheme and host come first, then a "/": the channel cannot move the target elsewhere
    protocol = app.config["PROTOCOL"]
    return redirect(protocol + app.config["PROXY_HOST"] + "/live/" + channel + "/" + file)


@app.route("/edge/<endpoint>")
def edge(endpoint):
    return redirect("/" + app.config["EDGE"] + "/" + endpoint)


def upload_root_url():
    return app.config["UPLOAD_ROOT"]


@app.route("/avatars/<path:path>")
def avatar(path):
    return redirect(upload_root_url() + path)


@app.route("/bounce")
def bounce():
    return redirect(app.config["PREFIX"] + request.args.get("to", ""))  # Noncompliant
