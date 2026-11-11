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
