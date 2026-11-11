import urllib.request

import requests
from flask import Flask, request

app = Flask(__name__)
session = requests.Session()


def download(url):
    with urllib.request.urlopen(url) as resp:  # Noncompliant {{request.args of GET /import}}
        return resp.read()


@app.route("/import")
def import_feed():
    return download(request.args["feed"])


@app.route("/avatar")
def avatar():
    src = request.args.get("src", "")
    if not src.startswith("https://cdn.example/"):
        return "bad", 400
    return requests.get(src).content


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return session.get("https://search.example/api", params={"q": q}).text
