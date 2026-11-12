import urllib
import urllib2
import urllib.request

import requests
from flask import Flask, request

app = Flask(__name__)
session = requests.Session()
recent_hosts = {}


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


@app.route("/classify")
def classify():
    # Python 2 apps: urllib.urlopen and urllib2.urlopen
    image = request.args.get("imageurl", "")
    data = urllib.urlopen(image).read()  # Noncompliant
    page = urllib2.urlopen(urllib2.Request(request.args["page"]))  # Noncompliant
    return urllib.urlopen("https://images.example/" + image).read() + data + page.read()


@app.route("/proxy/<host>")
def proxy(host):
    # the host must be a key of the configured map
    port = app.config["PROXY"].get(host, "")
    if not port:
        return "unknown host", 400
    return urllib2.urlopen("http://%s:%d/status" % (host, port)).read()


@app.route("/relay/<host>")
def relay(host):
    seen = recent_hosts.get(host)
    if not seen:
        recent_hosts[host] = 1
    return urllib2.urlopen("http://%s/status" % host).read()  # Noncompliant


class Feed:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout

    def fetch(self):
        return requests.get(self.url, timeout=self.timeout).text  # Noncompliant {{request.args of GET /feed}}


class DefaultFeed(Feed):
    def __init__(self):
        super().__init__(app.config["FEED_URL"])


@app.route("/feed")
def feed():
    f = Feed(request.args["url"])
    return f.fetch()


@app.route("/default-feed")
def default_feed():
    # the URL comes from the configuration; only the timeout from the caller
    Feed(app.config["FEED_URL"], timeout=int(request.args["t"])).fetch()
    return DefaultFeed().fetch()
