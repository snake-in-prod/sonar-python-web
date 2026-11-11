import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/convert", methods=["POST"])
def convert():
    size = request.form["size"]
    cmd = "convert in.png -resize %s out.png" % size
    subprocess.run(cmd, shell=True)  # Noncompliant {{request.form of POST /convert}}
    subprocess.run(["convert", "in.png", "-resize", size, "out.png"], shell=True)
    return "ok"


@app.route("/whois/<domain>")
def whois(domain):
    return subprocess.getoutput("whois " + domain)  # Noncompliant


@app.route("/count/<int:n>")
def count(n):
    return subprocess.getoutput(f"seq {n}")


@app.route("/version")
def version():
    return subprocess.check_output("git rev-parse HEAD", shell=True)
