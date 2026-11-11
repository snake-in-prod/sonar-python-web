from flask import Flask, render_template, render_template_string, request
from jinja2 import Environment
from markupsafe import Markup

app = Flask(__name__)
env = Environment(autoescape=True)


@app.route("/hi")
def hi():
    return render_template_string("Hi " + request.args["name"])  # Noncompliant {{request.args of GET /hi}}


@app.route("/note", methods=["POST"])
def note():
    body = request.form["body"]
    return render_template("note.html", body=Markup(body))  # Noncompliant


@app.route("/report")
def report():
    tpl = env.from_string(request.args["tpl"])  # Noncompliant
    return tpl.render()


@app.route("/hi/safe")
def hi_safe():
    return render_template_string("Hi {{ name }}", name=request.args["name"])


@app.route("/note/safe", methods=["POST"])
def note_safe():
    return render_template("note.html", body=Markup("<b>%s</b>") % request.form["body"])


@app.route("/note/escaped", methods=["POST"])
def note_escaped():
    return render_template("note.html", body=Markup(Markup.escape(request.form["body"])))


@app.route("/report/safe")
def report_safe():
    return env.from_string("<p>{{ v }}</p>").render(v=request.args["v"])
