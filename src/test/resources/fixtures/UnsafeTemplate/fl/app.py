from flask import Flask, render_template, render_template_string, request
from jinja2 import Environment
from markupsafe import Markup, escape

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


@app.route("/hello")
def hello():
    # a string a Flask view returns is an HTML page
    name = request.args.get("name", "you")
    return f"<h1>Hello {name}</h1>"  # Noncompliant {{request.args of GET /hello instead of returning it in HTML}}


@app.route("/board/<board_id>")
def board(board_id):
    return "<p>No board " + board_id + "</p>", 404  # Noncompliant


@app.route("/hello/safe")
def hello_safe():
    name = request.args.get("name", "you")
    page = request.args.get("page", 1, type=int)
    if not name.isalnum():
        return f"Bad name {name}", 400
    return f"<h1>Hello {escape(name)}, page {page}</h1>"


@app.route("/count")
def count():
    return f"Value must be < {request.args['max']}"
