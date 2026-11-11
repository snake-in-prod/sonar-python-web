from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/notes")
def notes():
    return "list"


@app.post("/notes")
def add_note():  # Noncompliant {{POST /notes}}
    return "added"


@app.delete("/notes/<int:nid>")
@login_required
def delete_note(nid):
    return "deleted"
