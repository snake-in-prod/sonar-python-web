from flask import Blueprint, request
from flask_login import login_required

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return "hello"


@main.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    return request.form.get("text", "")


@main.post("/notes/<int:note_id>/delete")
def delete_note(note_id):
    return str(note_id)


@main.route("/files/<path:name>")
def files(name):
    return name
