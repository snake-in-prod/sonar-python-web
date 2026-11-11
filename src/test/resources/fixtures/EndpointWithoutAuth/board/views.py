from flask import Blueprint, abort, request
from flask_login import current_user, login_required

from .db import Post, db

bp = Blueprint("board", __name__)


@bp.route("/posts/<int:pid>", methods=["DELETE"])
def remove_post(pid):  # Noncompliant {{DELETE /posts/<int:pid>}}
    db.session.delete(Post.query.get(pid))
    db.session.commit()


@bp.post("/posts")
def add_post():  # Noncompliant
    db.session.add(Post(body=request.form["body"]))
    db.session.commit()


@bp.post("/posts/<int:pid>/edit")
@login_required
def edit_post(pid):
    Post.query.get(pid).body = request.form["body"]
    db.session.commit()


@bp.post("/register")
def register():
    db.session.add(Post(body="hello"))
    db.session.commit()


@bp.post("/posts/<int:pid>/flag")
def flag_post(pid):
    if current_user.is_anonymous:
        abort(401)
    db.session.commit()


@bp.post("/search")
def search():
    return request.form["q"]


@bp.route("/posts/<int:pid>")
def show_post(pid):
    return Post.query.get(pid).body
