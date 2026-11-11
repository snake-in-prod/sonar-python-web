from flask import Blueprint, abort, session

admin_bp = Blueprint("admin", __name__, url_prefix="/backoffice")


@admin_bp.before_request
def check_admin():
    if not session.get("is_admin"):
        abort(403)


@admin_bp.route("/users/<int:uid>", methods=["DELETE"])
def drop_user(uid):
    return str(uid)
