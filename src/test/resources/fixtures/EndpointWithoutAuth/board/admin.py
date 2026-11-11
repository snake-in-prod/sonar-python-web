from flask import Blueprint, abort
from flask_login import current_user

from .db import db

bp = Blueprint("admin", __name__)


@bp.before_request
def only_admins():
    if not current_user.is_admin:
        abort(403)


@bp.delete("/posts/<int:pid>")
def purge_post(pid):
    db.session.commit()
