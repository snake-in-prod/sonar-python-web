from flask import Flask

from .admin import admin_bp
from .views import main


def create_app():
    app = Flask(__name__)
    app.register_blueprint(main)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    return app
