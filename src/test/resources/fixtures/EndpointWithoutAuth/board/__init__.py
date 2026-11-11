from flask import Flask

from .admin import bp as admin_bp
from .views import bp

app = Flask(__name__)
app.register_blueprint(bp)
app.register_blueprint(admin_bp, url_prefix="/admin")
