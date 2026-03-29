from flask import Flask

from .db import init_db
from .routes.pages import pages_bp
from .routes.api import api_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

    init_db()

    app.register_blueprint(pages_bp)
    app.register_blueprint(api_bp)

    return app
