from flask import Flask
from app.config import Config
from app.db import init_db

def create_app():
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.config.from_object(Config)

    # Init MongoDB
    init_db(app)

    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.ui import ui_bp
    from app.routes.auth import auth_bp

    app.register_blueprint(auth_bp)                  # /login, /logout
    app.register_blueprint(ui_bp)                    # /
    app.register_blueprint(api_bp, url_prefix="/api")# /api/*

    return app
