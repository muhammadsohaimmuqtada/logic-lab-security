from flask import Flask, render_template
from .config import Config
from .db import init_db, close_db
from .security import csrf_token, csrf_protect, current_user


def create_app(config_object=None):
    app = Flask(__name__)
    app.config.from_object(config_object or Config)

    from .auth import auth_bp
    from .organizations import org_bp
    from .services import services_bp
    from .commerce import commerce_bp
    from .lab import lab_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(org_bp)
    app.register_blueprint(services_bp)
    app.register_blueprint(commerce_bp)
    app.register_blueprint(lab_bp)

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["current_user"] = current_user
    app.before_request(csrf_protect)
    app.teardown_appcontext(close_db)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        return response

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/health")
    def health():
        return {"status": "ok", "lab_mode": bool(app.config["LAB_MODE"])}

    with app.app_context():
        init_db()

    return app
