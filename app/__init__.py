from flask import Flask

from app.config import Config
from app.extensions import db
from app.models import seed_db


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    from app.challenges.a01_idor import bp as a01_bp
    from app.challenges.a02_crypto import bp as a02_bp
    from app.challenges.a03_sqli import bp as a03_sqli_bp
    from app.challenges.a03_cmdi import bp as a03_cmdi_bp
    from app.challenges.a05_misconfig import bp as a05_bp
    from app.challenges.a07_authfail import bp as a07_bp
    from app.challenges.a08_deserialize import bp as a08_bp
    from app.challenges.a10_ssrf import bp as a10_bp

    app.register_blueprint(a01_bp)
    app.register_blueprint(a02_bp)
    app.register_blueprint(a03_sqli_bp)
    app.register_blueprint(a03_cmdi_bp)
    app.register_blueprint(a05_bp)
    app.register_blueprint(a07_bp)
    app.register_blueprint(a08_bp)
    app.register_blueprint(a10_bp)

    @app.get("/")
    def index():
        challenges = [
            {"id": "a01", "name": "Broken Access Control - IDOR", "path": "/a01"},
            {"id": "a02", "name": "Cryptographic Failures - Predictable Reset Token", "path": "/a02"},
            {"id": "a03-sqli", "name": "Injection - SQL Injection", "path": "/a03-sqli"},
            {"id": "a03-cmdi", "name": "Injection - Command Injection", "path": "/a03-cmdi"},
            {"id": "a05", "name": "Security Misconfiguration - Exposed Debug Endpoint", "path": "/a05"},
            {"id": "a07", "name": "Auth Failures - JWT alg=none", "path": "/a07"},
            {"id": "a08", "name": "Software/Data Integrity - Insecure Deserialization", "path": "/a08"},
            {"id": "a10", "name": "SSRF - Internal Admin Endpoint", "path": "/a10"},
        ]
        return {"project": "vulnlab", "challenges": challenges}

    with app.app_context():
        db.create_all()
        seed_db()

    return app
