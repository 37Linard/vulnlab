import os
import tempfile
import threading

import pytest
from werkzeug.serving import make_server

from app import create_app
from app.config import Config
from app.extensions import db


@pytest.fixture(scope="session")
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    class TestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"

    flask_app = create_app(TestConfig)
    yield flask_app

    with flask_app.app_context():
        db.engine.dispose()
    os.remove(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def live_server(app):
    """Real TCP server, needed for the SSRF challenge (server must make an actual HTTP call)."""
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)
