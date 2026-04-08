"""
Test fixtures for logic-lab-security.

Environment variables must be set BEFORE importing app.app because DB_PATH
and SECURITY_LOG are resolved at module-import time.
"""
import os
import tempfile
from pathlib import Path

# Point to temp files before any app import so module-level init_db() works
_tmp = tempfile.mkdtemp(prefix="logiclab_test_")
os.environ.setdefault("DATABASE_PATH", os.path.join(_tmp, "init.db"))
os.environ.setdefault("SECURITY_LOG_PATH", os.path.join(_tmp, "security.log"))
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdmin123!")

import pytest
import app.app as app_module
from app.app import app as flask_app


@pytest.fixture(autouse=True)
def _fast_password_hash(monkeypatch):
    """
    Replace werkzeug's password hashing with a fast method for tests.

    Production uses pbkdf2:sha256 with ~260 000 iterations (~100 ms per hash).
    In tests we use pbkdf2:sha256 with 1 iteration so the suite stays fast
    without sacrificing the hash/verify code-paths being exercised.

    We patch both the werkzeug module and the names imported directly into
    app.app so every call site is covered.
    """
    import werkzeug.security as _ws

    _original_generate = _ws.generate_password_hash

    def _fast_generate(password, method=None, salt_length=16):
        return _original_generate(password, method="pbkdf2:sha256:1", salt_length=salt_length)

    monkeypatch.setattr(_ws, "generate_password_hash", _fast_generate)
    # Patch the name as imported directly into app.app
    monkeypatch.setattr(app_module, "generate_password_hash", _fast_generate)
    # check_password_hash delegates to the stored method tag, so no patch needed.


@pytest.fixture()
def client(tmp_path):
    """Flask test client with a fresh SQLite DB per test (no cross-test pollution)."""
    db_path = tmp_path / "test.db"
    log_path = tmp_path / "security.log"

    # Patch module-level path globals and re-initialise schema
    old_db = app_module.DB_PATH
    old_log = app_module.SECURITY_LOG
    app_module.DB_PATH = db_path
    app_module.SECURITY_LOG = log_path
    app_module.init_db()

    flask_app.config["TESTING"] = True
    # Note: WTF_CSRF_ENABLED does not apply here — this app uses a manual CSRF mechanism,
    # not Flask-WTF. The csrf_protect_all_posts() before_request hook remains active.

    with flask_app.test_client() as c:
        yield c

    # Restore original paths
    app_module.DB_PATH = old_db
    app_module.SECURITY_LOG = old_log


def _csrf(client):
    """Return current CSRF token from the session (creates one if absent)."""
    import secrets
    with client.session_transaction() as sess:
        if "_csrf_token" not in sess:
            sess["_csrf_token"] = secrets.token_urlsafe(32)
        return sess["_csrf_token"]


def register_and_login(client, username, password, org_name):
    """Register a new user and log them in. Returns the login response."""
    tok = _csrf(client)
    client.post("/register", data={
        "username": username,
        "password": password,
        "org_name": org_name,
        "csrf_token": tok,
    }, follow_redirects=True)

    tok = _csrf(client)
    resp = client.post("/login", data={
        "username": username,
        "password": password,
        "csrf_token": tok,
    }, follow_redirects=True)
    return resp
