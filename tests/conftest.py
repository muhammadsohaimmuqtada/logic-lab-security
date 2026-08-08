import pytest
from pathlib import Path
from app import create_app
from app.config import TestingConfig


@pytest.fixture()
def app(tmp_path):
    class TestConfig(TestingConfig):
        DATABASE_PATH = Path(tmp_path) / "logiclab-test.db"
        SECURITY_LOG_PATH = Path(tmp_path) / "security.log"
    return create_app(TestConfig)


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client):
    with client.session_transaction() as sess:
        token = sess.get("_csrf_token")
        if not token:
            token = "test-csrf-token"
            sess["_csrf_token"] = token
        return token


def login(client, username, password="Password1!"):
    token = csrf(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=True,
    )


def logout(client):
    token = csrf(client)
    return client.post("/logout", data={"csrf_token": token}, follow_redirects=True)
