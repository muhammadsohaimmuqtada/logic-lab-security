import zipfile

from app import config as config_module
from app.db import get_db
from scripts import build_learner_bundle
from tests.conftest import api_headers, csrf, expected_flag, login


def test_single_coupon_does_not_award_promotion_abuse(app, client):
    login(client, "alice")
    token = csrf(client)
    response = client.post(
        "/commerce/checkout",
        data={"service_id": "1", "price_cents": "12000", "coupon_codes": "ONCE50", "csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert expected_flag(app, "LL12", "alice").encode() not in response.data


def test_recovery_flag_remains_bound_to_original_lab_actor(app, client):
    login(client, "student")
    token = csrf(client)
    response = client.post(
        "/recover",
        data={"username": "carol", "org_name": "BetaOps", "new_password": "NewPassword1!", "csrf_token": token},
        follow_redirects=True,
    )
    assert expected_flag(app, "LL16", "student").encode() in response.data
    assert expected_flag(app, "LL16", "carol").encode() not in response.data


def test_invitation_is_bound_to_recipient_identity(client):
    login(client, "alice")
    token = csrf(client)
    response = client.post(
        "/org/accept",
        data={"token": "BETA-USED-INVITE", "csrf_token": token},
    )
    assert response.status_code == 403


def test_standard_invites_respect_subscription_capacity(app, client):
    login(client, "student")
    token = csrf(client)
    first = client.post(
        "/org/invite",
        data={"email": "first@example.local", "role": "member", "csrf_token": token},
        follow_redirects=True,
    )
    assert first.status_code == 200
    token = csrf(client)
    second = client.post(
        "/org/invite",
        data={"email": "second@example.local", "role": "member", "csrf_token": token},
        follow_redirects=True,
    )
    assert b"Seat limit reached" in second.data
    with app.app_context():
        gamma = get_db().execute("SELECT id FROM orgs WHERE name='GammaLabs'").fetchone()["id"]
        pending = get_db().execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (gamma,)).fetchone()["c"]
        assert pending == 1


def test_legacy_export_obeys_quota_while_preserving_ll02(app, client):
    login(client, "student")
    first = client.get("/services/export?org_id=2")
    assert first.status_code == 200
    assert expected_flag(app, "LL02", "student").encode() in first.data
    second = client.get("/services/export?org_id=2")
    assert second.status_code == 429


def test_malformed_numeric_inputs_return_400(client):
    login(client, "student")
    assert client.get("/services/search?q=x&org_id=not-a-number").status_code == 400
    token = csrf(client)
    assert client.post("/commerce/checkout", data={"service_id": "bad", "csrf_token": token}).status_code == 400
    assert client.post("/api/v1/services/batch-visibility", json={"ids": ["bad"], "visibility": "public"}, headers=api_headers(client)).status_code == 400


def test_non_owner_ui_does_not_disclose_transfer_action(client):
    login(client, "bob")
    response = client.get("/services/1")
    assert response.status_code == 200
    assert b"Transfer ownership" not in response.data


def test_generated_runtime_secrets_are_distinct_and_persistent(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "INSTANCE_DIR", tmp_path)
    monkeypatch.delenv("TEST_FLASK_SECRET", raising=False)
    monkeypatch.delenv("TEST_FLAG_SECRET", raising=False)
    flask_secret = config_module._load_or_create_secret("TEST_FLASK_SECRET", ".test-flask-secret")
    flag_secret = config_module._load_or_create_secret("TEST_FLAG_SECRET", ".test-flag-secret")
    assert flask_secret
    assert flag_secret
    assert flask_secret != flag_secret
    assert config_module._load_or_create_secret("TEST_FLASK_SECRET", ".test-flask-secret") == flask_secret
    assert config_module._load_or_create_secret("TEST_FLAG_SECRET", ".test-flag-secret") == flag_secret


def test_learner_bundle_excludes_instructor_spoilers(tmp_path, monkeypatch):
    out = tmp_path / "logic-lab-learner.zip"
    monkeypatch.setattr(build_learner_bundle, "OUT", out)
    build_learner_bundle.main()
    assert out.exists()
    with zipfile.ZipFile(out) as archive:
        names = set(archive.namelist())
    assert "README.md" in names
    assert "docs/INSTRUCTOR_GUIDE.md" not in names
    assert "challenges/manifest.yml" not in names
    assert "tests/test_challenge_contracts.py" not in names
    assert "tests/test_expansion_contracts.py" not in names
