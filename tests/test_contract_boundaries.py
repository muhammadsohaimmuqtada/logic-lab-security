from pathlib import Path
from tests.conftest import api_headers, csrf, expected_flag, login
from app.config import _persistent_secret
from app.db import get_db


def register(client, username, email, org):
    token = csrf(client)
    return client.post("/register", data={"username": username, "email": email, "password": "Password1!", "org_name": org, "csrf_token": token}, follow_redirects=True)


def test_normal_authorized_views_do_not_leak_resource_markers(app, client):
    login(client, "bob")
    r1 = client.get("/services/1")
    assert expected_flag(app, "LL01", "bob").encode() not in r1.data
    r3 = client.get("/services/3")
    assert expected_flag(app, "LL09", "bob").encode() not in r3.data

    login(client, "dave")
    r4 = client.get("/services/4")
    assert expected_flag(app, "LL10", "dave").encode() not in r4.data

    login(client, "carol")
    export = client.get("/services/export?org_id=2")
    assert export.status_code == 200
    assert expected_flag(app, "LL02", "carol").encode() not in export.data


def test_single_legitimate_coupon_does_not_solve_ll12(app, client):
    login(client, "alice")
    token = csrf(client)
    first = client.post("/commerce/checkout", data={"service_id": "1", "price_cents": "12000", "coupon_codes": "ONCE50", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL12", "alice").encode() not in first.data

    token = csrf(client)
    second = client.post("/commerce/checkout", data={"service_id": "1", "price_cents": "12000", "coupon_codes": "ONCE50", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL12", "alice").encode() in second.data


def test_invitation_is_bound_to_recipient(app, client):
    login(client, "student")
    token = csrf(client)
    r = client.post("/org/accept", data={"token": "BETA-USED-INVITE", "csrf_token": token})
    assert r.status_code == 403


def test_invitation_tokens_hidden_from_non_managers(client):
    login(client, "bob")
    member_view = client.get("/org")
    assert b"ALPHA-ARCHIVED-INVITE" not in member_view.data

    login(client, "dave")
    manager_view = client.get("/org")
    assert b"BETA-USED-INVITE" in manager_view.data


def test_normal_invite_path_enforces_projected_seat_limit(app, client):
    login(client, "student")
    token = csrf(client)
    first = client.post("/org/invite", data={"email": "one@test.local", "role": "member", "csrf_token": token}, follow_redirects=True)
    assert b"Invitation created" in first.data

    token = csrf(client)
    second = client.post("/org/invite", data={"email": "two@test.local", "role": "member", "csrf_token": token}, follow_redirects=True)
    assert b"No seat capacity" in second.data
    with app.app_context():
        gamma = get_db().execute("SELECT id FROM orgs WHERE name='GammaLabs'").fetchone()["id"]
        pending = get_db().execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (gamma,)).fetchone()["c"]
        assert pending == 1


def test_legacy_export_uses_same_quota_budget(client):
    login(client, "student")
    first = client.get("/services/export?org_id=2")
    assert first.status_code == 200
    second = client.get("/services/export?org_id=2")
    assert second.status_code == 429


def test_recovery_marker_belongs_to_authenticated_learner(app, client):
    login(client, "student")
    token = csrf(client)
    r = client.post("/recover", data={"username": "carol", "org_name": "BetaOps", "new_password": "AnotherPassword1!", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL16", "student").encode() in r.data
    assert expected_flag(app, "LL16", "carol").encode() not in r.data


def test_management_controls_are_not_advertised_to_non_owner(client):
    login(client, "bob")
    r = client.get("/services/1")
    assert b"Transfer ownership" not in r.data
    assert b"Save content" not in r.data


def test_malformed_integer_inputs_are_controlled_errors(client):
    login(client, "student")
    assert client.get("/services/search?q=x&org_id=not-an-int").status_code == 400

    token = csrf(client)
    assert client.post("/commerce/checkout", data={"service_id": "bad", "csrf_token": token}).status_code == 400

    assert client.post("/api/v1/services/batch-visibility", json={"ids": ["bad"], "visibility": "public"}, headers=api_headers(client)).status_code == 400


def test_persistent_secret_is_random_and_stable(tmp_path, monkeypatch):
    env_name = "LOGICLAB_TEST_EPHEMERAL_SECRET"
    monkeypatch.delenv(env_name, raising=False)
    path = Path(tmp_path) / "secret"
    first = _persistent_secret(env_name, path)
    second = _persistent_secret(env_name, path)
    assert first == second
    assert len(first) == 64
    assert path.read_text(encoding="utf-8") == first
    assert path.stat().st_mode & 0o777 == 0o600
