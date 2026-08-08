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


def test_fresh_recovery_defers_flag_until_learner_identity_exists(app, client):
    token = csrf(client)
    recovery = client.post(
        "/recover",
        data={"username": "carol", "org_name": "BetaOps", "new_password": "NewPassword1!", "csrf_token": token},
        follow_redirects=True,
    )
    assert recovery.status_code == 200
    assert b"FLAG{" not in recovery.data
    with client.session_transaction() as sess:
        assert sess.get("pending_ll16") is True
        assert not sess.get("lab_actor_id")

    response = login(client, "student")
    assert expected_flag(app, "LL16", "student").encode() in response.data
    assert expected_flag(app, "LL16", "carol").encode() not in response.data
    with client.session_transaction() as sess:
        assert sess.get("lab_actor_id") == 6
        assert "pending_ll16" not in sess


def test_invitation_is_bound_to_recipient_identity(client):
    login(client, "alice")
    token = csrf(client)
    response = client.post(
        "/org/accept",
        data={"token": "BETA-USED-INVITE", "csrf_token": token},
    )
    assert response.status_code == 403


def test_invite_acceptance_persists_tenant_and_refreshes_capability_context(app, client):
    login(client, "student")
    token = csrf(client)
    response = client.post(
        "/org/accept",
        data={"token": "BETA-USED-INVITE", "csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess["active_org_id"] == 2
        assert sess["capability_org_id"] == 2
    with app.app_context():
        active_org_id = get_db().execute("SELECT active_org_id FROM users WHERE username='student'").fetchone()["active_org_id"]
        assert active_org_id == 2
    context = client.get("/org/context-feed")
    assert expected_flag(app, "LL04", "student").encode() not in context.data


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


def test_entitlement_mutations_require_manager_role(client):
    login(client, "bob")
    page = client.get("/entitlements")
    assert page.status_code == 200
    assert b"Bulk seat invitations" not in page.data
    assert b"Request trial extension" not in page.data

    token = csrf(client)
    assert client.post("/entitlements/bulk-invite", data={"emails": "x@test.local", "csrf_token": token}).status_code == 403
    token = csrf(client)
    assert client.post("/entitlements/trial/extend", data={"days": "7", "csrf_token": token}).status_code == 403


def test_referral_reward_is_single_use_per_referred_account(app, client):
    login(client, "student")
    token = csrf(client)
    first = client.post(
        "/commerce/referral",
        data={"referral_code": "BOB10", "csrf_token": token},
        follow_redirects=True,
    )
    assert first.status_code == 200
    assert b"Referral reward applied" in first.data
    with app.app_context():
        db = get_db()
        student_after_first = db.execute("SELECT credits FROM users WHERE username='student'").fetchone()["credits"]
        bob_after_first = db.execute("SELECT credits FROM users WHERE username='bob'").fetchone()["credits"]

    token = csrf(client)
    second = client.post(
        "/commerce/referral",
        data={"referral_code": "ALICE10", "csrf_token": token},
        follow_redirects=True,
    )
    assert second.status_code == 200
    assert b"already been applied" in second.data
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT credits FROM users WHERE username='student'").fetchone()["credits"] == student_after_first
        assert db.execute("SELECT credits FROM users WHERE username='bob'").fetchone()["credits"] == bob_after_first
        assert db.execute("SELECT COUNT(*) AS c FROM referral_events WHERE referred_user_id=6").fetchone()["c"] == 1


def test_legacy_export_obeys_quota_while_preserving_ll02(app, client):
    login(client, "student")
    token = csrf(client)
    first = client.post("/services/export", data={"org_id": "2", "csrf_token": token})
    assert first.status_code == 200
    assert expected_flag(app, "LL02", "student").encode() in first.data
    token = csrf(client)
    second = client.post("/services/export", data={"org_id": "2", "csrf_token": token})
    assert second.status_code == 429


def test_quota_consuming_exports_are_not_get_requests(app, client):
    login(client, "student")
    assert client.get("/services/export").status_code == 405
    assert client.get("/entitlements/export").status_code == 405
    assert client.get("/api/v1/export").status_code == 405
    with app.app_context():
        used = get_db().execute(
            "SELECT COALESCE(SUM(quantity),0) AS c FROM feature_usage WHERE org_id=3 AND feature='tenant_export'"
        ).fetchone()["c"]
        assert used == 0


def test_quota_consuming_exports_require_csrf(client):
    login(client, "student")
    assert client.post("/services/export").status_code == 403
    assert client.post("/entitlements/export").status_code == 403
    assert client.post("/api/v1/export").status_code == 403


def test_api_sensitive_patch_rejects_invalid_domain_state(client):
    login(client, "student")
    assert client.patch("/api/v1/services/2", json={"status": "not-a-state"}, headers=api_headers(client)).status_code == 400
    assert client.patch("/api/v1/services/2", json={"visibility": "everywhere"}, headers=api_headers(client)).status_code == 400
    assert client.patch("/api/v1/services/2", json={"owner_user_id": 9999}, headers=api_headers(client)).status_code == 400
    assert client.patch("/api/v1/services/2", json={"org_id": 9999}, headers=api_headers(client)).status_code == 400
    assert client.patch("/api/v1/services/2", json={"org_id": True}, headers=api_headers(client)).status_code == 400
    assert client.patch("/api/v1/services/2", json={"owner_user_id": 2.5}, headers=api_headers(client)).status_code == 400


def test_api_rejects_non_object_and_ambiguous_batch_payloads(client):
    login(client, "student")
    headers = api_headers(client)
    assert client.patch("/api/v1/services/5", data="not-json", content_type="application/json", headers=headers).status_code == 400
    assert client.post("/api/v1/services/batch-visibility", json={"ids": [5], "visibility": ["public"]}, headers=api_headers(client)).status_code == 400
    assert client.post("/api/v1/services/batch-visibility", json={"ids": [5, 5], "visibility": "public"}, headers=api_headers(client)).status_code == 400
    assert client.post("/api/v1/services/batch-visibility", json={"ids": [5, 9999], "visibility": "public"}, headers=api_headers(client)).status_code == 400
    assert client.post("/api/v1/partners/enroll", json={"email": ["student@evilalpha.local"]}, headers=api_headers(client)).status_code == 400


def test_malformed_numeric_inputs_return_400(client):
    login(client, "student")
    assert client.get("/services/search?q=x&org_id=not-a-number").status_code == 400
    token = csrf(client)
    assert client.post("/commerce/checkout", data={"service_id": "bad", "csrf_token": token}).status_code == 400
    assert client.post("/api/v1/services/batch-visibility", json={"ids": ["bad"], "visibility": "public"}, headers=api_headers(client)).status_code == 400


def test_service_text_validation_is_consistent_and_description_can_be_cleared(app, client):
    login(client, "student")
    token = csrf(client)
    too_long = client.post(
        "/services/new",
        data={"name": "x" * 121, "description": "ok", "visibility": "private", "price_cents": "1", "csrf_token": token},
    )
    assert too_long.status_code == 400

    token = csrf(client)
    oversized_edit = client.post(
        "/services/5/edit",
        data={"name": "Starter Compliance Checklist", "description": "x" * 5001, "csrf_token": token},
    )
    assert oversized_edit.status_code == 400

    token = csrf(client)
    cleared = client.post(
        "/services/5/edit",
        data={"name": "Starter Compliance Checklist", "description": "", "csrf_token": token},
        follow_redirects=True,
    )
    assert cleared.status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT description FROM services WHERE id=5").fetchone()["description"] == ""


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
    assert not any(name.startswith("tests/") for name in names)
