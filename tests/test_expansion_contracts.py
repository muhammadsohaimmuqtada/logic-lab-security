from tests.conftest import api_headers, csrf, expected_flag, login
from app.db import get_db


def test_ll18_direct_premium_feature_bypasses_plan(app, client):
    login(client, "student")
    r = client.get("/entitlements/premium-report")
    assert r.status_code == 200
    assert expected_flag(app, "LL18", "student").encode() in r.data


def test_ll19_bulk_invites_exceed_projected_seat_limit(app, client):
    login(client, "student")
    token = csrf(client)
    r = client.post("/entitlements/bulk-invite", data={"emails": "one@test.local,two@test.local", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL19", "student").encode() in r.data
    with app.app_context():
        gamma = get_db().execute("SELECT id FROM orgs WHERE name='GammaLabs'").fetchone()["id"]
        pending = get_db().execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (gamma,)).fetchone()["c"]
        assert pending >= 2


def test_ll20_trial_extension_is_replayable(app, client):
    login(client, "student")
    token = csrf(client)
    client.post("/entitlements/trial/extend", data={"days": "7", "csrf_token": token}, follow_redirects=True)
    token = csrf(client)
    r = client.post("/entitlements/trial/extend", data={"days": "7", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL20", "student").encode() in r.data


def test_ll21_api_notes_lack_object_authorization(app, client):
    login(client, "student")
    r = client.get("/api/v1/services/2/notes")
    assert r.status_code == 200
    assert r.get_json()["marker"] == expected_flag(app, "LL21", "student")


def test_ll22_api_allows_sensitive_property_update(app, client):
    login(client, "student")
    r = client.patch("/api/v1/services/2", json={"owner_user_id": 6, "status": "published"}, headers=api_headers(client))
    assert r.status_code == 200
    assert r.get_json()["marker"] == expected_flag(app, "LL22", "student")
    with app.app_context():
        row = get_db().execute("SELECT owner_user_id FROM services WHERE id=2").fetchone()
        assert row["owner_user_id"] == 6


def test_ll23_batch_only_authorizes_first_object(app, client):
    login(client, "student")
    r = client.post("/api/v1/services/batch-visibility", json={"ids": [5, 2], "visibility": "public"}, headers=api_headers(client))
    assert r.status_code == 200
    assert r.get_json()["marker"] == expected_flag(app, "LL23", "student")
    with app.app_context():
        foreign = get_db().execute("SELECT visibility FROM services WHERE id=2").fetchone()
        assert foreign["visibility"] == "public"


def test_ll24_partner_domain_suffix_is_not_identity(app, client):
    login(client, "student")
    r = client.post("/api/v1/partners/enroll", json={"email": "attacker@notalpha.local"}, headers=api_headers(client))
    assert r.status_code == 200
    assert r.get_json()["marker"] == expected_flag(app, "LL24", "student")


def test_ll25_alternate_export_path_bypasses_quota(app, client):
    login(client, "student")
    first = client.get("/entitlements/export")
    assert first.status_code == 200
    second = client.get("/api/v1/export")
    assert second.status_code == 200
    assert second.get_json()["marker"] == expected_flag(app, "LL25", "student")
