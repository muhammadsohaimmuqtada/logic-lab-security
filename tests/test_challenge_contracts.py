from concurrent.futures import ThreadPoolExecutor
from tests.conftest import csrf, expected_flag, login
from app.commerce import racy_redeem
from app.db import get_db


def register(client, username, email, org):
    token = csrf(client)
    return client.post("/register", data={"username": username, "email": email, "password": "Password1!", "org_name": org, "csrf_token": token}, follow_redirects=True)


def test_ll01_tenant_self_enrollment(app, client):
    register(client, "intruder01", "intruder01@test.local", "AlphaSec")
    login(client, "intruder01")
    r = client.get("/services/1")
    assert r.status_code == 200
    assert expected_flag(app, "LL01", "intruder01").encode() in r.data


def test_ll02_cross_tenant_export(app, client):
    login(client, "student")
    r = client.get("/services/export?org_id=2")
    assert expected_flag(app, "LL02", "student").encode() in r.data


def test_ll03_tenant_parameter_trust(app, client):
    login(client, "student")
    r = client.get("/services/search?q=Incident&org_id=2")
    assert expected_flag(app, "LL03", "student").encode() in r.data


def test_ll04_stale_tenant_context(app, client):
    login(client, "auditor")
    token = csrf(client)
    client.post("/org/switch/2", data={"csrf_token": token}, follow_redirects=True)
    r = client.get("/org/context-feed")
    assert expected_flag(app, "LL04", "auditor").encode() in r.data


def test_ll05_indirect_activity_leak(app, client):
    login(client, "student")
    r = client.get("/services/2/activity")
    assert expected_flag(app, "LL05", "student").encode() in r.data


def test_ll06_same_org_peer_can_take_ownership(app, client):
    login(client, "bob")
    token = csrf(client)
    r = client.post("/services/1/transfer", data={"new_owner_user_id": "2", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL06", "bob").encode() in r.data


def test_ll07_invite_role_override(app, client):
    register(client, "contractor07", "contractor07@example.local", "GammaLabs")
    login(client, "alice")
    token = csrf(client)
    client.post("/org/invite", data={"email": "contractor07@example.local", "role": "viewer", "csrf_token": token}, follow_redirects=True)
    with app.app_context():
        invite_token = get_db().execute("SELECT token FROM invitations WHERE email='contractor07@example.local' ORDER BY id DESC").fetchone()["token"]
    login(client, "contractor07")
    token = csrf(client)
    r = client.post("/org/accept", data={"token": invite_token, "role": "owner", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL07", "contractor07").encode() in r.data


def test_ll08_revoked_or_used_invite_still_accepted(app, client):
    register(client, "analyst08", "analyst@example.local", "GammaLabs")
    login(client, "analyst08")
    token = csrf(client)
    r = client.post("/org/accept", data={"token": "BETA-USED-INVITE", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL08", "analyst08").encode() in r.data


def test_ll09_state_machine_skip(app, client):
    login(client, "bob")
    token = csrf(client)
    r = client.post("/services/3/transition", data={"status": "published", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL09", "bob").encode() in r.data


def test_ll10_edit_does_not_invalidate_approval(app, client):
    login(client, "dave")
    token = csrf(client)
    r = client.post("/services/4/edit", data={"name": "Changed After Approval", "description": "new content", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL10", "dave").encode() in r.data


def test_ll11_client_controls_checkout_price(app, client):
    login(client, "alice")
    token = csrf(client)
    r = client.post("/commerce/checkout", data={"service_id": "1", "price_cents": "1", "coupon_codes": "", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL11", "alice").encode() in r.data


def test_ll12_promotions_stack_and_are_not_consumed(app, client):
    login(client, "alice")
    token = csrf(client)
    r = client.post("/commerce/checkout", data={"service_id": "1", "price_cents": "12000", "coupon_codes": "ONCE50,STACK20", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL12", "alice").encode() in r.data
    token = csrf(client)
    r2 = client.post("/commerce/checkout", data={"service_id": "1", "price_cents": "12000", "coupon_codes": "ONCE50", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL12", "alice").encode() in r2.data


def test_ll13_self_referral_creates_value(app, client):
    login(client, "student")
    token = csrf(client)
    r = client.post("/commerce/referral", data={"referral_code": "STUDENT10", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL13", "student").encode() in r.data


def test_ll14_refund_is_replayable(app, client):
    login(client, "bob")
    token = csrf(client)
    client.post("/commerce/orders/1/refund", data={"csrf_token": token}, follow_redirects=True)
    token = csrf(client)
    r = client.post("/commerce/orders/1/refund", data={"csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL14", "bob").encode() in r.data


def test_ll15_owner_can_approve_own_work(app, client):
    login(client, "alice")
    token = csrf(client)
    r = client.post("/services/1/approve", data={"csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL15", "alice").encode() in r.data


def test_ll16_org_knowledge_is_enough_for_recovery(app, client):
    login(client, "student")
    token = csrf(client)
    r = client.post("/recover", data={"username": "carol", "org_name": "BetaOps", "new_password": "NewPassword1!", "csrf_token": token}, follow_redirects=True)
    assert expected_flag(app, "LL16", "student").encode() in r.data


def test_ll17_concurrent_redemption_exceeds_recorded_usage(app):
    def worker():
        with app.app_context():
            return racy_redeem("RACE1", 6, delay=0.25)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: worker(), range(2)))
    assert results == [True, True]
    with app.app_context():
        db = get_db()
        coupon = db.execute("SELECT * FROM coupons WHERE code='RACE1'").fetchone()
        receipts = db.execute("SELECT COUNT(*) AS c FROM coupon_redemptions WHERE code='RACE1'").fetchone()["c"]
        assert coupon["used_count"] == 1
        assert receipts == 2
        assert receipts > coupon["used_count"]
