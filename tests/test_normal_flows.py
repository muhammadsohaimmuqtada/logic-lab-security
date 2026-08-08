from tests.conftest import csrf, login


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json == {"status": "ok", "lab_mode": True}


def test_csrf_is_still_required(client):
    r = client.post("/login", data={"username": "alice", "password": "Password1!"})
    assert r.status_code == 403


def test_seeded_login_and_catalog(client):
    r = login(client, "alice")
    assert r.status_code == 200
    assert b"Internal Red-Team Playbook" in r.data


def test_wrong_password_rejected(client):
    token = csrf(client)
    r = client.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": token}, follow_redirects=True)
    assert b"Invalid credentials" in r.data


def test_direct_cross_tenant_service_view_is_blocked(client):
    login(client, "student")
    r = client.get("/services/1")
    assert r.status_code == 404


def test_new_service_happy_path(client):
    login(client, "student")
    token = csrf(client)
    r = client.post(
        "/services/new",
        data={"name": "Student Audit", "description": "lab service", "visibility": "org", "price_cents": "5000", "csrf_token": token},
        follow_redirects=True,
    )
    assert b"Student Audit" in r.data
