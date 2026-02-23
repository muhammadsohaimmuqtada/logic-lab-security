"""
Security smoke tests for logic-lab-security.

Covers:
  - IDOR / horizontal access control
  - Visibility enforcement (private / org / public)
  - CSRF rejection
  - Owner-only mutation policy
  - Rate limiting (login throttle)
  - Input validation (visibility, username, password)
  - Admin access control
"""
import pytest
from app.app import app as flask_app
from tests.conftest import _csrf, register_and_login


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _create_service(client, name, visibility="private", description="test"):
    tok = _csrf(client)
    resp = client.post("/services/new", data={
        "name": name,
        "description": description,
        "visibility": visibility,
        "price_cents": "0",
        "csrf_token": tok,
    }, follow_redirects=True)
    return resp


def _get_last_service_id(client):
    """Fetch /services and return the first service id found in hrefs."""
    resp = client.get("/services")
    html = resp.data.decode()
    import re
    ids = re.findall(r'/services/(\d+)', html)
    return int(ids[0]) if ids else None


# ---------------------------------------------------------------------------
# 1. IDOR / Horizontal access
# ---------------------------------------------------------------------------

def test_idor_user_b_cannot_edit_user_a_service(client):
    """User B must get 403 when trying to edit User A's service."""
    register_and_login(client, "alice_idor", "Password1!", "OrgIDOR")
    _create_service(client, "AliceService")
    sid = _get_last_service_id(client)
    assert sid is not None

    # Log out alice, log in bob (different org)
    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "bob_idor", "Password1!", "OrgIDOR2")

    tok = _csrf(client)
    resp = client.post(f"/services/{sid}/edit", data={
        "name": "Hijacked",
        "description": "pwned",
        "csrf_token": tok,
    })
    assert resp.status_code == 403


def test_idor_user_b_cannot_delete_user_a_service(client):
    """User B must get 403 when trying to delete User A's service."""
    register_and_login(client, "alice_del", "Password1!", "OrgDel1")
    _create_service(client, "AliceServiceDel")
    sid = _get_last_service_id(client)
    assert sid is not None

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "bob_del", "Password1!", "OrgDel2")

    tok = _csrf(client)
    resp = client.post(f"/services/{sid}/delete", data={"csrf_token": tok})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 2. Visibility enforcement
# ---------------------------------------------------------------------------

def test_private_service_not_visible_to_other_user(client):
    """Private service is not returned in /services list for another user."""
    register_and_login(client, "priv_owner", "Password1!", "OrgPriv1")
    _create_service(client, "PrivateService", visibility="private")
    sid = _get_last_service_id(client)

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "priv_other", "Password1!", "OrgPriv2")

    resp = client.get("/services")
    html = resp.data.decode()
    assert "PrivateService" not in html

    # Direct access returns 404
    resp2 = client.get(f"/services/{sid}")
    assert resp2.status_code == 404


def test_org_service_visible_within_same_org(client):
    """Org-visibility service is visible to a user in the same org."""
    register_and_login(client, "org_owner", "Password1!", "SharedOrg")
    _create_service(client, "OrgService", visibility="org")

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "org_peer", "Password1!", "SharedOrg")

    resp = client.get("/services")
    html = resp.data.decode()
    assert "OrgService" in html


def test_org_service_not_visible_to_different_org(client):
    """Org-visibility service is NOT visible to a user in a different org."""
    register_and_login(client, "org_owner2", "Password1!", "OrgA_vis")
    _create_service(client, "OrgServiceA", visibility="org")

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "org_outsider", "Password1!", "OrgB_vis")

    resp = client.get("/services")
    html = resp.data.decode()
    assert "OrgServiceA" not in html


def test_public_service_visible_to_all(client):
    """Public service appears in /services list for any logged-in user."""
    register_and_login(client, "pub_owner", "Password1!", "OrgPub1")
    _create_service(client, "PublicService", visibility="public")

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "pub_viewer", "Password1!", "OrgPub2")

    resp = client.get("/services")
    html = resp.data.decode()
    assert "PublicService" in html


# ---------------------------------------------------------------------------
# 3. CSRF rejection
# ---------------------------------------------------------------------------

def test_post_without_csrf_returns_403(client):
    """POST without a CSRF token must return 403."""
    # Must be logged in (CSRF check happens after session check in practice,
    # but the blanket csrf_protect_all_posts fires before auth decorators)
    register_and_login(client, "csrf_user", "Password1!", "OrgCSRF")
    resp = client.post("/services/new", data={
        "name": "NoCSRF",
        "description": "test",
        "visibility": "private",
        "price_cents": "0",
        # no csrf_token field
    })
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 4. Owner-only mutations (same-org can VIEW but not MODIFY)
# ---------------------------------------------------------------------------

def test_same_org_peer_cannot_modify_org_service(client):
    """Same-org peer can view an org service but cannot edit or delete it."""
    register_and_login(client, "mod_owner", "Password1!", "OrgMod")
    _create_service(client, "OrgModService", visibility="org")
    sid = _get_last_service_id(client)

    tok = _csrf(client)
    client.post("/logout", data={"csrf_token": tok})
    register_and_login(client, "mod_peer", "Password1!", "OrgMod")

    # Peer CAN view
    resp_view = client.get(f"/services/{sid}")
    assert resp_view.status_code == 200

    # Peer CANNOT edit
    tok = _csrf(client)
    resp_edit = client.post(f"/services/{sid}/edit", data={
        "name": "Hijacked",
        "description": "nope",
        "csrf_token": tok,
    })
    assert resp_edit.status_code == 403


# ---------------------------------------------------------------------------
# 5. Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_after_max_failed_logins(client):
    """After LOGIN_FAIL_MAX failed attempts, login returns a throttle message."""
    from app.app import LOGIN_FAIL_MAX

    # Ensure a fresh CSRF token for each POST
    for _ in range(LOGIN_FAIL_MAX):
        tok = _csrf(client)
        client.post("/login", data={
            "username": "noexist_rl",
            "password": "wrongpassword",
            "csrf_token": tok,
        }, follow_redirects=True)

    tok = _csrf(client)
    resp = client.post("/login", data={
        "username": "noexist_rl",
        "password": "wrongpassword",
        "csrf_token": tok,
    }, follow_redirects=True)
    html = resp.data.decode()
    assert "Too many" in html


# ---------------------------------------------------------------------------
# 6. Input validation
# ---------------------------------------------------------------------------

def test_invalid_visibility_rejected(client):
    """Submitting an invalid visibility value must not create the service."""
    register_and_login(client, "val_user", "Password1!", "OrgVal")
    tok = _csrf(client)
    resp = client.post("/services/new", data={
        "name": "BadVis",
        "description": "test",
        "visibility": "superadmin",  # invalid
        "price_cents": "0",
        "csrf_token": tok,
    }, follow_redirects=True)
    html = resp.data.decode()
    assert "Invalid visibility" in html or "BadVis" not in html


def test_username_with_special_chars_rejected(client):
    """Username containing spaces/special chars must be rejected on register."""
    tok = _csrf(client)
    resp = client.post("/register", data={
        "username": "bad user!",
        "password": "Password1!",
        "org_name": "OrgSpec",
        "csrf_token": tok,
    }, follow_redirects=True)
    html = resp.data.decode()
    assert "error" in html.lower() or "invalid" in html.lower()


def test_too_short_password_rejected(client):
    """Passwords shorter than 6 characters must be rejected on register."""
    tok = _csrf(client)
    resp = client.post("/register", data={
        "username": "shortpwduser",
        "password": "abc",  # 3 chars
        "org_name": "OrgShort",
        "csrf_token": tok,
    }, follow_redirects=True)
    html = resp.data.decode()
    assert "error" in html.lower() or "short" in html.lower()


# ---------------------------------------------------------------------------
# 7. Admin access control
# ---------------------------------------------------------------------------

def test_non_admin_cannot_access_admin_routes(client):
    """Regular users must get 403 on /admin/* routes."""
    register_and_login(client, "plain_user", "Password1!", "OrgPlain")
    resp = client.get("/admin/security")
    assert resp.status_code == 403


def test_unauthenticated_user_redirected_from_admin(client):
    """Unauthenticated requests to /admin/* must redirect to login (not 200)."""
    # Start fresh session (not logged in)
    with flask_app.test_client() as c:
        resp = c.get("/admin/security", follow_redirects=False)
        assert resp.status_code in (302, 403)

