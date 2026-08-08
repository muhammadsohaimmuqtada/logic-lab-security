import hmac
import secrets
import time
from functools import wraps
from flask import request, session, redirect, url_for, abort
from .db import get_db

ROLE_ORDER = {"viewer": 10, "member": 20, "manager": 30, "owner": 40}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def csrf_protect():
    if request.method not in STATE_CHANGING_METHODS:
        return None
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf_token") or ""
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        abort(403)
    return None


def parse_int(value, *, default=None, minimum=None, maximum=None):
    if value in (None, ""):
        if default is None:
            abort(400)
        number = int(default)
    elif isinstance(value, bool):
        abort(400)
    elif isinstance(value, int):
        number = value
    elif isinstance(value, str):
        try:
            number = int(value.strip())
        except (TypeError, ValueError):
            abort(400)
    else:
        abort(400)
    if minimum is not None and number < minimum:
        abort(400)
    if maximum is not None and number > maximum:
        abort(400)
    return number


def client_ip():
    return request.remote_addr or "unknown"


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def current_org_id():
    return session.get("active_org_id")


def membership(user_id=None, org_id=None):
    user_id = user_id or session.get("user_id")
    org_id = org_id or current_org_id()
    if not user_id or not org_id:
        return None
    return get_db().execute("SELECT * FROM memberships WHERE user_id=? AND org_id=?", (user_id, org_id)).fetchone()


def role_at_least(required_role, *, org_id=None):
    m = membership(org_id=org_id)
    return bool(m and ROLE_ORDER.get(m["role"], 0) >= ROLE_ORDER[required_role])


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return fn(*args, **kwargs)
    return wrapped


def role_required(required_role):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if not role_at_least(required_role):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def audit(event, detail=""):
    db = get_db()
    db.execute(
        "INSERT INTO security_events(user_id,ip,event,detail,created_at) VALUES(?,?,?,?,?)",
        (session.get("user_id"), client_ip(), event, str(detail)[:500], int(time.time())),
    )
