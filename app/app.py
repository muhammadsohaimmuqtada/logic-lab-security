import hmac
import logging
import sqlite3
import secrets
import time
from pathlib import Path
from functools import wraps
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash

BASE_DIR = Path(__file__).resolve().parent.parent
import os
DB_PATH = Path(os.environ.get("DATABASE_PATH", "/var/lib/logic-lab/logiclab.db"))
SECURITY_LOG = Path(os.environ.get("SECURITY_LOG_PATH", "/var/log/logic-lab/security.log"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64KB request cap
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-lab-fallback")


app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
# SESSION_COOKIE_SECURE should be True only when you move to HTTPS
app.config.setdefault("SESSION_COOKIE_SECURE", False)

# --------------- Python logging ---------------
_logger = logging.getLogger("logic_lab.security")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _logger.addHandler(_handler)
_logger.setLevel(logging.INFO)



# ---------------- CSRF (manual) ----------------
def csrf_token():
    # One token per session; rotates on new session
    tok = session.get("_csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf_token"] = tok
    return tok

def require_csrf():
    sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    real = session.get("_csrf_token", "")
    # Use hmac.compare_digest to prevent timing-based token oracle attacks
    if not real or not sent or not hmac.compare_digest(sent, real):
        try:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            security_log("CSRF_FAIL", ip=ip, detail=f"path={request.path}")
        except Exception:
            pass
        from flask import abort
        abort(403)

# Make csrf_token() usable inside templates: {{ csrf_token() }}
try:
    app.jinja_env.globals["csrf_token"] = csrf_token
except Exception:
    pass

# CSRF is enforced blanket-style via csrf_protect_all_posts() below.
# ------------------------------------------------

# -----------------------
# Hardcoded admin (LAB ONLY)
# -----------------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "dedsec")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    import warnings
    warnings.warn(
        "ADMIN_PASSWORD not set! Using insecure default. "
        "Set ADMIN_PASSWORD env var for any non-local usage.",
        stacklevel=2,
    )
    ADMIN_PASSWORD = "ChangeMe123!"


# -----------------------
# Security tuning knobs
# -----------------------
LOGIN_FAIL_WINDOW = 10 * 60
LOGIN_FAIL_MAX = 5
AUTO_BAN_LOGIN_FAILS = 999999  # admin-only bans; auto-ban disabled
AUTO_BAN_DURATION = 30 * 60

UNAUTH_WINDOW = 5 * 60
UNAUTH_MAX = 10

SCAN_WINDOW = 60
SCAN_MAX = 5


def _safe_log_value(v):
    s = str(v)
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    s = s.replace("|", "\\|")
    return s


def security_log(event, **details):
    timestamp = datetime.now(timezone.utc).isoformat()
    line = f"{timestamp} | EVENT={_safe_log_value(event)}"
    for k, v in details.items():
        line += f" | {k.upper()}={_safe_log_value(v)}"
    try:
        SECURITY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(SECURITY_LOG, "a") as f:
            f.write(line + "\n")
    except OSError as exc:
        _logger.warning("security_log file write failed: %s", exc)
    _logger.info("SECURITY %s", line)


def db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=5,                 # busy timeout in seconds (driver-level)
        isolation_level=None,      # autocommit; avoids long implicit transactions
        check_same_thread=False,   # safe with gunicorn multi-worker usage pattern
    )
    conn.row_factory = sqlite3.Row

    # Reduce locking + improve concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")  # 5s

    return conn


# -----------------------
# Authorization / tenancy helpers
# -----------------------
def is_admin_user():
    try:
        return bool(session.get("is_admin"))
    except Exception:
        return False

def current_user_org_id():
    try:
        return session.get("org_id")
    except Exception:
        return None

def can_view_service_row(row):
    """
    View policy:
      - public: visible to anyone
      - private: only owner_user_id
      - org: same org_id only
    """
    vis = (row["visibility"] or "").strip().lower()

    if vis == "public":
        return True

    uid = session.get("user_id")
    if not uid:
        return False

    if vis == "private":
        return int(row["owner_user_id"]) == int(uid)

    if vis == "org":
        uorg = session.get("org_id")
        sorg = row["org_id"]
        return (uorg is not None) and (sorg is not None) and int(uorg) == int(sorg)

    return False


def can_modify_service_row(row):
    """
    Owner-only mutation policy:
      - only owner_user_id may edit/delete/list/unlist
      - same-org users may view org-visible rows, but may NOT modify them
    """
    uid = session.get("user_id")
    if not uid:
        return False
    return int(row["owner_user_id"]) == int(uid)


def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS orgs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            org_id INTEGER REFERENCES orgs(id)
        );
    """)

    # Add is_admin / org_id columns if DB already existed (ignore if already added)
    for alter_sql in [
        "ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;",
        "ALTER TABLE users ADD COLUMN org_id INTEGER REFERENCES orgs(id);",
    ]:
        try:
            conn.execute(alter_sql)
        except sqlite3.OperationalError:
            pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            org_id INTEGER,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            visibility TEXT NOT NULL DEFAULT 'private',
            status TEXT NOT NULL DEFAULT 'draft',
            price_cents INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY(owner_user_id) REFERENCES users(id)
        );
    """)
    for alter_sql in [
        "ALTER TABLE services ADD COLUMN org_id INTEGER;",
        "ALTER TABLE services ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private';",
        "ALTER TABLE services ADD COLUMN status TEXT NOT NULL DEFAULT 'draft';",
        "ALTER TABLE services ADD COLUMN price_cents INTEGER NOT NULL DEFAULT 0;",
    ]:
        try:
            conn.execute(alter_sql)
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT,
            ok INTEGER NOT NULL DEFAULT 0,
            ts INTEGER NOT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            ip TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            banned_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
    """)

    # Seed admin (LAB ONLY). Create or force-update password + is_admin=1.
    admin = conn.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    admin_hash = generate_password_hash(ADMIN_PASSWORD)
    if not admin:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            (ADMIN_USERNAME, admin_hash)
        )
    else:
        conn.execute(
            "UPDATE users SET password_hash = ?, is_admin = 1 WHERE username = ?",
            (admin_hash, ADMIN_USERNAME)
        )

    conn.commit()
    conn.close()


def record_event(ip, event, detail=""):
    conn = db()
    conn.execute(
        "INSERT INTO security_events (ts, ip, event, detail) VALUES (?, ?, ?, ?)",
        (int(time.time()), ip, event, (detail or "")[:500])
    )
    conn.commit()
    conn.close()


def prune_expired_bans():
    now = int(time.time())
    conn = db()
    conn.execute("DELETE FROM banned_ips WHERE expires_at <= ?", (now,))
    conn.commit()
    conn.close()


def ban_ip(ip, reason, duration_seconds=AUTO_BAN_DURATION):
    now = int(time.time())
    expires = now + int(duration_seconds)
    conn = db()
    conn.execute(
        "INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at, expires_at) VALUES (?, ?, ?, ?)",
        (ip, reason, now, expires)
    )
    conn.commit()
    conn.close()
    record_event(ip, "AUTO_BANNED" if reason.startswith("AUTO:") else "MANUAL_BANNED", reason)
    security_log("IP_BANNED", ip=ip, reason=reason, expires_at=expires)


def unban_ip(ip):
    conn = db()
    conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    record_event(ip, "UNBANNED", "Removed ban")
    security_log("IP_UNBANNED", ip=ip)


def is_ip_banned(ip):
    prune_expired_bans()
    now = int(time.time())
    conn = db()
    row = conn.execute(
        "SELECT ip, reason, banned_at, expires_at FROM banned_ips WHERE ip = ? AND expires_at > ?",
        (ip, now)
    ).fetchone()
    conn.close()
    return row


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = db()
    user = conn.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or int(u["is_admin"]) != 1:
            return "Forbidden", 403
        return fn(*args, **kwargs)
    return wrapper


# SECURITY: Only trust X-Forwarded-For when behind a properly configured reverse proxy
# (e.g., nginx with proxy_set_header X-Forwarded-For $remote_addr;)
# Set TRUST_PROXY=1 in environment to enable XFF trust.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"

def client_ip():
    if TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def record_login_attempt(ip, username, ok):
    conn = db()
    conn.execute(
        "INSERT INTO login_attempts (ip, username, ok, ts) VALUES (?, ?, ?, ?)",
        (ip, username[:150] if username else None, int(ok), int(time.time()))
    )
    conn.commit()
    conn.close()


def count_failures(ip, window_seconds):
    cutoff = int(time.time()) - int(window_seconds)
    conn = db()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM login_attempts WHERE ip = ? AND ok = 0 AND ts >= ?",
        (ip, cutoff)
    ).fetchone()
    conn.close()
    return (row["c"] if row else 0)


def too_many_failures(ip, window_seconds=LOGIN_FAIL_WINDOW, max_failures=LOGIN_FAIL_MAX):
    return count_failures(ip, window_seconds) >= max_failures


def clear_failures(ip):
    conn = db()
    conn.execute("DELETE FROM login_attempts WHERE ip = ? AND ok = 0", (ip,))
    conn.commit()
    conn.close()


def count_events(ip, event, window_seconds):
    cutoff = int(time.time()) - int(window_seconds)
    conn = db()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM security_events WHERE ip = ? AND event = ? AND ts >= ?",
        (ip, event, cutoff)
    ).fetchone()
    conn.close()
    return (row["c"] if row else 0)


def detection_on_failed_login(ip, username):
    record_event(ip, "FAILED_LOGIN", f"user={username}")
    security_log("FAILED_LOGIN", ip=ip, username=username)

    fails = count_failures(ip, LOGIN_FAIL_WINDOW)
    # if fails >= AUTO_BAN_LOGIN_FAILS:  # auto-ban disabled (admin-only)
        # ban_ip(...)  # auto-ban disabled (admin-only)


def detection_on_rate_limit(ip):
    record_event(ip, "RATE_LIMIT_TRIGGERED", "login throttled")
    security_log("RATE_LIMIT_TRIGGERED", ip=ip)


def detection_on_unauthorized(ip, session_uid, owner_uid, service_id):
    record_event(ip, "UNAUTHORIZED_SERVICE_ACCESS", f"sid={service_id} session_uid={session_uid} owner_uid={owner_uid}")
    security_log("UNAUTHORIZED_SERVICE_ACCESS", ip=ip, session_user_id=session_uid, owner_user_id=owner_uid, service_id=service_id)

    scan_hits = count_events(ip, "UNAUTHORIZED_SERVICE_ACCESS", SCAN_WINDOW)
    if scan_hits >= SCAN_MAX:
        record_event(ip, "SCAN_DETECTED", f"{scan_hits} unauthorized hits in {SCAN_WINDOW}s")
        security_log("SCAN_DETECTED", ip=ip, hits=scan_hits, window=SCAN_WINDOW)

    unauthed = count_events(ip, "UNAUTHORIZED_SERVICE_ACCESS", UNAUTH_WINDOW)
    # if unauthed >= UNAUTH_MAX:  # auto-ban disabled (admin-only)
        # ban_ip(...)  # auto-ban disabled (admin-only)


init_db()


@app.before_request
def ban_gate():
    ip = client_ip()
    ban = is_ip_banned(ip)
    if not ban:
        return None

    # let admin manage bans even if their IP is banned
    u = current_user()
    if u and int(u["is_admin"]) == 1 and (request.path or "").startswith("/admin"):
        return None

    if (request.path or "").startswith("/static/"):
        return None

    return f"Banned: {ban['reason']} (expires {datetime.fromtimestamp(ban['expires_at'], tz=timezone.utc).isoformat()})", 403



def normalize_text_field(value, *, max_len=255, allow_empty=False):
    """
    Normalize text input:
      - convert None -> ""
      - strip surrounding whitespace
      - collapse internal whitespace runs
      - reject control chars (except normal spaces)
      - enforce max length
    """
    if value is None:
        value = ""
    value = str(value)
    # reject ASCII control chars
    for ch in value:
        o = ord(ch)
        if o < 32 and ch not in ("\t", "\n", "\r"):
            raise ValueError("invalid characters")
    # normalize whitespace
    value = " ".join(value.split())
    if not allow_empty and value == "":
        raise ValueError("required")
    if len(value) > max_len:
        raise ValueError("too long")
    return value


def parse_price_cents(value, *, max_cents=10_000_000):
    """
    Parse and validate integer cents:
      - integer only
      - 0 <= price <= max_cents
    """
    if value is None or str(value).strip() == "":
        return 0
    try:
        n = int(str(value).strip())
    except Exception:
        raise ValueError("invalid price")
    if n < 0:
        raise ValueError("invalid price")
    if n > max_cents:
        raise ValueError("price too large")
    return n


def normalize_visibility(value):
    v = (value or "private").strip().lower()
    if v not in {"private", "org", "public"}:
        raise ValueError("invalid visibility")
    return v


def normalize_username(value):
    value = normalize_text_field(value, max_len=32, allow_empty=False)
    # conservative username charset
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_\-\.]+", value):
        raise ValueError("invalid username")
    if len(value) < 3:
        raise ValueError("username too short")
    return value


def normalize_org_name(value):
    # case-insensitive match in DB already; normalize spacing here
    value = normalize_text_field(value, max_len=64, allow_empty=False)
    if len(value) < 2:
        raise ValueError("org name too short")
    return value


def validate_password_basic(password):
    if password is None:
        raise ValueError("password required")
    password = str(password)
    if len(password) < 6:
        raise ValueError("password too short")
    if len(password) > 128:
        raise ValueError("password too long")
    return password



@app.before_request
def csrf_protect_all_posts():
    """
    Defense-in-depth: require CSRF on all POST requests except static/non-browser endpoints.
    If some endpoint must be exempt later, add an explicit allowlist here.
    """
    if request.method != "POST":
        return None
    if (request.path or "").startswith("/static/"):
        return None
    # register/login/logout/service/admin POSTs all require CSRF
    return require_csrf()


@app.after_request
def add_security_headers(response):
    """Attach defensive HTTP security headers to every response."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    )
    return response


@app.route("/")
def home():
    return render_template("home.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = normalize_username(request.form.get("username", ""))
            password = validate_password_basic(request.form.get("password", ""))
            org_name = normalize_org_name(request.form.get("org_name", ""))
        except ValueError as e:
            flash(f"Registration error: {e}")
            return redirect(url_for("register"))

        conn = db()
        try:
            # Reuse org if name exists (case-insensitive), else create it
            org = conn.execute(
                "SELECT id FROM orgs WHERE lower(name) = lower(?)",
                (org_name,)
            ).fetchone()

            if org:
                org_id = org["id"]
            else:
                cur = conn.execute(
                    "INSERT INTO orgs (name) VALUES (?)",
                    (org_name,)
                )
                org_id = cur.lastrowid

            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, org_id) VALUES (?, ?, 0, ?)",
                (username, generate_password_hash(password), org_id)
            )
            conn.commit()
            flash("Account created. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            conn.rollback()
            flash("Username already exists.")
            return redirect(url_for("register"))
        finally:
            conn.close()

    return render_template("register.html", user=current_user())



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = client_ip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if too_many_failures(ip):
            detection_on_rate_limit(ip)
            flash("Too many failed attempts. Try again later.")
            return redirect(url_for("login"))

        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            record_login_attempt(ip, username, ok=0)
            detection_on_failed_login(ip, username)
            # soft throttle: progressive delay to slow brute-force (skipped in TESTING mode)
            if not app.config.get("TESTING"):
                time.sleep(min(3.0, 0.5 * (count_failures(ip, LOGIN_FAIL_WINDOW) // 3)))
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        record_login_attempt(ip, username, ok=1)
        clear_failures(ip)

        # Rotate session after login to prevent fixation
        session.clear()
        session["_csrf_token"] = secrets.token_urlsafe(32)
        session["user_id"] = user['id']

        session["is_admin"] = int(user["is_admin"])
        session["org_id"] = user["org_id"]
        # If admin, send to dashboard
        if int(user["is_admin"]) == 1:
            flash("Admin login.")
            return redirect(url_for("admin_security"))

        flash("Welcome back!")
        return redirect(url_for("dashboard"))

    return render_template("login.html", user=current_user())


@app.route("/logout", methods=["POST"])

def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())


@app.route("/services")
@login_required
def services_list():
    conn = db()
    rows = conn.execute(
        "SELECT * FROM services ORDER BY id DESC"
    ).fetchall()
    conn.close()

    services = [r for r in rows if can_view_service_row(r)]
    return render_template("services.html", user=current_user(), services=services)

@app.route("/services/new", methods=["GET", "POST"])
@login_required
def services_new():
    if request.method == "POST":
        require_csrf()

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        try:
            visibility = normalize_visibility(request.form.get("visibility", "private"))
        except ValueError:
            flash("Invalid visibility.")
            return redirect(url_for("services_new"))

        price_raw = (request.form.get("price_cents", "0") or "0").strip()
        try:
            price_cents = int(price_raw)
        except Exception:
            price_cents = 0

        if price_cents < 0:
            price_cents = 0
        if price_cents > 500000:
            price_cents = 500000

        if len(name) < 2:
            flash("Service name must be at least 2 characters.")
            return redirect(url_for("services_new"))

        uid = session["user_id"]
        org_id = session.get("org_id")

        conn = db()
        conn.execute(
            """
            INSERT INTO services (owner_user_id, org_id, name, description, visibility, status, price_cents)
            VALUES (?, ?, ?, ?, ?, 'draft', ?)
            """,
            (uid, org_id, name, description, visibility, price_cents)
        )
        conn.commit()
        conn.close()
        flash("Service created (draft).")
        return redirect(url_for("services_list"))

    return render_template("services.html", user=current_user(), services=[])


@app.route("/services/<int:service_id>")
@login_required
def services_view(service_id):
    conn = db()
    row = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    conn.close()

    if not row or not can_view_service_row(row):
        from flask import abort
        abort(404)

    return render_template("service_view.html", user=current_user(), service=row)


@app.route("/services/<int:service_id>/edit", methods=["GET", "POST"])
@login_required
def services_edit(service_id):
    uid = session["user_id"]
    ip = client_ip()

    conn = db()
    service = conn.execute(
        "SELECT id, owner_user_id, name, description FROM services WHERE id = ?",
        (service_id,)
    ).fetchone()

    if not service:
        conn.close()
        return "Service not found", 404

    if service["owner_user_id"] != uid:
        detection_on_unauthorized(ip, uid, service["owner_user_id"], service_id)
        conn.close()
        return "Forbidden", 403

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if len(name) < 2:
            conn.close()
            flash("Service name must be at least 2 characters.")
            return redirect(url_for("services_edit", service_id=service_id))

        conn.execute(
            "UPDATE services SET name = ?, description = ? WHERE id = ? AND owner_user_id = ?",
            (name, description, service_id, uid)
        )
        conn.commit()
        conn.close()
        flash("Service updated.")
        return redirect(url_for("services_list"))

    conn.close()
    return render_template("service_edit.html", user=current_user(), service=service)


@app.route("/services/<int:service_id>/delete", methods=["POST"])
@login_required
def services_delete(service_id):
    require_csrf()
    uid = session["user_id"]
    ip = client_ip()

    conn = db()
    row = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if not row:
        conn.close()
        from flask import abort
        abort(404)

    if not can_modify_service_row(row):
        detection_on_unauthorized(ip, uid, row["owner_user_id"], service_id)
        conn.close()
        from flask import abort
        abort(403)

    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()
    flash("Service deleted.")
    return redirect(url_for("services_list"))




@app.route("/services/<int:service_id>/list", methods=["POST"])
@login_required
def service_list_action(service_id):
    require_csrf()
    conn = db()
    row = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if not row:
        conn.close()
        from flask import abort
        abort(404)

    if not can_modify_service_row(row):
        conn.close()
        from flask import abort
        abort(403)

    # Allowed transition: draft -> listed
    if row["status"] != "draft":
        conn.close()
        flash("Only draft services can be listed.")
        return redirect(url_for("services_view", service_id=service_id))

    conn.execute("UPDATE services SET status = 'listed' WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()
    flash("Service listed.")
    return redirect(url_for("services_view", service_id=service_id))


@app.route("/services/<int:service_id>/unlist", methods=["POST"])
@login_required
def service_unlist_action(service_id):
    require_csrf()
    conn = db()
    row = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if not row:
        conn.close()
        from flask import abort
        abort(404)

    if not can_modify_service_row(row):
        conn.close()
        from flask import abort
        abort(403)

    # Allowed transition: listed -> draft
    if row["status"] != "listed":
        conn.close()
        flash("Only listed services can be moved back to draft.")
        return redirect(url_for("services_view", service_id=service_id))

    conn.execute("UPDATE services SET status = 'draft' WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()
    flash("Service moved to draft.")
    return redirect(url_for("services_view", service_id=service_id))

@app.route("/admin/security")
@login_required
@admin_required
def admin_security():
    conn = db()
    bans = conn.execute("""
        SELECT ip, reason, banned_at, expires_at
        FROM banned_ips
        ORDER BY expires_at DESC
        LIMIT 50
    """).fetchall()
    events = conn.execute("""
        SELECT ts, ip, event, detail
        FROM security_events
        ORDER BY ts DESC
        LIMIT 200
    """).fetchall()
    conn.close()
    return render_template("admin_security.html", user=current_user(), bans=bans, events=events, now=int(time.time()))


@app.route("/admin/ban", methods=["POST"])
@login_required
@admin_required
def admin_ban():
    ip = request.form.get("ip", "").strip()
    minutes = request.form.get("minutes", "30").strip()
    reason = request.form.get("reason", "").strip() or "admin ban"

    try:
        mins = int(minutes)
        mins = max(1, min(24 * 60, mins))
    except Exception:
        mins = 30

    if not ip:
        flash("IP required.")
        return redirect(url_for("admin_security"))

    ban_ip(ip, f"MANUAL: {reason}", mins * 60)
    flash(f"Banned {ip} for {mins} minutes.")
    return redirect(url_for("admin_security"))


@app.route("/admin/unban", methods=["POST"])
@login_required
@admin_required
def admin_unban():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP required.")
        return redirect(url_for("admin_security"))
    unban_ip(ip)
    flash(f"Unbanned {ip}.")
    return redirect(url_for("admin_security"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
