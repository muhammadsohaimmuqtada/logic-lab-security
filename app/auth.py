import sqlite3
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db
from .security import csrf_token
from .lab import flag

auth_bp = Blueprint("auth", __name__)


def _valid_username(value):
    value = (value or "").strip()
    return value if 3 <= len(value) <= 32 and all(c.isalnum() or c in "_.-" for c in value) else None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = _valid_username(request.form.get("username"))
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        org_name = (request.form.get("org_name") or "").strip()
        if not username or "@" not in email or len(password) < 8 or len(org_name) < 2:
            flash("Please provide valid registration details.", "error")
            return redirect(url_for("auth.register"))
        db = get_db()
        try:
            org = db.execute("SELECT id FROM orgs WHERE name=? COLLATE NOCASE", (org_name,)).fetchone()
            created_org = False
            if not org:
                org_id = db.execute("INSERT INTO orgs(name) VALUES(?)", (org_name,)).lastrowid
                created_org = True
                now = int(time.time())
                db.execute("INSERT INTO subscriptions(org_id,plan,seat_limit,export_quota,trial_started_at,trial_ends_at,trial_extensions) VALUES(?,?,?,?,?,?,0)", (org_id, "starter", 2, 1, now, now + 14 * 86400))
            else:
                org_id = org["id"]
            cur = db.execute("INSERT INTO users(username,email,password_hash,credits,referral_code,active_org_id) VALUES(?,?,?,?,?,?)", (username, email, generate_password_hash(password), 10000, f"{username.upper()}10", org_id))
            uid = cur.lastrowid
            db.execute("INSERT INTO memberships(user_id,org_id,role) VALUES(?,?,?)", (uid, org_id, "owner" if created_org else "member"))
            flash("Account created. You can sign in.", "success")
            return redirect(url_for("auth.login"))
        except sqlite3.IntegrityError:
            flash("Username, email, or referral code already exists.", "error")
            return redirect(url_for("auth.register"))
    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("auth.login"))
        session.clear()
        session["_csrf_token"] = csrf_token()
        session["user_id"] = user["id"]
        session["active_org_id"] = user["active_org_id"]
        session["capability_org_id"] = user["active_org_id"]
        return redirect(url_for("services.index"))
    return render_template("login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        org_name = (request.form.get("org_name") or "").strip()
        new_password = request.form.get("new_password") or ""
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return redirect(url_for("auth.recover"))
        user = get_db().execute("SELECT u.* FROM users u JOIN memberships m ON m.user_id=u.id JOIN orgs o ON o.id=m.org_id WHERE u.username=? AND o.name=? COLLATE NOCASE", (username, org_name)).fetchone()
        if not user:
            flash("Recovery details not recognized.", "error")
            return redirect(url_for("auth.recover"))
        get_db().execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_password), user["id"]))
        flash(f"Password reset completed. Recovery audit code: {flag('LL16', user_id=user['id'])}", "success")
        return redirect(url_for("auth.login"))
    return render_template("recover.html")
