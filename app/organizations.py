import secrets
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from .db import get_db
from .security import login_required, role_required, role_at_least, current_org_id, membership
from .lab import flag

org_bp = Blueprint("orgs", __name__, url_prefix="/org")


def _has_single_invite_capacity(org_id):
    db = get_db()
    sub = db.execute("SELECT seat_limit FROM subscriptions WHERE org_id=?", (org_id,)).fetchone()
    if not sub:
        return True
    members = db.execute("SELECT COUNT(*) AS c FROM memberships WHERE org_id=?", (org_id,)).fetchone()["c"]
    pending = db.execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (org_id,)).fetchone()["c"]
    return members + pending < sub["seat_limit"]


@org_bp.route("")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    memberships = db.execute("SELECT m.*, o.name FROM memberships m JOIN orgs o ON o.id=m.org_id WHERE m.user_id=? ORDER BY o.name", (uid,)).fetchall()
    active = db.execute("SELECT * FROM orgs WHERE id=?", (current_org_id(),)).fetchone()
    can_manage_invites = role_at_least("manager")
    invites = []
    if can_manage_invites:
        invites = db.execute("SELECT * FROM invitations WHERE org_id=? ORDER BY id DESC LIMIT 20", (current_org_id(),)).fetchall()
    return render_template("org.html", memberships=memberships, active=active, invites=invites, can_manage_invites=can_manage_invites)


@org_bp.route("/switch/<int:org_id>", methods=["POST"])
@login_required
def switch(org_id):
    if not membership(org_id=org_id):
        abort(403)
    session["active_org_id"] = org_id
    get_db().execute("UPDATE users SET active_org_id=? WHERE id=?", (org_id, session["user_id"]))
    flash("Organization switched.", "success")
    return redirect(url_for("orgs.dashboard"))


@org_bp.route("/context-feed")
@login_required
def context_feed():
    org_id = session.get("capability_org_id")
    rows = get_db().execute("SELECT detail FROM activities WHERE org_id=? AND event='TENANT_CONTEXT' ORDER BY id DESC", (org_id,)).fetchall()
    return render_template("context_feed.html", rows=rows, marker=flag("LL04") if rows and org_id != current_org_id() else None)


@org_bp.route("/invite", methods=["POST"])
@role_required("manager")
def create_invite():
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or "member").strip().lower()
    if role not in {"viewer", "member", "manager"} or "@" not in email:
        abort(400)
    if not _has_single_invite_capacity(current_org_id()):
        flash("Seat limit reached. Revoke a pending invitation or upgrade the plan.", "error")
        return redirect(url_for("orgs.dashboard"))
    token = secrets.token_urlsafe(18)
    get_db().execute("INSERT INTO invitations(org_id,email,role,token,revoked,used_at) VALUES(?,?,?,?,0,NULL)", (current_org_id(), email, role, token))
    flash(f"Invitation created: {token}", "success")
    return redirect(url_for("orgs.dashboard"))


@org_bp.route("/invite/<int:invite_id>/revoke", methods=["POST"])
@role_required("manager")
def revoke_invite(invite_id):
    get_db().execute("UPDATE invitations SET revoked=1 WHERE id=? AND org_id=?", (invite_id, current_org_id()))
    flash("Invitation revoked.", "success")
    return redirect(url_for("orgs.dashboard"))


@org_bp.route("/accept", methods=["GET", "POST"])
@login_required
def accept_invite():
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        requested_role = (request.form.get("role") or "").strip().lower()
        db = get_db()
        invite = db.execute("SELECT * FROM invitations WHERE token=?", (token,)).fetchone()
        if not invite:
            flash("Invitation not found.", "error")
            return redirect(url_for("orgs.accept_invite"))
        user = db.execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["email"].lower() != invite["email"].lower():
            abort(403)
        role = requested_role if requested_role in {"viewer", "member", "manager", "owner"} else invite["role"]
        db.execute("INSERT INTO memberships(user_id,org_id,role) VALUES(?,?,?) ON CONFLICT(user_id,org_id) DO UPDATE SET role=excluded.role", (session["user_id"], invite["org_id"], role))
        db.execute("UPDATE invitations SET used_at=? WHERE id=?", (int(time.time()), invite["id"]))
        db.execute("UPDATE users SET active_org_id=? WHERE id=?", (invite["org_id"], session["user_id"]))
        session["active_org_id"] = invite["org_id"]
        session["capability_org_id"] = invite["org_id"]
        marker = []
        if requested_role and role != invite["role"]:
            marker.append(flag("LL07"))
        if invite["revoked"] or invite["used_at"]:
            marker.append(flag("LL08"))
        flash("Invitation accepted. " + " ".join(marker), "success")
        return redirect(url_for("orgs.dashboard"))
    return render_template("accept_invite.html")
