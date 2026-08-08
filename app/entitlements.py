import secrets
import time
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from .db import get_db
from .lab import flag
from .security import current_org_id, login_required, role_at_least, role_required, parse_int

entitlements_bp = Blueprint("entitlements", __name__, url_prefix="/entitlements")


def _subscription():
    return get_db().execute("SELECT * FROM subscriptions WHERE org_id=?", (current_org_id(),)).fetchone()


@entitlements_bp.route("")
@login_required
def index():
    db = get_db()
    sub = _subscription()
    members = db.execute("SELECT COUNT(*) AS c FROM memberships WHERE org_id=?", (current_org_id(),)).fetchone()["c"]
    pending = db.execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (current_org_id(),)).fetchone()["c"]
    exports = db.execute("SELECT COALESCE(SUM(quantity),0) AS c FROM feature_usage WHERE org_id=? AND feature='tenant_export'", (current_org_id(),)).fetchone()["c"]
    return render_template(
        "entitlements.html",
        sub=sub,
        members=members,
        pending=pending,
        exports=exports,
        marker=None,
        can_manage=role_at_least("manager"),
    )


@entitlements_bp.route("/premium-report")
@login_required
def premium_report():
    sub = _subscription()
    if not sub:
        abort(404)
    marker = flag("LL18") if sub["plan"] != "enterprise" else None
    report = "Organization-wide executive risk forecast and portfolio telemetry."
    return render_template("entitlements.html", sub=sub, members=None, pending=None, exports=None, marker=marker, premium_report=report, can_manage=False)


@entitlements_bp.route("/bulk-invite", methods=["POST"])
@role_required("manager")
def bulk_invite():
    db = get_db()
    sub = _subscription()
    raw = (request.form.get("emails") or "").replace("\n", ",")
    emails = [x.strip().lower() for x in raw.split(",") if "@" in x]
    current_members = db.execute("SELECT COUNT(*) AS c FROM memberships WHERE org_id=?", (current_org_id(),)).fetchone()["c"]
    pending = db.execute("SELECT COUNT(*) AS c FROM invitations WHERE org_id=? AND revoked=0 AND used_at IS NULL", (current_org_id(),)).fetchone()["c"]
    if not sub or current_members + pending >= sub["seat_limit"]:
        flash("No seat capacity is currently available.", "error")
        return redirect(url_for("entitlements.index"))
    created = 0
    for email in emails[:20]:
        db.execute("INSERT INTO invitations(org_id,email,role,token,revoked,used_at) VALUES(?,?,?,?,0,NULL)", (current_org_id(), email, "member", secrets.token_urlsafe(18)))
        created += 1
    marker = flag("LL19") if current_members + pending + created > sub["seat_limit"] else ""
    flash(f"Created {created} pending invitations. {marker}", "success")
    return redirect(url_for("entitlements.index"))


@entitlements_bp.route("/trial/extend", methods=["POST"])
@role_required("manager")
def extend_trial():
    db = get_db()
    sub = _subscription()
    if not sub:
        abort(404)
    days = parse_int(request.form.get("days"), default=7, minimum=1, maximum=30)
    previous = sub["trial_extensions"]
    db.execute("UPDATE subscriptions SET trial_ends_at=trial_ends_at+?, trial_extensions=trial_extensions+1 WHERE org_id=?", (days * 86400, current_org_id()))
    marker = flag("LL20") if previous >= 1 else ""
    flash(f"Trial extended by {days} days. {marker}", "success")
    return redirect(url_for("entitlements.index"))


@entitlements_bp.route("/export", methods=["POST"])
@login_required
def quota_export():
    db = get_db()
    sub = _subscription()
    if not sub:
        abort(404)
    used = db.execute("SELECT COALESCE(SUM(quantity),0) AS c FROM feature_usage WHERE org_id=? AND feature='tenant_export'", (current_org_id(),)).fetchone()["c"]
    if used >= sub["export_quota"]:
        return {"error": "export quota exceeded", "used": used, "quota": sub["export_quota"]}, 429
    db.execute("INSERT INTO feature_usage(org_id,user_id,feature,quantity,created_at) VALUES(?,?,?,?,?)", (current_org_id(), session["user_id"], "tenant_export", 1, int(time.time())))
    return {"status": "export generated", "used": used + 1, "quota": sub["export_quota"]}
