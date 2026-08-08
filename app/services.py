import csv
import io
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, Response
from .db import get_db
from .security import login_required, current_org_id, membership, role_at_least, audit
from .lab import flag

services_bp = Blueprint("services", __name__, url_prefix="/services")


def _service(service_id):
    return get_db().execute("SELECT * FROM services WHERE id=?", (service_id,)).fetchone()


def _can_view(row):
    if not row:
        return False
    if row["visibility"] == "public":
        return True
    if row["owner_user_id"] == session.get("user_id"):
        return True
    return row["visibility"] == "org" and bool(membership(org_id=row["org_id"]))


@services_bp.route("")
@login_required
def index():
    db = get_db()
    uid = session["user_id"]
    org_id = current_org_id()
    rows = db.execute("SELECT * FROM services WHERE visibility='public' OR owner_user_id=? OR (visibility='org' AND org_id=?) ORDER BY id", (uid, org_id)).fetchall()
    return render_template("services.html", services=rows)


@services_bp.route("/new", methods=["POST"])
@login_required
def create():
    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    visibility = (request.form.get("visibility") or "private").strip()
    try:
        price = max(0, min(1_000_000, int(request.form.get("price_cents") or 0)))
    except ValueError:
        abort(400)
    if visibility not in {"private", "org", "public"} or len(name) < 2:
        abort(400)
    get_db().execute("INSERT INTO services(org_id,owner_user_id,name,description,visibility,status,price_cents) VALUES(?,?,?,?,?,'draft',?)", (current_org_id(), session["user_id"], name, description, visibility, price))
    return redirect(url_for("services.index"))


@services_bp.route("/<int:service_id>")
@login_required
def view(service_id):
    row = _service(service_id)
    if not _can_view(row):
        abort(404)
    marker = flag(row["secret_flag"]) if row["secret_flag"] else None
    return render_template("service_view.html", service=row, marker=marker)


@services_bp.route("/<int:service_id>/edit", methods=["POST"])
@login_required
def edit(service_id):
    row = _service(service_id)
    if not row or row["owner_user_id"] != session["user_id"]:
        abort(403)
    name = (request.form.get("name") or row["name"]).strip()
    description = (request.form.get("description") or row["description"]).strip()
    get_db().execute("UPDATE services SET name=?,description=? WHERE id=?", (name, description, service_id))
    marker = flag("LL10") if row["approved_at"] else ""
    flash("Service updated. " + marker, "success")
    return redirect(url_for("services.view", service_id=service_id))


@services_bp.route("/<int:service_id>/transfer", methods=["POST"])
@login_required
def transfer(service_id):
    row = _service(service_id)
    new_owner = int(request.form.get("new_owner_user_id") or 0)
    if not row or not membership(org_id=row["org_id"]):
        abort(403)
    target = get_db().execute("SELECT 1 FROM memberships WHERE user_id=? AND org_id=?", (new_owner, row["org_id"])).fetchone()
    if not target:
        abort(400)
    old_owner = row["owner_user_id"]
    get_db().execute("UPDATE services SET owner_user_id=? WHERE id=?", (new_owner, service_id))
    marker = flag("LL06") if old_owner != session["user_id"] else ""
    flash("Ownership transferred. " + marker, "success")
    return redirect(url_for("services.view", service_id=service_id))


@services_bp.route("/<int:service_id>/transition", methods=["POST"])
@login_required
def transition(service_id):
    row = _service(service_id)
    if not row or row["owner_user_id"] != session["user_id"]:
        abort(403)
    target = (request.form.get("status") or "").strip().lower()
    if target not in {"draft", "review", "approved", "published", "archived"}:
        abort(400)
    old = row["status"]
    get_db().execute("UPDATE services SET status=? WHERE id=?", (target, service_id))
    marker = flag("LL09") if old == "draft" and target in {"approved", "published"} else ""
    flash(f"State changed {old} → {target}. {marker}", "success")
    return redirect(url_for("services.view", service_id=service_id))


@services_bp.route("/<int:service_id>/approve", methods=["POST"])
@login_required
def approve(service_id):
    row = _service(service_id)
    if not row or not role_at_least("manager", org_id=row["org_id"]):
        abort(403)
    get_db().execute("UPDATE services SET status='approved',approved_at=?,approved_by=? WHERE id=?", (int(time.time()), session["user_id"], service_id))
    marker = flag("LL15") if row["owner_user_id"] == session["user_id"] else ""
    flash("Service approved. " + marker, "success")
    return redirect(url_for("services.view", service_id=service_id))


@services_bp.route("/export")
@login_required
def export_services():
    org_id = int(request.args.get("org_id") or current_org_id())
    rows = get_db().execute("SELECT id,name,description,status,secret_flag FROM services WHERE org_id=? ORDER BY id", (org_id,)).fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "name", "description", "status", "marker"])
    for r in rows:
        marker = flag(r["secret_flag"]) if r["secret_flag"] else ""
        writer.writerow([r["id"], r["name"], r["description"], r["status"], marker])
    return Response(out.getvalue(), mimetype="text/csv")


@services_bp.route("/search")
@login_required
def search():
    q = (request.args.get("q") or "").strip()
    org_id = int(request.args.get("org_id") or current_org_id())
    rows = get_db().execute("SELECT id,name,description,status FROM services WHERE org_id=? AND (name LIKE ? OR description LIKE ?) ORDER BY id", (org_id, f"%{q}%", f"%{q}%")).fetchall()
    marker = None
    if rows and org_id != current_org_id() and not membership(org_id=org_id):
        marker = flag("LL03")
    return render_template("search.html", rows=rows, q=q, marker=marker)


@services_bp.route("/<int:service_id>/activity")
@login_required
def activity(service_id):
    service = _service(service_id)
    rows = get_db().execute("SELECT * FROM activities WHERE service_id=? ORDER BY id DESC", (service_id,)).fetchall()
    audit("ACTIVITY_VIEW", f"service_id={service_id}")
    marker = None
    if service and rows and not _can_view(service):
        marker = flag("LL05")
    return render_template("activity.html", rows=rows, marker=marker)
