import time
from flask import Blueprint, abort, request, session
from .db import get_db
from .lab import flag
from .security import current_org_id, login_required, membership, parse_int

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

VALID_VISIBILITY = {"private", "org", "public"}
VALID_STATUS = {"draft", "review", "approved", "published", "archived"}


def _service(service_id):
    return get_db().execute("SELECT * FROM services WHERE id=?", (service_id,)).fetchone()


def _json_object():
    payload = request.get_json(silent=True)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        abort(400)
    return payload


def _validated_patch(db, service, payload):
    values = {}

    if "name" in payload:
        if not isinstance(payload["name"], str) or not 2 <= len(payload["name"].strip()) <= 120:
            abort(400)
        values["name"] = payload["name"].strip()

    if "description" in payload:
        if not isinstance(payload["description"], str) or len(payload["description"]) > 5000:
            abort(400)
        values["description"] = payload["description"].strip()

    if "visibility" in payload:
        visibility = str(payload["visibility"]).strip().lower()
        if visibility not in VALID_VISIBILITY:
            abort(400)
        values["visibility"] = visibility

    if "status" in payload:
        status = str(payload["status"]).strip().lower()
        if status not in VALID_STATUS:
            abort(400)
        values["status"] = status

    target_org_id = service["org_id"]
    if "org_id" in payload:
        target_org_id = parse_int(payload["org_id"], minimum=1)
        if not db.execute("SELECT 1 FROM orgs WHERE id=?", (target_org_id,)).fetchone():
            abort(400)
        values["org_id"] = target_org_id

    target_owner_id = service["owner_user_id"]
    if "owner_user_id" in payload:
        target_owner_id = parse_int(payload["owner_user_id"], minimum=1)
        values["owner_user_id"] = target_owner_id

    if "org_id" in payload or "owner_user_id" in payload:
        if not db.execute(
            "SELECT 1 FROM memberships WHERE user_id=? AND org_id=?",
            (target_owner_id, target_org_id),
        ).fetchone():
            abort(400)

    return values


@api_bp.route("/services/<int:service_id>/notes")
@login_required
def service_notes(service_id):
    db = get_db()
    service = _service(service_id)
    if not service:
        abort(404)
    rows = db.execute("SELECT id,event,detail,created_at FROM activities WHERE service_id=? ORDER BY id DESC", (service_id,)).fetchall()
    unauthorized = not membership(org_id=service["org_id"]) and service["owner_user_id"] != session["user_id"]
    return {"service_id": service_id, "notes": [dict(r) for r in rows], "marker": flag("LL21") if unauthorized and rows else None}


@api_bp.route("/services/<int:service_id>", methods=["PATCH"])
@login_required
def update_service(service_id):
    db = get_db()
    service = _service(service_id)
    if not service:
        abort(404)
    payload = _json_object()
    values = _validated_patch(db, service, payload)
    if not values:
        return {"updated": False}
    touched_sensitive = bool(set(values) & {"visibility", "status", "owner_user_id", "org_id"})
    fields = [f"{key}=?" for key in values]
    params = [values[key] for key in values]
    params.append(service_id)
    db.execute(f"UPDATE services SET {', '.join(fields)} WHERE id=?", tuple(params))
    unauthorized = service["owner_user_id"] != session["user_id"]
    return {"updated": True, "marker": flag("LL22") if touched_sensitive and unauthorized else None}


@api_bp.route("/services/batch-visibility", methods=["POST"])
@login_required
def batch_visibility():
    db = get_db()
    payload = _json_object()
    raw_ids = payload.get("ids", [])
    if not isinstance(raw_ids, list):
        abort(400)
    ids = [parse_int(x, minimum=1) for x in raw_ids[:20]]
    visibility = payload.get("visibility", "org")
    if not ids or visibility not in VALID_VISIBILITY:
        abort(400)
    first = _service(ids[0])
    if not first or first["owner_user_id"] != session["user_id"]:
        abort(403)
    placeholders = ",".join("?" for _ in ids)
    before = db.execute(f"SELECT id,org_id,owner_user_id FROM services WHERE id IN ({placeholders})", tuple(ids)).fetchall()
    cross_scope = any(r["owner_user_id"] != session["user_id"] for r in before)
    db.execute(f"UPDATE services SET visibility=? WHERE id IN ({placeholders})", (visibility, *ids))
    return {"updated_ids": ids, "marker": flag("LL23") if cross_scope else None}


@api_bp.route("/partners/enroll", methods=["POST"])
@login_required
def partner_enroll():
    payload = _json_object()
    email = str(payload.get("email", "")).strip().lower()
    if not email.endswith("alpha.local"):
        return {"accepted": False, "reason": "partner domain required"}, 403
    db = get_db()
    alpha = db.execute("SELECT id FROM orgs WHERE name='AlphaSec' COLLATE NOCASE").fetchone()
    db.execute("INSERT INTO memberships(user_id,org_id,role) VALUES(?,?,?) ON CONFLICT(user_id,org_id) DO UPDATE SET role=excluded.role", (session["user_id"], alpha["id"], "viewer"))
    actual_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    is_real_partner = actual_domain == "alpha.local"
    return {"accepted": True, "marker": flag("LL24") if not is_real_partner else None}


@api_bp.route("/export", methods=["POST"])
@login_required
def alternate_export():
    db = get_db()
    sub = db.execute("SELECT * FROM subscriptions WHERE org_id=?", (current_org_id(),)).fetchone()
    if not sub:
        abort(404)
    used = db.execute("SELECT COALESCE(SUM(quantity),0) AS c FROM feature_usage WHERE org_id=? AND feature='tenant_export'", (current_org_id(),)).fetchone()["c"]
    db.execute("INSERT INTO feature_usage(org_id,user_id,feature,quantity,created_at) VALUES(?,?,?,?,?)", (current_org_id(), session["user_id"], "tenant_export", 1, int(time.time())))
    new_used = used + 1
    return {"status": "export generated", "used": new_used, "quota": sub["export_quota"], "marker": flag("LL25") if new_used > sub["export_quota"] else None}
