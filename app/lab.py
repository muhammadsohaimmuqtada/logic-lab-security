import hashlib
import hmac
import time
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    has_request_context,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

lab_bp = Blueprint("lab", __name__)

DIFFICULTY_POINTS = {"Beginner": 100, "Intermediate": 200, "Advanced": 350, "Expert": 500}
HINT_COST = 25

CHALLENGES = [
    {"id":"LL01","title":"Tenant Enrollment","difficulty":"Intermediate","track":"Tenancy","objective":"Access organization-only data without being invited.","hints":["Map how organization membership is created.","Compare new-tenant and existing-tenant registration paths."]},
    {"id":"LL02","title":"Cross-Tenant Export","difficulty":"Intermediate","track":"Tenancy","objective":"Recover protected service data through an export workflow.","hints":["Look for secondary representations of service data.","Decide who the server trusts to choose the export tenant."]},
    {"id":"LL03","title":"Tenant Parameter Trust","difficulty":"Intermediate","track":"Tenancy","objective":"Discover another tenant's service metadata through a normal search feature.","hints":["Search requests may carry more context than the UI exposes.","Treat tenant identifiers as untrusted input."]},
    {"id":"LL04","title":"Stale Tenant Context","difficulty":"Advanced","track":"Authorization lifecycle","objective":"Use an organization switch to expose data from a previous security context.","hints":["Use an account that belongs to more than one organization.","Compare active organization state with cached capability state."]},
    {"id":"LL05","title":"Indirect Object Leak","difficulty":"Intermediate","track":"Object authorization","objective":"Reach protected service information through a secondary representation.","hints":["The primary object view is not the only representation.","Inspect activity and audit-adjacent workflows."]},
    {"id":"LL06","title":"Ownership Transfer","difficulty":"Intermediate","track":"Authorization","objective":"Take ownership of a service you are allowed to view but not manage.","hints":["View permission and ownership are different capabilities.","Test the ownership-management workflow separately from edit."]},
    {"id":"LL07","title":"Invite Role Escalation","difficulty":"Advanced","track":"Identity","objective":"Turn a legitimate collaboration invitation into a higher-privilege membership.","hints":["Separate invite identity from accepted membership properties.","Ask which side controls the accepted role."]},
    {"id":"LL08","title":"Invite Lifecycle","difficulty":"Intermediate","track":"Identity","objective":"Abuse invitation state after the business believes it is no longer usable.","hints":["Invitation state is a state machine.","Test both revoked and already-consumed tokens."]},
    {"id":"LL09","title":"State Machine Bypass","difficulty":"Intermediate","track":"Workflow","objective":"Reach a protected service state without completing its required lifecycle.","hints":["The UI only shows expected transitions.","Send a transition the UI never offers."]},
    {"id":"LL10","title":"Approval Integrity","difficulty":"Advanced","track":"Workflow","objective":"Change approved content without invalidating the approval decision.","hints":["Approval should bind to a specific version of content.","Try mutating content after approval."]},
    {"id":"LL11","title":"Checkout Integrity","difficulty":"Beginner","track":"Commerce","objective":"Purchase a service for less than its authoritative price.","hints":["Identify which price the server actually charges.","Hidden form fields are still client-controlled."]},
    {"id":"LL12","title":"Promotion Abuse","difficulty":"Intermediate","track":"Commerce","objective":"Break the intended single-use or single-promotion rules.","hints":["Try more than one promotion in one transaction.","Check whether checkout actually consumes a one-use coupon."]},
    {"id":"LL13","title":"Referral Economics","difficulty":"Intermediate","track":"Commerce","objective":"Create reward value without introducing a new customer.","hints":["A referral is supposed to involve distinct parties.","Who is prevented from referring themselves?"]},
    {"id":"LL14","title":"Refund Replay","difficulty":"Intermediate","track":"Commerce","objective":"Receive more refund value than was paid.","hints":["Financial operations should be idempotent.","Repeat a previously successful refund."]},
    {"id":"LL15","title":"Separation of Duties","difficulty":"Intermediate","track":"Workflow","objective":"Approve work despite a maker-checker policy.","hints":["Authorization by role is not the whole policy.","Compare the creator and approver identities."]},
    {"id":"LL16","title":"Recovery Proof","difficulty":"Intermediate","track":"Identity","objective":"Reset an account using business information that is not a real authentication factor.","hints":["Public business context is not an identity secret.","Test what recovery considers sufficient proof."]},
    {"id":"LL17","title":"Redemption Race","difficulty":"Advanced","track":"Concurrency","objective":"Win a concurrency race against a one-use promotion.","hints":["Look for check-then-act behavior.","Two requests should observe the same precondition before either commits."]},
    {"id":"LL18","title":"Premium Feature Gate","difficulty":"Beginner","track":"Entitlements","objective":"Use an enterprise-only feature from a starter subscription.","hints":["UI visibility is not authorization.","Request the premium capability directly."]},
    {"id":"LL19","title":"Seat Limit Projection","difficulty":"Intermediate","track":"Entitlements","objective":"Create more pending seats than the subscription permits.","hints":["Quota checks must account for the whole proposed operation.","Try a bulk operation near the current seat limit."]},
    {"id":"LL20","title":"Trial Extension Replay","difficulty":"Intermediate","track":"Entitlements","objective":"Extend a supposedly one-time trial more than once.","hints":["A successful trial extension should consume eligibility.","Repeat the exact business operation."]},
    {"id":"LL21","title":"API Object Authorization","difficulty":"Intermediate","track":"API","objective":"Read another tenant's service notes through the API.","hints":["Web authorization does not automatically protect API representations.","Try a known service identifier against its notes endpoint."]},
    {"id":"LL22","title":"API Property Authorization","difficulty":"Advanced","track":"API","objective":"Change a security-sensitive service property you should not control.","hints":["Object access and property-level access are separate decisions.","Look for writable ownership, tenant, status, or visibility fields."]},
    {"id":"LL23","title":"Batch Authorization","difficulty":"Advanced","track":"API","objective":"Use an authorized object to smuggle an unauthorized object into a batch operation.","hints":["Batch authorization must cover every item.","Put an owned object first and a foreign object later."]},
    {"id":"LL24","title":"Partner Identity Boundary","difficulty":"Intermediate","track":"Identity","objective":"Pass a partner-domain membership check with a non-partner identity.","hints":["String suffixes are not domain identities.","Construct a domain that ends with the trusted domain text."]},
    {"id":"LL25","title":"Alternate Quota Path","difficulty":"Advanced","track":"Abuse resistance","objective":"Exceed an export quota through an alternate business-flow path.","hints":["Quotas must apply across every equivalent route.","Consume the normal quota, then look for another export surface."]},
]

CHALLENGE_MAP = {c["id"]: c for c in CHALLENGES}


def _user_id(user_id=None):
    if user_id is not None:
        return int(user_id)
    if has_request_context() and session.get("user_id"):
        return int(session["user_id"])
    return 0


def flag(challenge_id: str, *, user_id=None) -> str:
    challenge_id = challenge_id.upper()
    if challenge_id not in CHALLENGE_MAP:
        raise KeyError(challenge_id)
    uid = _user_id(user_id)
    key = str(current_app.config["LAB_FLAG_SECRET"]).encode()
    digest = hmac.new(key, f"{challenge_id}:{uid}".encode(), hashlib.sha256).hexdigest()[:20]
    return f"FLAG{{{challenge_id}_{digest}}}"


def _db():
    from .db import get_db
    return get_db()


def challenge_points(challenge_id, hint_count=0):
    base = DIFFICULTY_POINTS[CHALLENGE_MAP[challenge_id]["difficulty"]]
    return max(base // 2, base - HINT_COST * int(hint_count))


@lab_bp.route("/lab")
def index():
    uid = session.get("user_id")
    solved = {}
    hint_counts = {}
    total_score = 0
    if uid:
        for row in _db().execute("SELECT challenge_id,solved_at,points_awarded FROM challenge_progress WHERE user_id=?", (uid,)).fetchall():
            solved[row["challenge_id"]] = row
            total_score += row["points_awarded"]
        for row in _db().execute("SELECT challenge_id,COUNT(*) AS c FROM challenge_hints WHERE user_id=? GROUP BY challenge_id", (uid,)).fetchall():
            hint_counts[row["challenge_id"]] = row["c"]
    board = []
    for c in CHALLENGES:
        item = dict(c)
        item["solved"] = c["id"] in solved
        item["hint_count"] = hint_counts.get(c["id"], 0)
        item["points"] = challenge_points(c["id"], item["hint_count"])
        item["visible_hints"] = c["hints"][: item["hint_count"]]
        board.append(item)
    return render_template("lab.html", challenges=board, solved_count=len(solved), total_score=total_score)


@lab_bp.route("/lab/submit", methods=["POST"])
def submit_flag():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    challenge_id = (request.form.get("challenge_id") or "").upper().strip()
    submitted = (request.form.get("flag") or "").strip()
    if challenge_id not in CHALLENGE_MAP:
        flash("Unknown challenge.", "error")
        return redirect(url_for("lab.index"))
    expected = flag(challenge_id, user_id=session["user_id"])
    if not hmac.compare_digest(submitted, expected):
        flash("Flag rejected.", "error")
        return redirect(url_for("lab.index"))
    db = _db()
    existing = db.execute("SELECT 1 FROM challenge_progress WHERE user_id=? AND challenge_id=?", (session["user_id"], challenge_id)).fetchone()
    if existing:
        flash(f"{challenge_id} was already solved.", "success")
        return redirect(url_for("lab.index"))
    hint_count = db.execute("SELECT COUNT(*) AS c FROM challenge_hints WHERE user_id=? AND challenge_id=?", (session["user_id"], challenge_id)).fetchone()["c"]
    points = challenge_points(challenge_id, hint_count)
    db.execute("INSERT INTO challenge_progress(user_id,challenge_id,solved_at,points_awarded) VALUES(?,?,?,?)", (session["user_id"], challenge_id, int(time.time()), points))
    flash(f"{challenge_id} solved for {points} points.", "success")
    return redirect(url_for("lab.index"))


@lab_bp.route("/lab/hint/<challenge_id>", methods=["POST"])
def use_hint(challenge_id):
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    challenge_id = challenge_id.upper()
    challenge = CHALLENGE_MAP.get(challenge_id)
    if not challenge:
        abort(404)
    db = _db()
    used = db.execute("SELECT COUNT(*) AS c FROM challenge_hints WHERE user_id=? AND challenge_id=?", (session["user_id"], challenge_id)).fetchone()["c"]
    if used >= len(challenge["hints"]):
        flash("No more hints are available for this challenge.", "error")
        return redirect(url_for("lab.index"))
    db.execute("INSERT INTO challenge_hints(user_id,challenge_id,hint_index,created_at) VALUES(?,?,?,?)", (session["user_id"], challenge_id, used, int(time.time())))
    flash(f"Hint unlocked for {challenge_id}. Future solve value reduced by {HINT_COST} points.", "success")
    return redirect(url_for("lab.index"))


@lab_bp.route("/lab/progress")
def progress():
    if not session.get("user_id"):
        return {"authenticated": False, "solved": 0, "score": 0}
    rows = _db().execute("SELECT challenge_id,solved_at,points_awarded FROM challenge_progress WHERE user_id=? ORDER BY solved_at", (session["user_id"],)).fetchall()
    return {"authenticated": True, "solved": len(rows), "score": sum(r["points_awarded"] for r in rows), "challenges": [dict(r) for r in rows]}
