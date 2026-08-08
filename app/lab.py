import hashlib
from flask import Blueprint, render_template, request, flash, redirect, url_for, session

lab_bp = Blueprint("lab", __name__)

CHALLENGES = [
    {"id": "LL01", "title": "Tenant Enrollment", "difficulty": "Intermediate", "objective": "Access organization-only data without being invited."},
    {"id": "LL02", "title": "Cross-Tenant Export", "difficulty": "Intermediate", "objective": "Recover protected service data through an export workflow."},
    {"id": "LL03", "title": "Tenant Parameter Trust", "difficulty": "Intermediate", "objective": "Discover another tenant's service metadata through a normal search feature."},
    {"id": "LL04", "title": "Stale Tenant Context", "difficulty": "Advanced", "objective": "Use an organization switch to expose data from a previous security context."},
    {"id": "LL05", "title": "Indirect Object Leak", "difficulty": "Intermediate", "objective": "Reach protected service information through a secondary representation."},
    {"id": "LL06", "title": "Ownership Transfer", "difficulty": "Intermediate", "objective": "Take ownership of a service you are allowed to view but not manage."},
    {"id": "LL07", "title": "Invite Role Escalation", "difficulty": "Advanced", "objective": "Turn a legitimate collaboration invitation into a higher-privilege membership."},
    {"id": "LL08", "title": "Invite Lifecycle", "difficulty": "Intermediate", "objective": "Abuse invitation state after the business believes it is no longer usable."},
    {"id": "LL09", "title": "State Machine Bypass", "difficulty": "Intermediate", "objective": "Reach a protected service state without completing its required lifecycle."},
    {"id": "LL10", "title": "Approval Integrity", "difficulty": "Advanced", "objective": "Change approved content without invalidating the approval decision."},
    {"id": "LL11", "title": "Checkout Integrity", "difficulty": "Beginner", "objective": "Purchase a service for less than its authoritative price."},
    {"id": "LL12", "title": "Promotion Abuse", "difficulty": "Intermediate", "objective": "Break the intended single-use or single-promotion rules."},
    {"id": "LL13", "title": "Referral Economics", "difficulty": "Intermediate", "objective": "Create reward value without introducing a new customer."},
    {"id": "LL14", "title": "Refund Replay", "difficulty": "Intermediate", "objective": "Receive more refund value than was paid."},
    {"id": "LL15", "title": "Separation of Duties", "difficulty": "Intermediate", "objective": "Approve work despite a maker-checker policy."},
    {"id": "LL16", "title": "Recovery Proof", "difficulty": "Intermediate", "objective": "Reset an account using business information that is not a real authentication factor."},
    {"id": "LL17", "title": "Redemption Race", "difficulty": "Advanced", "objective": "Win a concurrency race against a one-use promotion."},
]

FLAGS = {
    "LL01": "FLAG{tenant_membership_requires_authorization}",
    "LL02": "FLAG{exports_need_object_scope_too}",
    "LL03": "FLAG{tenant_ids_are_not_authority}",
    "LL04": "FLAG{authorization_context_must_rotate}",
    "LL05": "FLAG{every_representation_needs_authz}",
    "LL06": "FLAG{view_permission_is_not_ownership}",
    "LL07": "FLAG{server_controls_role_assignment}",
    "LL08": "FLAG{invites_have_a_state_machine}",
    "LL09": "FLAG{state_transitions_are_security_boundaries}",
    "LL10": "FLAG{approval_must_bind_to_content}",
    "LL11": "FLAG{server_is_the_price_authority}",
    "LL12": "FLAG{promotions_need_atomic_constraints}",
    "LL13": "FLAG{referrals_require_distinct_parties}",
    "LL14": "FLAG{refunds_must_be_idempotent}",
    "LL15": "FLAG{makers_should_not_be_checkers}",
    "LL16": "FLAG{business_data_is_not_identity_proof}",
    "LL17": "FLAG{check_then_act_is_not_atomic}",
}

FLAG_HASHES = {k: hashlib.sha256(v.encode()).hexdigest() for k, v in FLAGS.items()}


def flag(challenge_id: str) -> str:
    return FLAGS[challenge_id]


@lab_bp.route("/lab")
def index():
    solved = session.get("solved", [])
    return render_template("lab.html", challenges=CHALLENGES, solved=solved)


@lab_bp.route("/lab/submit", methods=["POST"])
def submit_flag():
    challenge_id = (request.form.get("challenge_id") or "").upper().strip()
    submitted = (request.form.get("flag") or "").strip()
    expected_hash = FLAG_HASHES.get(challenge_id)
    if not expected_hash or hashlib.sha256(submitted.encode()).hexdigest() != expected_hash:
        flash("Flag rejected.", "error")
        return redirect(url_for("lab.index"))
    solved = set(session.get("solved", []))
    solved.add(challenge_id)
    session["solved"] = sorted(solved)
    flash(f"{challenge_id} solved.", "success")
    return redirect(url_for("lab.index"))
