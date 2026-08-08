# Instructor Guide — Logic Lab Security v2

> **Spoilers:** this document maps every intentional vulnerability. Learners should not use it during a blind attempt.

## Design rules

Every challenge follows four rules:

1. the normal application workflow must remain coherent;
2. the vulnerability must arise from a business assumption, authorization boundary, lifecycle rule, economic rule, or concurrency rule;
3. exploitability must be covered by an automated challenge-contract test;
4. host-level primitives such as shell execution, arbitrary file access, or container escape are outside the lab's intended scope.

## Scenario map

### LL01 — Tenant Enrollment
Registration reuses an existing organization when the submitted organization name matches. No invitation or membership authorization is required.

### LL02 — Cross-Tenant Export
The export workflow accepts an organization identifier and applies it directly without verifying tenant membership.

### LL03 — Tenant Parameter Trust
Search supports a legacy `org_id` query parameter even though the standard UI does not expose it.

### LL04 — Stale Tenant Context
Login creates both an active organization and a cached capability organization. Tenant switching rotates only the active organization.

### LL05 — Indirect Object Leak
Direct service access checks visibility, but the activity representation checks only authentication.

### LL06 — Ownership Transfer
The transfer workflow checks organization membership but does not require the actor to be the current owner or a privileged administrator.

### LL07 — Invite Role Escalation
Invite acceptance accepts an undocumented client-supplied `role` value.

### LL08 — Invite Lifecycle
Invitation acceptance intentionally omits `revoked` and `used_at` validation.

### LL09 — State Machine Bypass
The transition route validates the requested state as an enum but does not validate legal state-machine edges.

### LL10 — Approval Integrity
Approved/published content is locked in the normal UI, but the edit endpoint remains reachable and does not invalidate approval metadata.

### LL11 — Checkout Integrity
Checkout trusts a client-returned price value rather than using only the authoritative service price.

### LL12 — Promotion Abuse
Checkout accepts multiple comma-separated codes and does not consume coupon usage.

### LL13 — Referral Economics
Referral processing does not require referrer and referred user to be distinct.

### LL14 — Refund Replay
Refund processing never makes the operation terminal or idempotent.

### LL15 — Separation of Duties
Approval requires manager-level authority but does not require approver and service owner to be different users.

### LL16 — Recovery Proof
Legacy recovery treats username plus organization name as sufficient identity proof.

### LL17 — Redemption Race
Promotion redemption performs a stale check-then-act update, allowing concurrent successful receipts beyond the recorded usage count.

## Teaching sequence

A useful progression is LL11; LL01/LL03/LL05; LL06/LL07/LL08; LL09/LL10/LL15; LL12/LL13/LL14; then LL04/LL17.

## Reset policy

Use `python scripts/reset_demo_db.py` between learner cohorts or whenever scenario state has been consumed. Challenge-contract tests create isolated databases automatically.
