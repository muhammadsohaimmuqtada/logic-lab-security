# Logic Lab Security v3 — Instructor Guide

> **Spoilers.** Do not distribute this file to learners in black-box mode.

Logic Lab uses learner-specific HMAC flags. Exploitation succeeds when the vulnerable workflow returns the current learner's flag; submission and scoring are handled by the challenge engine.

## Existing scenarios

- **LL01 Tenant Enrollment** — registration silently joins an existing organization by name.
- **LL02 Cross-Tenant Export** — export trusts a caller-supplied `org_id`.
- **LL03 Tenant Parameter Trust** — search trusts an alternate tenant identifier.
- **LL04 Stale Tenant Context** — organization switching does not rotate cached capability context.
- **LL05 Indirect Object Leak** — activity representation lacks the primary object's authorization.
- **LL06 Ownership Transfer** — same-organization membership is treated as authority to transfer ownership.
- **LL07 Invite Role Escalation** — invite acceptance trusts a caller-supplied role.
- **LL08 Invite Lifecycle** — revoked and consumed invitations remain usable.
- **LL09 State Machine Bypass** — arbitrary service state transitions are accepted.
- **LL10 Approval Integrity** — approved content can be edited without invalidating approval.
- **LL11 Checkout Integrity** — checkout trusts a client-supplied price.
- **LL12 Promotion Abuse** — promotions stack and checkout does not consume one-use coupons.
- **LL13 Referral Economics** — self-referral creates credits.
- **LL14 Refund Replay** — refunds are not idempotent.
- **LL15 Separation of Duties** — creators can approve their own work.
- **LL16 Recovery Proof** — organization knowledge is accepted as account-recovery proof.
- **LL17 Redemption Race** — check-then-act coupon redemption is non-atomic.

## v3 expansion

- **LL18 Premium Feature Gate** — the UI hides enterprise reporting, but the direct route has no plan authorization.
- **LL19 Seat Limit Projection** — bulk invite checks current active seats once and ignores projected pending seats.
- **LL20 Trial Extension Replay** — extension eligibility is never consumed; the operation can be repeated.
- **LL21 API Object Authorization** — API service notes do not enforce tenant/object authorization.
- **LL22 API Property Authorization** — the service PATCH endpoint accepts security-sensitive properties without property-level authorization.
- **LL23 Batch Authorization** — only the first service in a batch is authorized; subsequent foreign objects are mutated.
- **LL24 Partner Identity Boundary** — partner enrollment uses a string suffix check instead of an exact email-domain identity.
- **LL25 Alternate Quota Path** — the web export route enforces quota while the alternate API export route does not.

## Scoring

Beginner challenges award 100 points, Intermediate 200, Advanced 350 and Expert 500. Each unlocked hint reduces the eventual award by 25 points, down to 50% of the base value.

## Classroom operation

For black-box use, deploy the application and distribute only the instance URL, selected seeded credentials and challenge board access. Do not distribute this guide. Authenticated learners can inspect their own `/lab/progress` endpoint.
