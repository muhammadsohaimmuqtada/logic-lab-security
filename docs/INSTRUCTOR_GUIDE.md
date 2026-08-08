# Logic Lab Security v3 — Instructor Guide

> **Spoilers.** Do not distribute this file to learners in black-box mode.

Logic Lab uses learner-specific HMAC flags. Exploitation succeeds when the vulnerable workflow returns the current learner's flag; submission and scoring are handled by the challenge engine. The lab actor is tracked separately from the application account so takeover/recovery scenarios can pivot into a victim account without transferring challenge ownership. If recovery is performed before any learner identity exists, LL16 is held pending and bound when the browser establishes its first learner identity at login.

## Existing scenarios

- **LL01 Tenant Enrollment** — registration silently joins an existing organization by name.
- **LL02 Cross-Tenant Export** — the POST export workflow trusts a caller-supplied `org_id`; the route still consumes the caller organization's export quota so LL02 does not create an unrelated LL25 shortcut.
- **LL03 Tenant Parameter Trust** — search trusts an alternate tenant identifier.
- **LL04 Stale Tenant Context** — organization switching does not rotate cached capability context.
- **LL05 Indirect Object Leak** — activity representation lacks the primary object's authorization.
- **LL06 Ownership Transfer** — same-organization membership is treated as authority to transfer ownership. The standard UI only shows ownership controls to the actual owner, so learners must discover/manipulate the backend operation.
- **LL07 Invite Role Escalation** — invite acceptance trusts a caller-supplied role. Invitations remain bound to the intended recipient email.
- **LL08 Invite Lifecycle** — revoked and consumed invitations remain usable by their intended recipient.
- **LL09 State Machine Bypass** — arbitrary service state transitions are accepted.
- **LL10 Approval Integrity** — approved content can be edited without invalidating approval; the normal UI hides post-approval editing.
- **LL11 Checkout Integrity** — checkout trusts a client-supplied price.
- **LL12 Promotion Abuse** — promotions can be stacked and checkout does not consume one-use coupon eligibility. A normal single first-time coupon does not award the challenge.
- **LL13 Referral Economics** — self-referral creates credits.
- **LL14 Refund Replay** — refunds are not idempotent.
- **LL15 Separation of Duties** — creators can approve their own work.
- **LL16 Recovery Proof** — organization knowledge is accepted as account-recovery proof. Existing learner identity remains stable through recovery/takeover. Fresh unauthenticated recovery stores a pending challenge proof until the first learner login establishes attribution.
- **LL17 Redemption Race** — check-then-act coupon redemption is non-atomic.

## v3 expansion

- **LL18 Premium Feature Gate** — the UI hides enterprise reporting, but the direct route has no plan authorization.
- **LL19 Seat Limit Projection** — normal single invites respect current member + pending-invite capacity, while manager/owner bulk invite validates the current total only once and ignores the full projected batch.
- **LL20 Trial Extension Replay** — manager/owner extension eligibility is never consumed; the operation can be repeated.
- **LL21 API Object Authorization** — API service notes do not enforce tenant/object authorization.
- **LL22 API Property Authorization** — the service PATCH endpoint accepts valid security-sensitive properties without property-level authorization. Input/domain validation remains intact so the lesson is authorization rather than state corruption.
- **LL23 Batch Authorization** — only the first service in a batch is authorized; subsequent foreign objects are mutated.
- **LL24 Partner Identity Boundary** — partner enrollment uses a string suffix check instead of an exact email-domain identity.
- **LL25 Alternate Quota Path** — the normal entitlement export and legacy service export enforce the caller's quota while the alternate API export path does not. Quota-consuming exports are POST operations protected by the normal CSRF boundary.

## Scoring

Beginner challenges award 100 points, Intermediate 200, Advanced 350 and Expert 500. Each unlocked hint reduces the eventual award by 25 points, down to 50% of the base value.

## Challenge isolation rule

If a separate endpoint provides an easier route to the same objective without exercising the intended invariant, treat that as a lab-design regression. Either remove the shortcut or promote it into its own explicit challenge with its own success condition and test.

## Classroom operation

For black-box use, deploy the application and distribute only the instance URL, selected seeded credentials and challenge board access. Do not distribute this guide. Authenticated learners can inspect their own `/lab/progress` endpoint.

For central Docker deployments, leave runtime secrets unset unless you supply unique managed values; the application will create distinct persistent installation secrets inside the instance volume. The production image deliberately excludes test suites, instructor material, challenge manifests, development dependencies and repository-only tooling.
