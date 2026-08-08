# Architecture

Logic Lab Security is a deliberately vulnerable business-logic training platform with a deliberately narrow safety boundary: application workflows may violate selected business invariants, but the runtime should remain unsuitable for host compromise.

## Request flow

```text
Browser / API client
        |
        v
Flask application factory
        |
        +--> global CSRF + response security headers
        |
        +--> auth / organizations / services / commerce / entitlements / API
        |
        +--> challenge engine (flags, hints, scoring, progress)
        |
        v
SQLite training state
```

## Identity model

Two identities are intentionally separated:

- **application user** (`session.user_id`) — the account currently operating inside the simulated SaaS product;
- **lab actor** (`session.lab_actor_id`) — the learner whose flags, hints, and progress are being scored.

This allows account-recovery and takeover exercises to pivot into another application account without moving the learner's score to the victim account.

## Challenge contract

Every challenge must define:

1. the business invariant that should hold;
2. the intentionally vulnerable server-side assumption;
3. the exact success condition that releases a learner-scoped flag;
4. normal product behavior around the vulnerable workflow;
5. an exploitability regression test;
6. safety invariants proving the challenge does not require host compromise.

Unrelated flaws that provide an easier route to the same objective are treated as lab-design bugs and should either be removed or promoted into their own explicit challenge.

## Data model

The SQLite schema models:

- organizations and memberships;
- users and active tenant context;
- services and workflow state;
- invitations;
- activities/audit-adjacent representations;
- subscriptions and feature usage;
- orders, coupons, referrals, and refunds;
- challenge progress and hint usage.

Schema creation is idempotent. Demo seeding is protected by a SQLite `BEGIN IMMEDIATE` transaction so multiple application workers cannot race on a fresh database.

## Flag model

Flags are derived with HMAC-SHA256 from:

```text
installation flag secret + challenge id + lab actor id
```

The installation flag secret is distinct from the Flask session secret. If explicit secrets are not configured, `app/config.py` creates separate random secret files in the instance directory and reuses them for that installation.

## Deployment boundary

Direct Python and default Gunicorn execution bind to loopback. In Docker, Gunicorn binds to the container interface while Compose publishes the service only on host loopback.

The container runs as an unprivileged user and the CI pipeline boots the built image and checks `/health` over the published port.

## Testing layers

- `test_normal_flows.py` — normal application behavior;
- `test_challenge_contracts.py` — LL01–LL17 exploit contracts;
- `test_expansion_contracts.py` — LL18–LL25 exploit contracts;
- `test_platform_engine.py` — flags, progress, hints, scoring;
- `test_integrity_regressions.py` — challenge isolation and audited regressions;
- `test_safety_invariants.py` — runtime safety boundaries.

A challenge test passing means the intended flaw still exists. A safety/integrity test passing means surrounding accidental behavior has not weakened the educational contract or host boundary.
