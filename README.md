# Logic Lab Security

[![CI](https://github.com/muhammadsohaimmuqtada/logic-lab-security/actions/workflows/ci.yml/badge.svg)](https://github.com/muhammadsohaimmuqtada/logic-lab-security/actions/workflows/ci.yml)

**Logic Lab Security is an intentionally vulnerable, local-first training platform for web business-logic security.** It models a multi-tenant security-services SaaS product and teaches learners to reason about authorization, workflow, economic, entitlement, identity, API, and concurrency failures rather than rely on scanner-only findings.

> Do not expose this application directly to the public internet. Run it on localhost, in a disposable VM/container, or on an isolated classroom network.

## What the lab teaches

Learners are expected to understand the application before exploiting it:

1. map users, organizations, roles, objects, states, quotas, and APIs;
2. identify the intended business invariant;
3. find where another representation or workflow violates that invariant;
4. demonstrate impact;
5. submit a learner-specific flag.

The standard UI represents the intended product workflow. Deliberate challenge conditions live in server-side assumptions and alternate paths, so the lab does not depend on obvious `/vulnerable` endpoints.

## Current challenge set

The platform currently ships with **25 challenge contracts**:

| Range | Focus |
|---|---|
| LL01–LL05 | multi-tenancy, tenant context, and indirect object representations |
| LL06–LL10 | ownership, invitations, state machines, and approval integrity |
| LL11–LL17 | checkout, promotions, referrals, refunds, recovery, and concurrency |
| LL18–LL20 | subscriptions, premium entitlements, seat limits, and trial lifecycle |
| LL21–LL25 | API object/property authorization, batch operations, identity boundaries, and quota bypass |

Each challenge has a regression test that proves the intended teaching flaw remains reproducible. A passing challenge-contract test means the lab contract still exists; it is not a claim that the challenged behavior is secure.

## Training platform features

- learner-specific HMAC flags;
- persistent server-side progress;
- difficulty-weighted scoring;
- progressive hints with point penalties;
- challenge progress JSON endpoint;
- deterministic seeded organizations, users, services, plans, invitations, orders, and coupons;
- separate web and `/api/v1` business surfaces;
- resettable lab state;
- spoiler-reduced learner bundle with the test suite and instructor materials removed;
- instructor guide and architecture documentation;
- Docker and direct Python/Gunicorn execution;
- separate runtime and development dependency sets;
- CI coverage for Python compilation, regression tests, learner-bundle generation, production-image hygiene, Docker image build, and live container health.

## Flag integrity

Runtime secrets are never intentionally stored as known defaults.

If `FLASK_SECRET_KEY` or `LAB_FLAG_SECRET` is not provided, Logic Lab creates separate cryptographically random values under the instance directory and reuses them for that installation. Docker keeps the instance directory in a named volume, so flags and sessions remain stable across container restarts while remaining unique to the deployment.

For managed classroom deployments, you can still supply explicit long random values through environment variables.

The lab actor is separate from the application account currently in use. Account-recovery and account-takeover workflows can therefore pivot into another account without moving challenge ownership. If recovery is completed before any learner identity has been established, the proof is held pending and bound on first login.

## Quick start

```bash
git clone https://github.com/muhammadsohaimmuqtada/logic-lab-security.git
cd logic-lab-security
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export $(grep -v '^#' .env | xargs)
python app/app.py
```

Open `http://127.0.0.1:8000`.

### Seeded accounts

All seeded users use the demo password `Password1!`.

| Username | Initial context |
|---|---|
| `alice` | AlphaSec owner |
| `bob` | AlphaSec member |
| `carol` | BetaOps owner |
| `dave` | BetaOps manager |
| `auditor` | AlphaSec viewer + BetaOps viewer |
| `student` | GammaLabs owner |

Reset to the deterministic training state:

```bash
python scripts/reset_demo_db.py
```

## Docker

```bash
docker compose up --build
```

The container listens on its internal interface while Compose publishes it only on `127.0.0.1:8000`. The image runs as an unprivileged user, contains only runtime dependencies and runtime application files, and includes a health check.

```bash
docker compose ps
curl http://127.0.0.1:8000/health
```

## Challenge engine

Authenticated learners can open `/lab` to view objectives, scoring, solved state, and progressive hints. Progress is stored server-side.

`/lab/progress` exposes the current learner's progress as JSON for classroom tooling.

The lab tracks a stable learner identity separately from the application account currently being used. This means account-recovery or account-takeover exercises can pivot into another application account without transferring challenge ownership to the victim account.

## Learner and instructor modes

The public repository supports white-box study.

For a black-box classroom exercise, deploy the application centrally and give learners only the URL, selected credentials, and challenge objectives.

A spoiler-reduced bundle can be generated with:

```bash
python scripts/build_learner_bundle.py
```

The generated archive excludes the instructor guide, internal challenge manifest, and the complete test suite. Because application source is still included, this is intentionally described as **spoiler-reduced**, not source-secret or tamper-proof.

## HTTP and safety model

State-changing operations use POST/PATCH and pass through the global CSRF guard. This includes quota-consuming export generation: although the response is an export, generating it changes persistent quota usage and is therefore modeled as a mutation rather than a GET request.

The application is intentionally weak at selected **business-logic** boundaries while retaining guardrails around the host/runtime boundary. The project intentionally keeps:

- parameterized SQL for user-provided values;
- normal domain validation around intentionally weak authorization decisions;
- CSRF checks on state-changing HTTP methods;
- Jinja auto-escaping;
- request-size limits;
- HTTPOnly and SameSite session-cookie defaults;
- loopback-only host publication;
- an unprivileged container user;
- no shell-command execution challenge;
- no arbitrary host file-read/write challenge.

See [SECURITY.md](SECURITY.md) for what should be treated as an actual project security defect.

## Testing

Install the development/test dependency set and run the complete suite:

```bash
python -m pip install -r requirements-dev.txt
python -m pip check
pytest -q
```

The tests are organized into four layers:

1. **normal flows** — ordinary product behavior remains coherent;
2. **challenge contracts** — intended vulnerabilities remain exploitable in the required way;
3. **platform/integrity regressions** — flags, scoring, challenge isolation, authorization boundaries, malformed input, protocol semantics, quotas, and learner packaging behave correctly;
4. **safety invariants** — the training app does not drift toward host-command execution or unsafe network exposure.

GitHub Actions additionally verifies the spoiler-reduced learner bundle, builds the production image, asserts that development/test material is absent from that image, checks the unprivileged runtime UID, boots Gunicorn with two workers, and verifies the live `/health` endpoint.

## Repository structure

```text
app/
├── __init__.py          Flask application factory
├── app.py               direct/Gunicorn entrypoint
├── api.py               API business flows and domain validation
├── auth.py              registration, login, recovery, learner attribution
├── commerce.py          checkout, coupons, referrals, refunds, races
├── config.py            runtime configuration and installation secrets
├── db.py                schema, migrations, deterministic seed state
├── entitlements.py      plans, quotas, seats, trials
├── lab.py               challenge catalog, flags, scoring, hints, progress
├── organizations.py     memberships, invites, tenant switching
├── security.py          CSRF, roles, parsing helpers, audit events
├── services.py          service authorization and workflow logic
├── static/
└── templates/
challenges/manifest.yml  internal challenge inventory
docs/ARCHITECTURE.md     architecture and challenge-contract boundaries
docs/INSTRUCTOR_GUIDE.md instructor spoilers and challenge mapping
scripts/                  reset and learner-bundle tooling
tests/                    product, challenge, platform, integrity, and safety tests
requirements.txt          runtime dependencies
requirements-dev.txt      test/development dependencies
```

## Contributing

Challenge additions must preserve a coherent product story and the runtime safety boundary. New challenges should include a business invariant, a non-obvious violation, an exploitability regression test, normal-flow coverage, learner-facing objective text, and instructor documentation.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Intended for authorized education, local testing, classroom exercises, and defensive security research.
