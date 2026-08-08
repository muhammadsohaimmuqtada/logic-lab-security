# Logic Lab Security v3

**Logic Lab Security is intentionally vulnerable.** It is a local training platform for learning web business-logic exploitation in a realistic multi-tenant SaaS environment.

The application is not designed around obvious scanner findings. Learners are expected to understand the business model, map roles, state transitions, entitlements and API surfaces, identify assumptions, and prove impact.

## What changed in v3

Logic Lab now behaves like a training platform rather than a collection of vulnerable routes:

- **25 challenge contracts** across tenancy, identity, workflow, commerce, concurrency, subscriptions and APIs;
- learner-specific HMAC flags generated from an installation secret;
- server-side persistent challenge progress;
- point values by difficulty;
- optional hints with point penalties;
- a JSON progress endpoint for classroom tooling;
- subscription, quota and seat-limit workflows;
- a parallel `/api/v1` surface with business-logic authorization scenarios;
- challenge-contract tests that deliberately prove the teaching flaws remain exploitable;
- safety-invariant tests that keep host-compromise primitives out of scope.

## Challenge families

| Range | Focus |
|---|---|
| LL01–LL05 | multi-tenancy and object representations |
| LL06–LL10 | ownership, invitations and state machines |
| LL11–LL17 | commerce, recovery and concurrency |
| LL18–LL20 | subscription entitlements and quotas |
| LL21–LL25 | API authorization, identity boundaries and sensitive business-flow abuse |

The learner-facing challenge board gives objectives and optional progressive hints, never exploit steps.

## Dynamic flags

Flags are not stored as static strings in source. They are derived from the installation flag secret, challenge id and learner user id. Set a unique `LAB_FLAG_SECRET` for each deployed instance. A flag copied from another learner or deployment will not validate.

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

All seeded users use `Password1!`: `alice`, `bob`, `carol`, `dave`, `auditor`, and `student`.

Reset the lab with `python scripts/reset_demo_db.py`.

## Docker

```bash
docker compose up --build
```

Compose publishes only on `127.0.0.1:8000`.

## Learner vs instructor use

The public repository supports white-box study. For black-box classroom use, instructors should deploy the Docker instance and give learners only the URL, seeded credentials and challenge objectives.

A spoiler-reduced learner bundle can be produced with:

```bash
python scripts/build_learner_bundle.py
```

The bundle omits instructor spoilers, challenge-contract exploit tests and the internal challenge manifest. Dynamic flags still prevent copied flags from validating for another learner.

## Testing philosophy

The suite has four layers: normal product flows, platform-engine behavior, challenge-contract exploitability, and safety invariants.

```bash
pytest -q
```

A passing challenge-contract test means the scenario is intentionally exploitable; it is not a security claim.

## Safety boundary

The lab intentionally keeps parameterized SQL, Jinja auto-escaping, request-size limits and CSRF protection for all state-changing HTTP methods. It contains no shell-command execution feature or arbitrary host-file read/write challenge.

Run only on localhost, a disposable VM/container, or an isolated classroom network. Do not expose it directly to the public internet.

## License

MIT. Intended for authorized education, local testing, classroom exercises and defensive security research.
