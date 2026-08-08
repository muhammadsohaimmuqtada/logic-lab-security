# Logic Lab Security v3

**Logic Lab Security is intentionally vulnerable.** It is a local training platform for learning web business-logic exploitation in a realistic multi-tenant SaaS environment.

The application is not designed around obvious scanner findings. Learners are expected to understand the business model, map roles, state transitions, entitlements and API surfaces, identify assumptions, and prove impact.

## Platform model

Logic Lab currently provides:

- **25 challenge contracts** across tenancy, identity, workflow, commerce, concurrency, subscriptions and APIs;
- learner-specific HMAC flags generated from an installation secret;
- server-side persistent challenge progress;
- point values by difficulty;
- optional hints with point penalties;
- a JSON progress endpoint for classroom tooling;
- subscription, quota and seat-limit workflows;
- a parallel `/api/v1` surface with business-logic authorization scenarios;
- positive exploit-contract tests and negative legitimate-flow boundary tests;
- safety-invariant tests that keep host-compromise primitives out of scope.

## Challenge families

| Range | Focus |
|---|---|
| LL01–LL05 | multi-tenancy and object representations |
| LL06–LL10 | ownership, invitations and state machines |
| LL11–LL17 | commerce, recovery and concurrency |
| LL18–LL20 | subscription entitlements and quotas |
| LL21–LL25 | API authorization, identity boundaries and sensitive business-flow abuse |

The learner-facing challenge board gives objectives and optional progressive hints, never exploit steps. Challenge markers are issued only when the corresponding business invariant is actually violated; ordinary authorized use should not solve a challenge.

## Dynamic flags and instance secrets

Flags are derived from the installation flag secret, challenge id and learner user id. A flag copied from another learner or deployment will not validate.

If `FLASK_SECRET_KEY` or `LAB_FLAG_SECRET` is unset or blank, Logic Lab generates a cryptographically random value and persists it beside the database with owner-only permissions. Explicit environment values override the generated secrets. Do not use public or shared secret values for classroom deployments.

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

Reset the lab with:

```bash
python scripts/reset_demo_db.py
```

## Docker

```bash
docker compose up --build
```

The container listens on its internal interface while Compose publishes it only on host loopback at `127.0.0.1:8000`. Flask and flag secrets are generated automatically in the persistent instance volume unless explicitly supplied.

## Learner vs instructor use

The public repository supports white-box study. For black-box classroom use, instructors should deploy the application and give learners only the instance URL, selected seeded credentials and challenge objectives.

A spoiler-reduced learner bundle can be produced with:

```bash
python scripts/build_learner_bundle.py
```

The bundle omits instructor spoilers, challenge-contract exploit tests and the internal challenge manifest. For strict black-box exercises, deploy centrally rather than distributing source.

## Testing philosophy

The suite covers:

1. normal product flows;
2. platform-engine behavior;
3. intended challenge exploitability;
4. legitimate-flow challenge boundaries;
5. safety invariants;
6. release-path smoke checks for Gunicorn, Docker and learner packaging in CI.

```bash
pytest -q
```

A passing exploit-contract test means the scenario remains intentionally exploitable; it is not a security claim. A passing boundary test means legitimate behavior does not accidentally award the same challenge.

## Safety boundary

The lab intentionally keeps parameterized SQL, Jinja auto-escaping, request-size limits and CSRF protection for all state-changing HTTP methods. It contains no shell-command execution feature or arbitrary host-file read/write challenge.

Run only on localhost, a disposable VM/container, or an isolated classroom network. Do not expose it directly to the public internet.

## License

MIT. Intended for authorized education, local testing, classroom exercises and defensive security research.
