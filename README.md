# Logic Lab Security v2

**Logic Lab Security is intentionally vulnerable.** It is a local training application for learning web business-logic exploitation in a realistic multi-tenant SaaS environment.

The application is not designed around obvious scanner findings. Learners are expected to understand the business model, map roles and state transitions, identify assumptions, and then prove impact.

## Training model

Logic Lab models a security-services SaaS platform with:

- organizations and tenant membership
- owner / manager / member / viewer roles
- collaboration invitations
- private, organization, and public services
- review / approval / publication workflows
- service ownership transfers
- credit-based purchases and promotions
- referrals and refunds
- account recovery
- audit/activity feeds
- tenant switching

The normal UI expresses the *intended* workflow. Several backend assumptions intentionally diverge from that workflow.

## Challenge families

The v2 lab ships with **17 challenge contracts** spanning:

| ID | Theme | Difficulty |
|---|---|---|
| LL01 | Tenant enrollment | Intermediate |
| LL02 | Cross-tenant export | Intermediate |
| LL03 | Tenant parameter trust | Intermediate |
| LL04 | Stale authorization context | Advanced |
| LL05 | Indirect object leakage | Intermediate |
| LL06 | Ownership transfer | Intermediate |
| LL07 | Invite role escalation | Advanced |
| LL08 | Invite lifecycle abuse | Intermediate |
| LL09 | State-machine bypass | Intermediate |
| LL10 | Approval integrity | Advanced |
| LL11 | Checkout integrity | Beginner |
| LL12 | Promotion abuse | Intermediate |
| LL13 | Referral economics | Intermediate |
| LL14 | Refund replay | Intermediate |
| LL15 | Separation of duties | Intermediate |
| LL16 | Account recovery proof | Intermediate |
| LL17 | Concurrency / redemption race | Advanced |

The learner-facing challenge board gives objectives, not exploit steps.

## Safety boundary

The application logic is deliberately flawed, but the lab avoids host-compromise primitives. The project intentionally keeps:

- parameterized SQL
- CSRF protection on state-changing requests
- Jinja auto-escaping
- bounded request size
- loopback-only development/Gunicorn binding
- no shell-command execution feature
- no arbitrary file-read/write challenge

Run it only on a local machine, disposable VM, or isolated classroom network. Do **not** expose it directly to the public internet.

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

All seeded users use the demo password `Password1!`:

| User | Organization / role |
|---|---|
| `alice` | AlphaSec owner |
| `bob` | AlphaSec member |
| `carol` | BetaOps owner |
| `dave` | BetaOps manager |
| `auditor` | AlphaSec viewer + BetaOps viewer |
| `student` | GammaLabs owner |

Reset the lab whenever you want a clean state:

```bash
python scripts/reset_demo_db.py
```

## Docker

```bash
docker compose up --build
```

The compose configuration publishes the lab only on `127.0.0.1:8000`.

## Testing philosophy

The test suite has three layers:

1. **normal-flow tests** — the application must still behave like a coherent SaaS product;
2. **challenge-contract tests** — each intentional flaw must remain reproducible, so a future security refactor cannot silently remove a teaching scenario;
3. **safety-invariant tests** — the project must not drift into host-level execution primitives.

```bash
pytest -q
```

A passing challenge-contract test means the lab scenario is still intentionally exploitable; it is not a claim that the behavior is secure.

## Repository structure

```text
app/
├── __init__.py          application factory
├── app.py               compatibility/run entrypoint
├── auth.py              onboarding, login, recovery
├── commerce.py          checkout, coupons, referrals, refunds, race lab
├── config.py            safe runtime boundary
├── db.py                schema and deterministic demo seed
├── lab.py               challenge catalog and flag validation
├── organizations.py     tenant membership, invites, tenant switching
├── security.py          CSRF, session helpers, roles, audit events
├── services.py          service authorization and workflow logic
├── static/
└── templates/
challenges/manifest.yml  learner challenge metadata
docs/INSTRUCTOR_GUIDE.md spoiler-heavy instructor mapping
tests/                   normal, challenge-contract, and safety tests
```

## Educational intent

Logic Lab is built to teach the difference between:

- authentication and authorization
- object authorization and tenant membership authorization
- UI workflow and server-side state enforcement
- data validation and business-rule validation
- successful transactions and economically valid transactions
- per-request authorization and authorization-context lifecycle
- sequential correctness and concurrent correctness

If you are using the lab as a learner, avoid reading `docs/INSTRUCTOR_GUIDE.md` until you have completed your attempt.

## License

MIT. Intended for authorized education, local testing, classroom exercises, and defensive security research.
