# Logic Lab Security

[![CI](https://github.com/muhammadsohaimmuqtada/logic-lab-security/actions/workflows/ci.yml/badge.svg)](https://github.com/muhammadsohaimmuqtada/logic-lab-security/actions/workflows/ci.yml)

A security-focused Flask lab application demonstrating multi-tenant business logic hardening for a service marketplace. Built as a LinkedIn-portfolio piece covering OWASP Top-10 threat categories.

---

## What this project demonstrates

- Multi-tenant visibility policy (`private`, `org`, `public`)
- Owner-only mutation policy (edit/delete/list/unlist)
- CSRF protection on **all** POST routes (blanket `before_request` hook)
- Server-side input validation and normalization
- SQL injection prevention via parameterized queries throughout
- Rate-limiting and progressive login throttle
- IP-ban system with admin override
- Log injection hardening (`_safe_log_value` sanitisation)
- Configurable reverse-proxy trust for `X-Forwarded-For`
- Startup warning when admin password is left at insecure default

---

## Threat Model

| Attack Vector | Defense Implemented | Code Location |
|---|---|---|
| CSRF / state-change forgery | Blanket `csrf_protect_all_posts()` before-request hook | `app/app.py` |
| Horizontal privilege escalation (IDOR) | `can_modify_service_row()` enforces owner-only writes | `app/app.py` |
| Broken object-level auth | `can_view_service_row()` checks visibility + org membership | `app/app.py` |
| Brute-force / credential stuffing | `too_many_failures()` rate-limits by IP; progressive sleep | `app/app.py` |
| Log injection / forgery | `_safe_log_value()` strips `\n`, `\r`, `|` from all log fields | `app/app.py` |
| IP spoofing via X-Forwarded-For | `TRUST_PROXY` flag; defaults OFF (falls back to `remote_addr`) | `app/app.py` |
| Insecure default credentials | Startup `warnings.warn()` if `ADMIN_PASSWORD` not overridden | `app/app.py` |
| Enum / input tampering | `normalize_visibility()`, `normalize_username()`, `validate_password_basic()` | `app/app.py` |
| Privilege escalation to admin | `admin_required` decorator checks `is_admin` from DB | `app/app.py` |

---

## Security Architecture

```
Browser / Client
       │
       ▼
  [nginx / reverse proxy]  ← sets X-Forwarded-For only when TRUST_PROXY=1
       │
       ▼
  [Gunicorn workers]
       │
       ├─ before_request: ban_gate()          ← IP ban check (every request)
       ├─ before_request: csrf_protect_all_posts()  ← CSRF on all POSTs
       │
       ▼
  [Route handler]
       ├─ @login_required                     ← session check
       ├─ @admin_required                     ← is_admin DB check
       ├─ Input validation / normalization
       ├─ can_view_service_row()              ← visibility + org policy
       └─ can_modify_service_row()            ← owner-only mutations
```

---

## OWASP Coverage

| OWASP A-Category | Coverage |
|---|---|
| A01 Broken Access Control | IDOR protection, visibility policy, admin guard |
| A03 Injection | Parameterized SQL throughout; log injection sanitisation |
| A04 Insecure Design | Threat-modelled multi-tenant visibility & mutation model |
| A05 Security Misconfiguration | Startup warning for default credentials; `TRUST_PROXY` flag |
| A07 Identification & Auth Failures | Rate limiting, session rotation on login, CSRF |

---

## Project Structure

```
logic-lab-security/
├── app/
│   ├── app.py            # Main Flask application (all logic)
│   ├── static/           # CSS / JS assets
│   └── templates/        # Jinja2 HTML templates
├── tests/
│   ├── conftest.py       # Pytest fixtures (per-test isolated DB)
│   └── test_policy_smoke.py  # 14 security smoke tests
├── .github/
│   └── workflows/
│       └── ci.yml        # GitHub Actions CI (Python 3.11, pytest)
├── .env.example          # Environment variable template
├── gunicorn.conf.py      # Gunicorn configuration
├── requirements.txt      # Python dependencies
└── README.md
```

---

## Quick Start

```bash
# 1. Clone and enter the directory
git clone https://github.com/muhammadsohaimmuqtada/logic-lab-security.git
cd logic-lab-security

# 2. Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env – set FLASK_SECRET_KEY, ADMIN_PASSWORD, and DATABASE_PATH

# 4. Run the development server
export $(cat .env | xargs)
python app/app.py
# or via gunicorn:
# gunicorn -c gunicorn.conf.py app.app:app
```

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

All tests use an isolated per-test SQLite database (no shared state, no external services required).

### What the test suite covers

| Test | Category |
|---|---|
| `test_idor_user_b_cannot_edit_user_a_service` | IDOR / Horizontal access |
| `test_idor_user_b_cannot_delete_user_a_service` | IDOR / Horizontal access |
| `test_private_service_not_visible_to_other_user` | Visibility enforcement |
| `test_org_service_visible_within_same_org` | Visibility enforcement |
| `test_org_service_not_visible_to_different_org` | Visibility enforcement |
| `test_public_service_visible_to_all` | Visibility enforcement |
| `test_post_without_csrf_returns_403` | CSRF rejection |
| `test_same_org_peer_cannot_modify_org_service` | Owner-only mutation policy |
| `test_rate_limit_after_max_failed_logins` | Rate limiting |
| `test_invalid_visibility_rejected` | Input validation |
| `test_username_with_special_chars_rejected` | Input validation |
| `test_too_short_password_rejected` | Input validation |
| `test_non_admin_cannot_access_admin_routes` | Admin access control |
| `test_unauthenticated_user_redirected_from_admin` | Admin access control |

---

## Core security design

### Visibility model
- `public` → visible to everyone (logged-in users)
- `org` → visible to users in the same organization only
- `private` → visible only to the owner

### Mutation model
- Edit / Delete / List / Unlist actions are **owner-only**
- Same-org users can *view* `org` items but **cannot** modify them

---

## Tech stack
- Flask 3.x
- Gunicorn
- nginx (production)
- SQLite (WAL mode)
- Jinja2

---

## Notes
This is a lab / portfolio project focused on secure application design and authorization logic. Do not run with default credentials in any environment accessible from the internet.

Suggested repository topics: `flask` · `security` · `web-security` · `authorization` · `csrf-protection` · `multi-tenant` · `python` · `owasp`

