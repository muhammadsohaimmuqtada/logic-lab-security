# Logic Lab Portfolio Project

A security-focused Flask lab application demonstrating business logic hardening for a multi-tenant service marketplace.

## What this project demonstrates

- Multi-tenant visibility policy (`private`, `org`, `public`)
- Owner-only mutation policy (edit/delete/list/unlist)
- CSRF protection on POST routes
- Server-side input validation and normalization
- SQLite-backed application logic
- Threat-oriented testing mindset (horizontal access, enum tampering, invalid inputs)

## Core security design

### Visibility model
- `public` → visible to everyone
- `org` → visible to users in the same organization
- `private` → visible only to the owner

### Mutation model
- Edit/Delete/List/Unlist actions are owner-only
- Same-org users can view `org` items but cannot modify them

## Tech stack
- Flask
- Gunicorn
- nginx
- SQLite
- Jinja2

## Local setup
1. Create a virtual environment
2. Install dependencies from `requirements.txt`
3. Configure environment variables (see `.env.example`)
4. Start the app behind Gunicorn/nginx (or run Flask directly for development)

## Notes
This is a local lab / portfolio project focused on secure application design and authorization logic.
