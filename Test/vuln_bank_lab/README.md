# Vulnerable Banking Lab

This folder contains a mock, local-only banking-style web app that is intentionally vulnerable for scanner and security testing.

It uses fake data only. Do not expose it to the internet or connect real accounts or credentials to it.

## What it includes

- SQLite database with seeded fake users, accounts, transactions, and support tickets
- Login flow with SQL injection
- Search endpoint with reflected SQL injection and XSS exposure
- Stored XSS in support tickets
- IDOR in account and profile views
- Path traversal in statement downloads
- SSRF in the remote fetch endpoint
- Open redirect endpoint
- XXE-style XML import vulnerability
- Insecure deserialization endpoint
- Command injection in the admin console
- Broken access control in admin tooling
- Missing security headers and unsafe CORS configuration
- Hardcoded admin unlock token for test purposes only

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open:

- `http://127.0.0.1:5001/`
- `http://127.0.0.1:5001/login`

## Test credentials

- `aarav.mehta@example.test` / `Aarav123!`
- `naina.shah@example.test` / `Naina123!`
- `kabir.rao@example.test` / `Kabir123!`
- `meera.iyer@example.test` / `Meera123!`
- `admin@example.test` / `Admin123!`

## Scanner targets

This lab is designed to trigger findings for:

- SQL Injection
- Reflected XSS
- Stored XSS
- SSRF
- Path Traversal
- IDOR
- Open Redirect
- XXE
- Insecure Deserialization
- Command Injection
- Broken Authentication and Access Control
- Hardcoded Secret exposure
- Missing Security Headers
- CORS misconfiguration

## Notes

- The app binds to `127.0.0.1` only.
- It is intentionally insecure and should only be used as a local test target.
- The database is recreated with fake seed data on first run.
