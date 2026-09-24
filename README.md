# Gatehouse — Secure PHP Authentication Demo

[![Quality](https://github.com/kooroosh1363/first-login-form/actions/workflows/quality.yml/badge.svg)](https://github.com/kooroosh1363/first-login-form/actions/workflows/quality.yml)

Gatehouse modernizes the repository's original 2023 static login-form exercise into a small, real server-side authentication application. It keeps the scope deliberately compact while demonstrating the security and engineering concerns that a visual login form alone does not address.

## Modernization summary

The original project was a generated HTML/CSS login design with no authentication backend. The modernized version replaces the mock interaction with:

- real users stored in SQLite
- password hashing with PHP's `password_hash()` / `password_verify()` APIs
- prepared PDO queries
- CSRF protection for sign-in and sign-out
- session ID rotation after authentication and periodically during active sessions
- 30-minute inactivity expiration
- generic credential errors to reduce account-enumeration leakage
- timing work for unknown users through a dummy password hash
- temporary throttling after repeated failed attempts
- Post/Redirect/Get after sign-in errors
- secure response and session-cookie settings
- a protected dashboard and POST-only logout
- responsive, accessible light/dark UI
- CLI-only user provisioning with no default credentials in Git
- automated PHP lint and SQLite-backed tests

The 2023 implementation remains available in Git history, so the repository shows an explicit progression from a frontend exercise to a security-minded server application.

## Security model

### Passwords

Passwords are never stored as plaintext. `UserRepository` persists only the result of `password_hash(..., PASSWORD_DEFAULT)`. Successful authentication uses `password_verify()`, and a valid login automatically rehashes the password when PHP's recommended parameters change.

### Session security

- strict session mode
- HttpOnly cookies
- SameSite=Lax cookies
- Secure cookies when HTTPS is active
- session ID regeneration immediately after login
- periodic session ID regeneration
- 30-minute inactivity expiration

### Request integrity

Both login and logout require a cryptographically random, session-bound CSRF token. Login also contains a simple honeypot field for low-cost automated spam rejection.

### Login throttling

Five failed attempts for the same normalized email identifier inside a five-minute window trigger a five-minute lock. Attempt records store a SHA-256 email key rather than the submitted email itself.

This is intentionally simple for a portfolio project. A larger production system would normally combine account, IP/network, device, and centralized rate-limit signals without allowing an attacker to easily denial-of-service a single account.

## Architecture

```text
Browser
  │
  ├── GET /
  ├── POST /
  └── POST /logout.php
       │
       ▼
public entry points
       │
       ├── LoginValidator
       ├── CSRF/session helpers
       └── AuthService
              │
              ├── timing-safe lookup
              ├── throttle policy
              └── UserRepository
                      │
                      ▼
                  SQLite DB
                      │
                      ▼
Authenticated session ──► dashboard.php
```

## Project structure

```text
.
├── bin/
│   └── create-user.php
├── public/
│   ├── index.php
│   ├── dashboard.php
│   ├── logout.php
│   └── assets/app.css
├── src/
│   ├── AuthService.php
│   ├── bootstrap.php
│   ├── helpers.php
│   ├── LoginValidator.php
│   └── UserRepository.php
├── storage/
│   └── .gitkeep
├── tests/
│   └── run.php
└── .github/workflows/
    └── quality.yml
```

## Requirements

- PHP 8.1+
- PDO SQLite
- `mbstring` recommended

## Run locally

```bash
php -S localhost:8000 -t public
```

The database is created automatically at `storage/auth.sqlite` and is ignored by Git.

## Create a user

No demo password is committed to this repository. Provision a local account from the CLI:

```bash
php bin/create-user.php user@example.com 'correct-horse-battery-staple'
```

Provisioning requires a password of at least 12 characters. The command stores only a password hash.

Then open:

```text
http://localhost:8000
```

## Test

```bash
php tests/run.php
```

Lint every PHP file:

```bash
find public src bin tests -name '*.php' -print0 | xargs -0 -n1 php -l
```

GitHub Actions runs both checks on pull requests and pushes to `main` using PHP 8.3 with `pdo_sqlite` and `mbstring`.

## What the tests cover

- login input normalization
- invalid email/password/honeypot handling
- provisioning password policy
- password hashing instead of plaintext storage
- case-insensitive account lookup
- valid and invalid credential behavior
- repeated-failure throttling
- lock expiry and successful authentication afterward

## Accessibility and UX

- semantic labels and landmarks
- `type="password"` and correct autocomplete tokens
- visible keyboard focus
- field-level errors connected with `aria-describedby`
- skip link
- responsive layouts
- reduced-motion behavior
- automatic light/dark color scheme
- no JavaScript dependency for the authentication path

## Trade-offs

Gatehouse is intentionally a focused authentication demo, not a complete identity platform. It does not implement self-registration, email verification, password reset, MFA, OAuth/OIDC, recovery codes, audit-log retention, or horizontally distributed rate limiting.

Those features would require additional security decisions and operational infrastructure. Keeping them out of scope makes the repository easier to review while allowing the implemented controls to remain explicit.

## Deployment

GitHub Pages cannot execute PHP. Run Gatehouse on a PHP-capable host with the web server document root pointing to `public/`. The `storage/` directory should remain outside the public document root and writable by the PHP process.

Production deployment should also use HTTPS and environment-specific filesystem/database permissions.

## Roadmap

Reasonable next steps if the product scope expands:

- password reset with single-use expiring tokens
- MFA / WebAuthn
- admin-managed account lifecycle
- centralized or Redis-backed rate limiting
- structured security audit events
- versioned database migrations
- PHPUnit/PHPStan once dependency management is justified

## License

No license is currently included. Add one before redistributing the code as reusable software.
