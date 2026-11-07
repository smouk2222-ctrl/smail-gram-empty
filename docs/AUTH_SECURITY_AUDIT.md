# Authentication security review

This is a source-level review, not a penetration test. Findings below describe behavior observed in this branch and identify items that need an explicit design decision before a public deployment.

## Controls observed

- Login-code records are bound to the normalized phone/email identity and the account owner observed at issuance. Verification checks ownership before and after the atomic code-store verification.
- Login codes have a configured TTL and maximum-attempt count. The RPC layer also has phone- and connection-scoped rate-limit configuration for unauthenticated code issuance.
- Two-step verification uses a `password_pending` authorization state. Normal authenticated-user lookup rejects that state until the password check completes.
- Authorization revocation removes the authorization, invalidates router caches, closes active sessions, and clears associated update state.
- Passkey login verifies the credential before binding an authorization.

## Items requiring follow-up

### 1. Development login code must never be exposed

The default phone-code provider is `development`, with fixed code `12345` accepted for every phone number. This is suitable only for isolated local testing. A public deployment must configure a real delivery provider and a strong secret for its delivery endpoint before exposing login.

### 2. Exported authorization token replay window

`internal/rpc/auth.go` signs an export token containing only the user ID and a five-minute expiry. The import path verifies the HMAC and expiry, then binds the receiving connection. The token is not visibly consumed or tracked as one-time in this handler.

Before relying on this flow in a public deployment, confirm the intended MTProto compatibility semantics and decide whether replay within the five-minute window is acceptable. If not, add a bounded, concurrency-safe one-time-use mechanism and tests for concurrent/repeated imports. Do not shorten the TTL or change semantics without client compatibility tests.

### 3. auth.dropTempAuthKeys currently acknowledges without dropping keys

The registered handler for `auth.dropTempAuthKeys` currently ignores `except_auth_keys` and returns `true`. This is a protocol-compatibility gap: callers are told the request succeeded, but the handler does not perform the requested cleanup. Review the temp-key lifecycle and implement the expected behavior with tests, or explicitly document the method as unsupported rather than silently acknowledging a no-op.

### 4. Admin-panel login has no application-level rate limit

`POST /api/login` is registered directly to `handleAPILogin`. The handler performs password authentication (including bcrypt work and a dummy hash for unknown usernames), but the route and login handler contain no attempt counter, cooldown, or IP/account rate limiter. The main HTTP server also does not wrap the mux in a login-specific limiter.

This is a confirmed source-level gap, not proof that a particular deployment is currently exploitable: a reverse proxy or firewall may add throttling outside this process. Implemented on this branch: a bounded, concurrency-safe in-process limiter counts attempts by source IP and by IP+normalized username. It returns HTTP 429 with Retry-After after 20 attempts per IP or 5 attempts per IP/username in a 15-minute window. It uses RemoteAddr only and deliberately does not trust arbitrary X-Forwarded-For headers. This is process-local; multi-replica deployments still need proxy-level rate limiting. Avoid permanent account lockouts that let an attacker deny service to an operator.

### 5. Admin session cookies do not set the Secure attribute

The session cookie and readable CSRF cookie are created without `Secure: true`; the clear-cookie helpers omit it too. If the panel is published on a hostname that is also reachable over plain HTTP, browsers may send the session cookie over that connection. A TLS reverse proxy alone does not automatically add the attribute.

Implemented on this branch: both cookies now set Secure automatically for direct TLS requests, or when `TELESRV_ADMIN_UI_COOKIE_SECURE=true` is configured (required when TLS terminates at a reverse proxy). The default remains false for the loopback plain-HTTP development setup; set it to true for any HTTPS deployment. The session cookie is HttpOnly and SameSite=Lax; the CSRF cookie is intentionally readable by the panel script.

### 6. Admin-panel accounts have no second factor or self-service recovery path in the login flow

The observed panel login accepts a username plus password for named operators, or the configured break-glass password/token. The login handler does not require TOTP, passkey, or another second factor. The operator-management API can reset another operator's password, but no self-service recovery flow is present in these files.

For a public or internet-reachable admin panel, require MFA for named operators and keep the break-glass credential offline/strongly protected. Document that loss of all operator credentials requires out-of-band recovery by the server owner; do not imply that end-user Telegram 2FA/passkeys automatically protect the separate admin console.

## Deployment checklist

- Replace development OTP with a real delivery provider; validate webhook authentication, TLS, timeouts, and secret rotation.
- Set the correct passkey RP ID and allowed origins for the deployment's own domain.
- Keep the Admin UI on loopback or behind a hardened HTTPS reverse proxy and additional access control.
- Use unique administrator credentials and a strong session key; keep all secrets and recovery material outside Git.
- Test login, 2FA, passkey, session revocation, password recovery, and account deletion against a non-production database before opening registration.
- Run the complete Go test suite and review all CI results before merging.

