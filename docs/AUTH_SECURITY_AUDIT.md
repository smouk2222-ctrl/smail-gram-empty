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

## Deployment checklist

- Replace development OTP with a real delivery provider; validate webhook authentication, TLS, timeouts, and secret rotation.
- Set the correct passkey RP ID and allowed origins for the deployment's own domain.
- Keep the Admin UI on loopback or behind a hardened HTTPS reverse proxy and additional access control.
- Use unique administrator credentials and a strong session key; keep all secrets and recovery material outside Git.
- Test login, 2FA, passkey, session revocation, password recovery, and account deletion against a non-production database before opening registration.
- Run the complete Go test suite and review all CI results before merging.

