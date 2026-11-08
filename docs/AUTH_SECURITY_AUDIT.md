# Authentication security review

This is a source-level review, not a penetration test. Findings below describe behavior observed in this branch and identify items that need an explicit design decision before a public deployment.

## Controls observed

- Login-code records are bound to the normalized phone/email identity and the account owner observed at issuance. Verification checks ownership before and after the atomic code-store verification.
- Login codes have a configured TTL and maximum-attempt count. The RPC layer also has phone- and connection-scoped rate-limit configuration for unauthenticated code issuance.
- Two-step verification uses a `password_pending` authorization state. Normal authenticated-user lookup rejects that state until the password check completes.
- Authorization revocation removes the authorization, invalidates router caches, closes active sessions, and clears associated update state.
- Passkey login verifies the credential before binding an authorization.
- Admin-panel login attempts are rate-limited in-process on this branch: 5 attempts per IP+username and 20 per IP per 15-minute window. The limiter is bounded and concurrency-safe; it trusts `RemoteAddr`, not arbitrary forwarding headers.
- Admin session and CSRF cookies set `Secure` for direct TLS or when `TELESRV_ADMIN_UI_COOKIE_SECURE=true` is configured for TLS-terminating proxies.

## Items requiring follow-up

### 1. Development login code must never be exposed

The default phone-code provider is `development`, with fixed code `12345` accepted for every phone number. This is suitable only for isolated local testing. A public deployment must configure a real delivery provider and a strong secret for its delivery endpoint before exposing login.

### 2. Exported authorization token lifetime and replay protection

`internal/rpc/auth.go` signs an export token containing the user ID and a five-minute expiry. The expiry is encoded at nanosecond precision and covered by HMAC-SHA256. Import consumes the token's SHA-256 digest in a mutex-protected, bounded in-memory replay cache (262,144 entries); only the first import succeeds, including when imports race concurrently. Expired entries are pruned during consumption, and a full cache fails closed rather than accepting an untracked token.

This protection is process-local and is lost on restart. The signing secret is also generated per process. The current deployment model assumes all advertised DC IDs alias the same server process, so export and import reach that process; a restart requires the client to export again. Do not spread export/import across independent processes or replicas without replacing both the signing-key and replay-cache assumptions with a shared, atomic design. Keep the five-minute compatibility window unless client tests justify changing it.

### 3. auth.dropTempAuthKeys currently acknowledges without dropping keys

The registered handler for `auth.dropTempAuthKeys` currently ignores `except_auth_keys` and returns `true`. This is a protocol-compatibility gap: callers are told the request succeeded, but the handler does not perform the requested cleanup.

The storage model makes a naive implementation unsafe:

- `auth_keys.expires_at = 0` identifies permanent keys; a positive value identifies temporary keys; `-1` is a migration-only legacy/unknown value that the edge rejects. The protocol key row is the authoritative source of this classification.
- `temp_auth_key_bindings` records only a temporary-to-permanent binding. A temporary key that has not yet been bound has no user/owner relationship in the current schema.
- `AuthKeyStore.Delete` is a physical-key destruction primitive. For a permanent key it also deletes every temporary key bound to that permanent key and associated update state. It is not a suitable implementation of a request that merely drops selected temporary keys.
- Physical deletion must be coordinated with active raw sessions and the activation/revalidation fence. Deleting rows based only on `expires_at` or a guessed current-user association could terminate another user's unbound handshake or race a connection becoming active.

Therefore this handler is deliberately left unchanged pending a protocol-scope decision. Before implementing it, verify the exact MTProto semantics for the calling authorization, define how unbound temporary keys are associated with that caller (or prove the operation is intentionally global), add a store operation with an explicit except-list and transaction/locking guarantees, fence and close only the targeted raw sessions, and test concurrent activation, binding, deletion, and cross-user isolation. Until then, returning `true` is misleading and should be treated as a known compatibility defect—not as completed cleanup.

### 4. Admin login limiter deployment boundary

The implemented limiter is process-local. It returns HTTP 429 with Retry-After after 20 attempts per IP or 5 attempts per IP/username in a 15-minute window. It deliberately does not trust arbitrary `X-Forwarded-For` headers. Multi-replica deployments still need equivalent proxy-level rate limiting; ensure the reverse proxy is configured to preserve a trustworthy client address before relying on IP-based limits.

### 5. Admin cookie deployment configuration

Both cookies set Secure automatically for direct TLS requests, or when `TELESRV_ADMIN_UI_COOKIE_SECURE=true` is configured (required when TLS terminates at a reverse proxy). The default remains false for loopback plain-HTTP development; set it to true for any HTTPS deployment. The session cookie is HttpOnly and SameSite=Lax; the CSRF cookie is intentionally readable by the panel script.

### 6. Admin-panel accounts have no second factor or self-service recovery path

The observed panel login accepts a username plus password for named operators, or the configured break-glass password/token. Named operator password creation and reset now require at least 15 Unicode characters (bcrypt maximum: 72 bytes). Existing hashes are not migrated or invalidated by this policy change. The login handler does not require TOTP, passkey, or another second factor. The operator-management API can reset another operator's password, but no self-service recovery flow is present in these files.

MFA is not implemented on this branch. For a public or internet-reachable admin panel, require MFA for named operators and keep the break-glass credential offline/strongly protected. A safe implementation must cover enrollment, secret storage, challenge verification, recovery codes, revocation, session invalidation, and UI/API flows together; adding only a TOTP check to the login handler would create lockout and downgrade paths. Loss of all operator credentials requires out-of-band recovery by the server owner. End-user Telegram 2FA/passkeys do not automatically protect this separate admin console.

## Deployment checklist

- Replace development OTP with a real delivery provider; validate webhook authentication, TLS, timeouts, and secret rotation.
- Set the correct passkey RP ID and allowed origins for the deployment's own domain.
- Keep the Admin UI on loopback or behind a hardened HTTPS reverse proxy and additional access control; set `TELESRV_ADMIN_UI_COOKIE_SECURE=true` behind TLS termination.
- The panel login limiter is process-local; apply matching proxy-level limits when running multiple replicas.
- MFA for panel operators remains a required follow-up before internet exposure; end-user Telegram 2FA does not protect the admin console.
- Use unique administrator credentials and a strong session key; keep all secrets and recovery material outside Git.
- Test login, 2FA, passkey, session revocation, password recovery, and account deletion against a non-production database before opening registration.
- Run the complete Go test suite and review all CI results before merging.
