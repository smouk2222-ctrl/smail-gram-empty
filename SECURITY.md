# Security notes

Smail Gram is a self-hosted server fork. Operators are responsible for protecting the host, database, media storage, signing keys, administrator credentials, and any user data stored by the deployment.

## Before exposing an instance to the internet

- Do not deploy with development authentication. The current code default is `TELESRV_PHONE_CODE_DELIVERY_PROVIDER=development` and `TELESRV_DEV_AUTH_CODE=12345`; that fixed code is accepted for every phone number. This is for local testing only and makes account takeover trivial if the login endpoint is publicly reachable. Configure a real, secured OTP delivery provider before exposing the server to the internet.
- Do not expose the Admin UI directly to the public internet. The code default binds it to loopback; keep `TELESRV_ADMIN_UI_ADDR=127.0.0.1:2600` or place it behind a carefully configured HTTPS reverse proxy and an additional access-control layer. Use unique administrator credentials and a strong session key.
- Keep `.env`, database credentials, private keys, wallet key files, recovery phrases, and backups out of Git. The repository ignores local environment and key files; do not override those protections.
- Use HTTPS for public endpoints, restrict firewall ports to those required, and persist database and media volumes with tested backups.
- Review all optional integrations before enabling them. In particular, custodial crypto donations are disabled by default. Enabling them creates operational responsibility for wallet encryption keys, recovery phrases, chain configuration, and funds.
- Keep the server, operating system, database, and reverse-proxy software updated. Review logs for unexpected authentication and administrator activity.

## Admin-panel credentials

Named admin-console accounts require passwords of at least 15 Unicode characters and no more than 72 UTF-8 bytes (bcrypt's input limit). Prefer a randomly generated passphrase from a password manager. This policy applies when creating or resetting named operator passwords; it does not silently rewrite existing password hashes. MFA is not implemented yet, so keep the panel on loopback or behind HTTPS plus a separate access-control layer, and do not treat the password rule as a substitute for MFA.

## Custodial donations

`TELESRV_DONATIONS_ENABLED` defaults to `false`. Set it to `true` only after reviewing the implementation and operational model, securely backing up the wallet encryption key and recovery material, and validating the configured chains and RPC endpoints. Disabling the feature does not delete an existing wallet or its funds; it leaves them dormant.

## Reporting a vulnerability

Do not publish credentials, private keys, recovery phrases, exploit details affecting live instances, or personal data in an issue. Use GitHub's private vulnerability reporting for this repository if it is enabled; otherwise contact the repository maintainer privately before disclosing details publicly.
