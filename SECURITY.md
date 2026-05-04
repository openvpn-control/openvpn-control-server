# Security

## Supported versions

Security fixes land on the default branch (`main` / `master`). There is no separate LTS line yet.

## Reporting a vulnerability

Do not open a public issue for undisclosed security problems until coordinated with maintainers.

1. Prefer [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) if enabled for this repository.
2. Otherwise use the security contact or process advertised for this repo.

Include: description, impact, affected area (UI, API, etc.), steps to reproduce if safe, version/commit.

## Hardening (self-hosted panel)

Before exposing the panel to the internet:

- Strong `JWT_SECRET`, database password, initial admin password — no demo defaults.
- HTTPS; align `CORS_ORIGIN`, `CSRF_TRUSTED_ORIGINS`, and `ALLOWED_HOSTS` with your real URL.
- Restrict network access where possible; keep dependencies and images updated.

See [README.md](README.md#развёртывание-у-себя-self-host) for a short checklist.

Issues in the **Linux agent** belong to the separate **openvpn-control-agent** repository (companion to this one) — report agent-specific findings there.
