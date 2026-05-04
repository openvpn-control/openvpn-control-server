# Helm chart: OpenVPN Control

Self-host checklist and security: [README](../../README.md), [SECURITY.md](../../SECURITY.md).

Chart deploys:
- `frontend` (nginx with built UI)
- `backend` (Express + Prisma)
- `postgres` (single-instance)

## Backup path

Panel backup archives are stored in backend directory:

- `/app/data/panel-backups` (inside backend container)

This path is persisted by a dedicated PVC in Helm (`backend.persistence.*`).

## Prerequisites

- Kubernetes 1.24+
- Helm 3+
- Built/pushed container images for:
  - backend
  - frontend

## Install

```bash
helm upgrade --install openvpn-control ./helm/openvpn-control \
  -n openvpn-control --create-namespace
```

## Minimal production overrides

Create `values-prod.yaml`:

```yaml
backend:
  image:
    repository: your-registry/ovpn-backend
    tag: "v1.0.0"
  jwtSecret: "REQUIRED-long-random-secret"
  initAdminUsername: "admin"
  initAdminPassword: "REQUIRED-strong-password"
  env:
    CORS_ORIGIN: "https://ovpn.example.com"
    ALLOWED_HOSTS: "ovpn.example.com"
    CSRF_TRUSTED_ORIGINS: "https://ovpn.example.com"
    CSRF_PROTECTION_ENABLED: "true"

frontend:
  image:
    repository: your-registry/ovpn-frontend
    tag: "v1.0.0"

postgres:
  password: "REQUIRED-strong-password"
  persistence:
    enabled: true
    size: 20Gi

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: ovpn.example.com
      paths:
        - path: /
          pathType: Prefix
```

`postgres.password`, `backend.jwtSecret` and `backend.initAdminPassword` are mandatory; chart install/upgrade fails if any of them is empty.

The chart also runs a pre-install/pre-upgrade Job (`backend-migrate-seed`) for:
- `prisma migrate deploy`
- initial admin bootstrap (`prisma/seed.js`, only if admin does not exist)

## Availability and network hardening

- PodDisruptionBudget is supported for `backend` and `frontend` via `podDisruptionBudget.*`
  - PDB resources are created only when replicas are greater than 1
- NetworkPolicy is enabled by default via `networkPolicy.enabled`
  - frontend ingress: strict by default (`networkPolicy.frontend.allowFromAny=false`)
  - frontend ingress-controller source is configured via `networkPolicy.frontend.ingressController.*` labels
  - backend ingress: frontend-only (same namespace) by default
  - postgres ingress: backend-only (same namespace) by default
- CSRF protection for state-changing requests is enabled by default (`backend.env.CSRF_PROTECTION_ENABLED=true`)
  - requests with `Origin` must match `CSRF_TRUSTED_ORIGINS`
  - keep `CSRF_TRUSTED_ORIGINS` aligned with `CORS_ORIGIN`
- Login brute-force throttling: `backend.env.LOGIN_MAX_ATTEMPTS` (default `8`) and `LOGIN_LOCKOUT_MINUTES` (default `15`) — per client IP + username, in-memory on each backend pod

Then deploy:

```bash
helm upgrade --install openvpn-control ./helm/openvpn-control \
  -n openvpn-control --create-namespace \
  -f values-prod.yaml
```
