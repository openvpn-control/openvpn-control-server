# Testing Guide

## Run locally

- Frontend: `cd frontend && npm ci && npm test`
- Backend: `cd backend && npm ci && npm test`

## CI

On each `push` and `pull_request`: [.github/workflows/ci-tests.yml](.github/workflows/ci-tests.yml) — jobs `frontend-tests`, `backend-tests`.

## Coverage matrix (current)

### Frontend

- Auth UI: login render, success/failure flows
- Routing: `appRoutes` parse/build
- Firewall UI (server/organization/user): render, Effective Policy modal, NAT modal (`preset` vs `manual`), table/empty states, NAT hook labels
- CRUD / OpenVPN: agent node, organization, VPN user, OpenVPN save/apply

### Backend

- App: `/health`, CORS, auth guard on protected prefixes
- Modules: tasks, organizations, vpn-users, agents, admins, clients, monitoring, openvpn-panel branches
- Services: firewall composition/normalization, iptables render, user CCD, OpenVPN sync helpers, certificate helpers

### Agent

The Go agent is tested in the **openvpn-control-agent** repository.

## Stability notes

- Backend tests may use `--test-concurrency=1` to avoid Prisma mock races.
- Restore original `prisma` methods after monkeypatching (`t.after(...)`).
