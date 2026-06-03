# Testing Guide

## Run locally

- Frontend: `cd frontend && npm ci && npm test`
- Backend (Go): `cd backend && go test ./...`

## CI

On each `push` and `pull_request`: [.github/workflows/ci-tests.yml](.github/workflows/ci-tests.yml) — jobs `frontend-tests`, `backend-tests` (Go).

## Coverage matrix (current)

### Frontend

- Auth UI, routing, firewall UI, CRUD / OpenVPN flows (Vitest)

### Backend (Go)

- `internal/cert` — inventory parsing
- Integration tests can be added under `backend/..._test.go`

### Agent

The OpenVPN agent is tested in the **openvpn-control-agent** repository.
