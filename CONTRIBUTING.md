# Contributing

Thank you for improving OpenVPN Control Server.

1. **Issues** — include version/commit, environment (OS, Docker/K8s), steps to reproduce.
2. **Pull requests** — one topic per PR; match existing style in touched files.
3. **Security** — see [SECURITY.md](SECURITY.md).

## Development

- Frontend: `frontend/` — `npm ci && npm test`
- Backend: `backend/` — `go test ./...`

The **agent** lives in a separate repository; do not commit agent code here.

## License

By contributing, you agree your contributions are licensed under [LICENSE](LICENSE) (MIT).
