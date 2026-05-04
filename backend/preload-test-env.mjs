/**
 * Preloaded via `node --import` so env is set before `config.js` / `app.js` load in tests.
 * Supertest uses ephemeral 127.0.0.1:<port> Host; integration tests use Origin http://localhost:3000.
 */
process.env.CORS_ORIGIN ??= "http://localhost:3000,http://localhost:5173";
process.env.CSRF_TRUSTED_ORIGINS ??=
  process.env.CORS_ORIGIN || "http://localhost:3000,http://localhost:5173";
process.env.ALLOWED_HOSTS ??= "*";
