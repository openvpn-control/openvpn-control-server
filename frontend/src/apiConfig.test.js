import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveApiUrl } from "./apiConfig.js";

describe("apiConfig", () => {
  afterEach(() => {
    delete window.__APP_CONFIG__;
    delete document.documentElement.dataset.apiUrl;
    vi.unstubAllEnvs();
  });

  it("uses runtime API_URL from env-config.js", () => {
    window.__APP_CONFIG__ = { API_URL: "https://panel.example.com/" };
    expect(resolveApiUrl()).toBe("https://panel.example.com");
  });

  it("uses data-api-url from index.html in production", () => {
    document.documentElement.dataset.apiUrl = "https://panel.example.com/";
    expect(resolveApiUrl()).toBe("https://panel.example.com");
  });

  it("uses VITE_API_URL when runtime config is empty", () => {
    vi.stubEnv("VITE_API_URL", "http://127.0.0.1:9000");
    expect(resolveApiUrl()).toBe("http://127.0.0.1:9000");
  });

  it("falls back to localhost for local dev", () => {
    expect(resolveApiUrl()).toBe("http://localhost:8080");
  });
});
