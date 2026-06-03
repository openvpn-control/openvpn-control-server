import { afterEach, describe, expect, it } from "vitest";
import { resolveApiUrl } from "./apiConfig";

describe("apiConfig", () => {
  afterEach(() => {
    delete window.__APP_CONFIG__;
    delete document.documentElement.dataset.apiUrl;
  });

  it("uses data-api-url from index.html", () => {
    document.documentElement.dataset.apiUrl = "http://panel.example.com/";
    expect(resolveApiUrl()).toBe("http://panel.example.com");
  });

  it("uses same origin when runtime config is empty in browser", () => {
    Object.defineProperty(window, "location", {
      value: { origin: "http://localhost:5173" },
      writable: true,
      configurable: true,
    });
    expect(resolveApiUrl()).toBe("http://localhost:5173");
  });
});
