import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/** Production image injects API_URL via data-api-url on <html>; dev keeps /env-config.js. */
function productionHtmlPlugin() {
  return {
    name: "openvpn-control-html",
    apply: "build",
    transformIndexHtml(html) {
      return html
        .replace(/\s*<script src="\/env-config\.js"><\/script>\s*/i, "\n")
        .replace(/\s+crossorigin/g, "");
    },
  };
}

export default defineConfig({
  plugins: [react(), productionHtmlPlugin()],
  server: {
    host: "0.0.0.0",
    port: 5173,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/matchMedia-polyfill.js", "./src/test/setupTests.js"],
    globals: true,
    css: true,
  },
});
