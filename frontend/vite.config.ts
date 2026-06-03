import { defineConfig } from "vitest/config";

import react from "@vitejs/plugin-react";



export default defineConfig({

  plugins: [react()],

  build: {

    outDir: "dist",

    // Не "assets" — uBlock/AdGuard часто блокируют /assets/*.js (Firefox status: 0)
    assetsDir: "static",

    sourcemap: true,

    rollupOptions: {

      output: {

        entryFileNames: "static/[name]-[hash].js",

        chunkFileNames: "static/[name]-[hash].js",

        assetFileNames: "static/[name]-[hash][extname]",

      },

    },

  },

  test: {

    environment: "jsdom",

    setupFiles: ["./src/test/matchMedia-polyfill.ts", "./src/test/setupTests.ts"],

    globals: true,

    css: true,

  },

});
