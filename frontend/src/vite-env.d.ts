/// <reference types="vite/client" />

interface AppRuntimeConfig {
  API_URL?: string;
}

interface Window {
  __APP_CONFIG__?: AppRuntimeConfig;
}
