// uPlot (dist/uPlot.cjs.js) uses bare `matchMedia(...)`; jsdom/Vitest leave globalThis.matchMedia unset.
function matchMediaPolyfill(query) {
  return {
    matches: false,
    media: query,
    onchange: null,
    addListener() {},
    removeListener() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() {
      return false;
    },
  };
}
globalThis.matchMedia = matchMediaPolyfill;
if (typeof window !== "undefined") {
  window.matchMedia = matchMediaPolyfill;
}
