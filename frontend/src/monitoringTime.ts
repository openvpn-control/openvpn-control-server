/** Parse API metric timestamp (UTC, RFC3339 or naive UTC) to epoch ms. */
export function parseUtcMs(value: unknown): number {
  if (value == null) return NaN;
  const s = String(value).trim();
  if (!s) return NaN;
  if (/[zZ]$|[+-]\d{2}:?\d{2}$/.test(s)) {
    const t = Date.parse(s);
    return Number.isFinite(t) ? t : NaN;
  }
  const normalized = s.includes("T") ? s : s.replace(" ", "T");
  const t = Date.parse(`${normalized}Z`);
  return Number.isFinite(t) ? t : NaN;
}

export function monitoringWindowMs(historyMinutes = 15): number {
  const m = Number(historyMinutes);
  const mins = Number.isFinite(m) && m > 0 ? m : 15;
  return mins * 60 * 1000;
}

/** Скользящее окно «последние N минут» для оси X uPlot (пересчитывается при каждой отрисовке). */
export function monitoringXRange(historyMinutes = 15): [number, number] {
  const xMax = Date.now();
  return [xMax - monitoringWindowMs(historyMinutes), xMax];
}
