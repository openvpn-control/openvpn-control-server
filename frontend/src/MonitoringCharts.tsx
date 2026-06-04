import { useEffect, useMemo, useRef, useState } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { monitoringXRange, parseUtcMs } from "./monitoringTime";

const LEFT_AXIS_PX = 40;

function fmtTime(ms) {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

function fmtTimeFull(ms) {
  const d = new Date(ms);
  const yyyy = d.getFullYear();
  const mon = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${yyyy}-${mon}-${day} ${hh}:${mm}:${ss}`;
}

function fmtRate(v) {
  const n = Math.max(Number(v || 0), 0);
  if (n < 1000) return `${n.toFixed(0)} Bps`;
  if (n < 1000 * 1000) return `${(n / 1000).toFixed(0)} kbps`;
  if (n < 1000 * 1000 * 1000) return `${(n / (1000 * 1000)).toFixed(1)} Mbps`;
  return `${(n / (1000 * 1000 * 1000)).toFixed(1)} Gbps`;
}

function toChartSeries(samples, seriesGetters, historyMinutes) {
  const [xMin] = monitoringXRange(historyMinutes);
  const rows = [...(samples || [])]
    .map((s) => ({ ...s, ts: parseUtcMs(s.createdAt) }))
    .filter((s) => Number.isFinite(s.ts) && s.ts >= xMin)
    .sort((a, b) => a.ts - b.ts);
  const x = rows.map((r) => r.ts);
  const ys = seriesGetters.map((g) => rows.map((r) => Number(g(r) || 0)));
  return { rows, data: [x, ...ys] };
}

function syncMonitoringXScale(plot, historyMinutes) {
  const [xMin, xMax] = monitoringXRange(historyMinutes);
  plot.setScale("x", { min: xMin, max: xMax });
}

function useUplot(containerRef, optionsFactory, data, onCursor, historyMinutes = 15) {
  const plotRef = useRef(null);
  const rootRef = useRef(null);
  const optionsFactoryRef = useRef(optionsFactory);
  const onCursorRef = useRef(onCursor);
  const dataRef = useRef(data);
  const historyMinutesRef = useRef(historyMinutes);

  useEffect(() => {
    optionsFactoryRef.current = optionsFactory;
  }, [optionsFactory]);

  useEffect(() => {
    onCursorRef.current = onCursor;
  }, [onCursor]);

  useEffect(() => {
    dataRef.current = data;
    historyMinutesRef.current = historyMinutes;
    if (!plotRef.current) return;
    plotRef.current.setData(data);
    syncMonitoringXScale(plotRef.current, historyMinutes);
    plotRef.current.redraw();
  }, [data, historyMinutes]);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const root = containerRef.current;
    rootRef.current = root;
    const w = Math.max(1, root.clientWidth);
    const opts = optionsFactoryRef.current(w);
    plotRef.current = new uPlot(opts, dataRef.current, root);
    syncMonitoringXScale(plotRef.current, historyMinutesRef.current);

    const slideAxis = () => {
      if (!plotRef.current) return;
      syncMonitoringXScale(plotRef.current, historyMinutesRef.current);
      plotRef.current.redraw();
    };
    const axisTimer = window.setInterval(slideAxis, 1000);

    const ro = new ResizeObserver(() => {
      if (!plotRef.current || !rootRef.current) return;
      plotRef.current.setSize({ width: Math.max(1, rootRef.current.clientWidth), height: 210 });
      slideAxis();
    });
    ro.observe(root);
    return () => {
      window.clearInterval(axisTimer);
      ro.disconnect();
      if (plotRef.current) {
        plotRef.current.destroy();
        plotRef.current = null;
      }
      onCursorRef.current?.(null);
    };
  }, [containerRef]);

  return plotRef;
}

interface ChartPanelProps {
  title: string;
  yMax: number;
  yTicks: number[];
  yFormat: (v: number) => string;
  series: Array<{
    label: string;
    color: string;
    fill?: string;
    getter: (r: Record<string, unknown>) => number;
    valueFormat: (v: number) => string;
  }>;
  samples: Array<Record<string, unknown>>;
  limitLabel?: string;
  legendRows?: Array<Array<{ label: string; value?: string; swatch?: string }>>;
  historyMinutes?: number;
}

function ChartPanel({ title, yMax, yTicks, yFormat, series, samples, limitLabel, legendRows, historyMinutes = 15 }: ChartPanelProps) {
  const holderRef = useRef(null);
  const [hover, setHover] = useState(null);
  const chart = useMemo(
    () => toChartSeries(samples, series.map((s) => s.getter), historyMinutes),
    [samples, series, historyMinutes],
  );

  const optionsFactory = useMemo(
    () => (width) => ({
      width,
      height: 184,
      class: "grafana-like",
      padding: [12, 10, 18, LEFT_AXIS_PX],
      scales: {
        x: {
          time: false,
          range: () => monitoringXRange(historyMinutes),
        },
        y: { auto: false, range: [0, yMax] },
      },
      axes: [
        {
          stroke: "#0f172a",
          grid: { stroke: "rgba(15, 23, 42, 0.14)", width: 1 },
          font: "12px Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif",
          size: 20,
          values: (_u, vals) => vals.map((v) => fmtTime(v)),
        },
        {
          stroke: "#0f172a",
          grid: { stroke: "rgba(15, 23, 42, 0.14)", width: 1 },
          font: "12px Roboto, system-ui, -apple-system, 'Segoe UI', sans-serif",
          values: (_u, vals) => vals.map((v) => yFormat(v)),
          splits: () => yTicks,
          size: LEFT_AXIS_PX,
        },
      ],
      series: [
        {},
        ...series.map((s) => ({
          stroke: s.color,
          width: 2,
          fill: s.fill || undefined,
        })),
      ],
      cursor: {
        y: false,
        x: true,
        points: { show: false },
      },
      legend: { show: false },
      hooks: {
        setCursor: [
          (u) => {
            if (u.cursor.idx == null || u.cursor.left == null) {
              setHover(null);
              return;
            }
            const idx = u.cursor.idx;
            const xVal = u.data[0][idx];
            const items = series.map((s, i) => ({
              label: s.label,
              color: s.color,
              value: s.valueFormat(u.data[i + 1][idx]),
            }));
            setHover({
              idx,
              x: u.cursor.left,
              time: xVal,
              items,
            });
          },
        ],
      },
    }),
    [series, yFormat, yMax, yTicks, historyMinutes],
  );

  const plotRef = useUplot(holderRef, optionsFactory, chart.data, setHover, historyMinutes);

  useEffect(() => {
    if (!plotRef.current || !Number.isFinite(yMax)) return;
    plotRef.current.setScale("y", { min: 0, max: yMax });
    plotRef.current.redraw();
  }, [plotRef, yMax, chart.data]);

  return (
    <div className="server-monitoring-panel">
      <div className="server-monitoring-panel-title">{title}</div>
      <div className="server-monitoring-canvas-wrap">
        <div ref={holderRef} />
        {hover ? (
          <div className="server-monitoring-tooltip" style={{ left: `calc(${hover.x}px - 110px)`, top: 40 }}>
            <div className="server-monitoring-tooltip-time">{fmtTimeFull(hover.time)}</div>
            {hover.items.map((it) => (
              <div key={it.label} className="server-monitoring-tooltip-row">
                <span style={{ color: it.color }}>{it.label}:</span>
                <strong>{it.value}</strong>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      <div className="server-monitoring-legend">
        {(legendRows || []).map((row, idx) => (
          <div key={idx} className="server-monitoring-legend-row">
            {row.map((st) => (
              <span key={`${st.label}-${st.value || ""}-${st.swatch || ""}`}>
                {st.swatch ? <span className={`swatch ${st.swatch}`}>{st.label}</span> : st.label}{" "}
                {st.value ? <strong>{st.value}</strong> : null}
              </span>
            ))}
            {idx === 0 && limitLabel ? (
              <span>
                limit <strong>{limitLabel}</strong>
              </span>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}

interface MonitoringChartsProps {
  samples?: Array<Record<string, unknown>>;
  current?: Record<string, unknown>;
  historyMinutes?: number;
}

export default function MonitoringCharts({ samples, current, historyMinutes = 15 }: MonitoringChartsProps) {
  const safeSamples = Array.isArray(samples) ? samples : [];
  const safeMin = (vals) => {
    const arr = (vals || []).filter((v) => Number.isFinite(v));
    return arr.length ? Math.min(...arr) : 0;
  };
  const safeMax = (vals) => {
    const arr = (vals || []).filter((v) => Number.isFinite(v));
    return arr.length ? Math.max(...arr) : 0;
  };
  const num = (v: unknown) => Number(v ?? 0);
  const cpuMin = Math.min(safeMin(safeSamples.map((s) => num(s.cpuPercent))), 0);
  const cpuMax = Math.max(safeMax(safeSamples.map((s) => num(s.cpuPercent))), num(current?.cpuPercent), 0);
  const cpuCur = num(current?.cpuPercent);
  const ramMin = Math.min(safeMin(safeSamples.map((s) => Number(s.memoryPercent || 0))), 0);
  const ramMax = Math.max(safeMax(safeSamples.map((s) => Number(s.memoryPercent || 0))), Number(current?.memoryPercent || 0), 0);
  const ramCur = Number(current?.memoryPercent || 0);

  const diskReadVals = safeSamples.map((s) => Number(s.diskReadBps || 0));
  const diskWriteVals = safeSamples.map((s) => Number(s.diskWriteBps || 0));
  const diskMax = Math.max(...diskReadVals, ...diskWriteVals, Number(current?.diskReadBps || 0), Number(current?.diskWriteBps || 0), 1);
  const diskScale = Math.max(400 * 1000 * 1000, Math.ceil(diskMax / (100 * 1000 * 1000)) * 100 * 1000 * 1000);

  const bwInVals = safeSamples.map((s) => Number(s.networkInBps || 0));
  const bwOutVals = safeSamples.map((s) => Number(s.networkOutBps || 0));
  const bwMax = Math.max(...bwInVals, ...bwOutVals, Number(current?.networkInBps || 0), Number(current?.networkOutBps || 0), 1);
  const bwScale = Math.max(40 * 1000 * 1000, Math.ceil(bwMax / (10 * 1000 * 1000)) * 10 * 1000 * 1000);

  return (
    <div className="server-monitoring-panels">
      <ChartPanel
        title="CPU"
        yMax={250}
        yTicks={[0, 50, 100, 150, 200, 250]}
        yFormat={(v) => `${Math.round(v)}%`}
        samples={safeSamples}
        historyMinutes={historyMinutes}
        series={[
          { label: "CPU", color: "#e59649", fill: "#efd7bc55", getter: (r) => Number(r.cpuPercent ?? 0), valueFormat: (v) => `${Math.round(v)}%` },
        ]}
        legendRows={[
          [
            { label: "CPU", swatch: "swatch-cpu" },
            { label: "min", value: `${Math.round(cpuMin)}%` },
            { label: "max", value: `${Math.round(cpuMax)}%` },
            { label: "current", value: `${Math.round(cpuCur)}%` },
          ],
        ]}
      />

      <ChartPanel
        title="RAM"
        yMax={100}
        yTicks={[0, 20, 40, 60, 80, 100]}
        yFormat={(v) => `${Math.round(v)}%`}
        samples={safeSamples}
        historyMinutes={historyMinutes}
        series={[
          { label: "RAM", color: "#22c55e", fill: "#bbf7d055", getter: (r) => Number(r.memoryPercent ?? 0), valueFormat: (v) => `${Math.round(v)}%` },
        ]}
        legendRows={[
          [
            { label: "RAM" },
            { label: "min", value: `${Math.round(ramMin)}%` },
            { label: "max", value: `${Math.round(ramMax)}%` },
            { label: "current", value: `${Math.round(ramCur)}%` },
          ],
        ]}
      />

      <ChartPanel
        title="Disk"
        yMax={diskScale}
        yTicks={[0, 100, 200, 300, 400].map((v) => v * 1000 * 1000)}
        yFormat={(v) => (v === 0 ? "0 Bps" : `${Math.round(v / (1000 * 1000))} MBps`)}
        samples={safeSamples}
        historyMinutes={historyMinutes}
        series={[
          { label: "Disk read", color: "#22a3de", fill: "#c4e8f833", getter: (r) => Number(r.diskReadBps ?? 0), valueFormat: fmtRate },
          { label: "Disk write", color: "#ef6f63", fill: "#f6c9c233", getter: (r) => Number(r.diskWriteBps ?? 0), valueFormat: fmtRate },
        ]}
        legendRows={[
          [
            { label: "Disk read", swatch: "swatch-disk-read" },
            { label: "min", value: fmtRate(safeMin(diskReadVals)) },
            { label: "max", value: fmtRate(safeMax(diskReadVals)) },
            { label: "current", value: fmtRate(current?.diskReadBps || 0) },
          ],
          [
            { label: "Disk write", swatch: "swatch-disk-write" },
            { label: "min", value: fmtRate(safeMin(diskWriteVals)) },
            { label: "max", value: fmtRate(safeMax(diskWriteVals)) },
            { label: "current", value: fmtRate(current?.diskWriteBps || 0) },
          ],
        ]}
      />

      <ChartPanel
        title="Bandwidth"
        yMax={bwScale}
        yTicks={[0, 10, 20, 30, 40].map((v) => v * 1000 * 1000)}
        yFormat={(v) => `${Math.round(v / (1000 * 1000))} Mbps`}
        samples={safeSamples}
        historyMinutes={historyMinutes}
        series={[
          { label: "Bandwidth in", color: "#0d94a7", fill: "#b7e7ea2e", getter: (r) => Number(r.networkInBps ?? 0), valueFormat: fmtRate },
          { label: "Bandwidth out", color: "#7681e7", fill: "#ced3ff2e", getter: (r) => Number(r.networkOutBps ?? 0), valueFormat: fmtRate },
        ]}
        legendRows={[
          [
            { label: "Bandwidth in", swatch: "swatch-bw-in" },
            { label: "min", value: fmtRate(safeMin(bwInVals)) },
            { label: "max", value: fmtRate(safeMax(bwInVals)) },
            { label: "current", value: fmtRate(current?.networkInBps || 0) },
          ],
          [
            { label: "Bandwidth out", swatch: "swatch-bw-out" },
            { label: "min", value: fmtRate(safeMin(bwOutVals)) },
            { label: "max", value: fmtRate(safeMax(bwOutVals)) },
            { label: "current", value: fmtRate(current?.networkOutBps || 0) },
          ],
        ]}
      />
    </div>
  );
}
