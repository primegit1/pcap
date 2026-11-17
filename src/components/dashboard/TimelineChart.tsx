import { formatTimestamp } from "../../utils/format";

interface TimelineBucket {
  timestampUs: number;
  packetCount: number;
  byteCount: number;
}

interface TimelineChartProps {
  buckets: TimelineBucket[];
}

export function TimelineChart({ buckets }: TimelineChartProps) {
  if (buckets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-slate-500">
        <svg className="w-10 h-10 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5" />
        </svg>
        <p className="text-sm">No timeline data — timestamps not available in capture</p>
      </div>
    );
  }

  // Find max for scaling
  let maxPackets = 1;
  let maxBytes = 1;
  for (const b of buckets) {
    if (b.packetCount > maxPackets) maxPackets = b.packetCount;
    if (b.byteCount > maxBytes) maxBytes = b.byteCount;
  }

  const height = 140;
  const padding = { top: 16, right: 16, bottom: 28, left: 16 };
  const chartW = 600; // virtual width for SVG viewBox
  const chartH = height;
  const plotW = chartW - padding.left - padding.right;
  const plotH = chartH - padding.top - padding.bottom;

  // Generate path for the area chart
  const stepX = plotW / (buckets.length - 1);
  const points = buckets.map((b, i) => ({
    x: padding.left + i * stepX,
    y: padding.top + plotH - (b.packetCount / maxPackets) * plotH,
    yBytes: padding.top + plotH - (b.byteCount / maxBytes) * plotH,
    count: b.packetCount,
    bytes: b.byteCount,
    ts: b.timestampUs,
  }));

  // Area path (packets)
  const areaPath = [
    `M ${padding.left} ${padding.top + plotH}`,
    ...points.map((p) => `L ${p.x.toFixed(1)} ${p.y.toFixed(1)}`),
    `L ${padding.left + plotW} ${padding.top + plotH}`,
    "Z",
  ].join(" ");

  // Line path (packets)
  const linePath = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(" ");

  // Bytes line path (subtle)
  const bytesPath = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.yBytes.toFixed(1)}`)
    .join(" ");

  // X-axis labels (every Nth)
  const xLabels: { label: string; x: number }[] = [];
  const labelInterval = Math.max(1, Math.floor(buckets.length / 6));
  for (let i = 0; i < buckets.length; i += labelInterval) {
    xLabels.push({
      label: formatTimestamp(buckets[i].timestampUs).replace(":00.", ":"),
      x: padding.left + i * stepX,
    });
  }
  // Always include last point
  const lastX = padding.left + (buckets.length - 1) * stepX;
  if (xLabels.length > 0 && xLabels[xLabels.length - 1].x < lastX - 20) {
    xLabels.push({
      label: formatTimestamp(buckets[buckets.length - 1].timestampUs).replace(":00.", ":"),
      x: lastX,
    });
  }

  // Y-axis labels
  const yLabels = [
    { label: String(maxPackets), y: padding.top },
    { label: String(Math.round(maxPackets / 2)), y: padding.top + plotH / 2 },
    { label: "0", y: padding.top + plotH },
  ];

  return (
    <div className="glass rounded-xl border border-slate-800">
      <svg
        viewBox={`0 0 ${chartW} ${chartH}`}
        className="w-full"
        style={{ height: `${height}px` }}
        role="img"
        aria-label="Traffic volume timeline"
      >
        {/* Grid lines */}
        {yLabels.map((yl) => (
          <line
            key={yl.label}
            x1={padding.left}
            y1={yl.y}
            x2={chartW - padding.right}
            y2={yl.y}
            stroke="#1e293b"
            strokeWidth={0.5}
          />
        ))}

        {/* Y-axis labels */}
        {yLabels.map((yl) => (
          <text
            key={`y-${yl.label}`}
            x={padding.left - 4}
            y={yl.y + 4}
            textAnchor="end"
            className="fill-slate-600 text-[9px]"
          >
            {yl.label}
          </text>
        ))}

        {/* Packets area gradient */}
        <defs>
          <linearGradient id="packetsGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#0ea5e9" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#0ea5e9" stopOpacity={0.05} />
          </linearGradient>
          <linearGradient id="bytesGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.02} />
          </linearGradient>
        </defs>

        {/* Bytes area (subtle) */}
        <path d={areaPath} fill="url(#bytesGradient)" opacity={0.3} />

        {/* Packets area */}
        <path d={areaPath} fill="url(#packetsGradient)" opacity={0.5} />

        {/* Packets line */}
        <path
          d={linePath}
          fill="none"
          stroke="#0ea5e9"
          strokeWidth={1.2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Bytes line (subtle overlay) */}
        <path
          d={bytesPath}
          fill="none"
          stroke="#8b5cf6"
          strokeWidth={0.6}
          strokeLinecap="round"
          strokeLinejoin="round"
          opacity={0.5}
        />

        {/* X-axis labels */}
        {xLabels.map((xl) => (
          <text
            key={`x-${xl.label}`}
            x={xl.x}
            y={chartH - 4}
            textAnchor="middle"
            className="fill-slate-600 text-[8px]"
          >
            {xl.label}
          </text>
        ))}
      </svg>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-1 mb-1 px-4">
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-0.5 rounded bg-cyan-400" />
          <span className="text-[10px] text-slate-500">Packets</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-0.5 rounded bg-violet-400 opacity-50" />
          <span className="text-[10px] text-slate-500">Bytes</span>
        </div>
      </div>
    </div>
  );
}