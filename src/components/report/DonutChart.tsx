interface DonutSlice {
  label: string;
  value: number;
  color: string;
}

interface DonutChartProps {
  data: DonutSlice[];
  total: number;
  centerLabel?: string;
}

export function DonutChart({ data, total, centerLabel }: DonutChartProps) {
  if (data.length === 0) {
    return <p className="text-slate-500 text-sm py-8 text-center">No data to display</p>;
  }

  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 80;
  const innerRadius = 50;

  // Sort data by value descending, cap at 10 slices
  const sorted = [...data].sort((a, b) => b.value - a.value);
  const visible = sorted.slice(0, 10);
  const others = sorted.slice(10);

  // Build arcs
  let startAngle = -Math.PI / 2; // Start from top
  const arcs: { path: string; color: string; label: string; value: number; pct: number }[] = [];

  const chartTotal = visible.reduce((s, d) => s + d.value, 0) +
    others.reduce((s, d) => s + d.value, 0);

  for (const slice of visible) {
    const pct = chartTotal > 0 ? slice.value / chartTotal : 0;
    const angle = pct * Math.PI * 2;
    const endAngle = startAngle + angle;

    const path = describeArc(cx, cy, radius, innerRadius, startAngle, endAngle);
    arcs.push({
      path,
      color: slice.color,
      label: slice.label,
      value: slice.value,
      pct: pct * 100,
    });

    startAngle = endAngle;
  }

  return (
    <div className="flex flex-col lg:flex-row items-center gap-6">
      {/* Donut SVG */}
      <svg
        viewBox={`0 0 ${size} ${size}`}
        className="w-48 h-48 flex-shrink-0"
        role="img"
        aria-label="Protocol distribution chart"
      >
        {arcs.map((arc, i) => (
          <path
            key={i}
            d={arc.path}
            fill={arc.color}
            stroke="#0f172a"
            strokeWidth={1}
            className="transition-all duration-300 hover:opacity-80 cursor-pointer"
          />
        ))}

        {/* Center text with gradient */}
        <text
          x={cx}
          y={cy - 4}
          textAnchor="middle"
          className="fill-transparent text-lg font-bold text-gradient"
          fontSize={18}
        >
          {centerLabel || total.toLocaleString()}
        </text>
        <text
          x={cx}
          y={cy + 12}
          textAnchor="middle"
          className="fill-slate-500"
          fontSize={9}
        >
          packets
        </text>
      </svg>

      {/* Legend */}
      <div className="flex-1 space-y-1.5 min-w-0 glass-border rounded-xl p-3">
        {arcs.map((arc, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <div
              className="w-2.5 h-2.5 rounded-full flex-shrink-0 glow-authority"
              style={{ backgroundColor: arc.color }}
            />
            <span className="text-slate-300 truncate">{arc.label}</span>
            <span className="text-slate-500 ml-auto flex-shrink-0 tabular-nums">
              {arc.pct.toFixed(1)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Generate SVG path for a donut arc.
 */
function describeArc(
  cx: number,
  cy: number,
  radius: number,
  innerRadius: number,
  startAngle: number,
  endAngle: number
): string {
  const largeArc = endAngle - startAngle > Math.PI ? 1 : 0;

  const x1 = cx + radius * Math.cos(startAngle);
  const y1 = cy + radius * Math.sin(startAngle);
  const x2 = cx + radius * Math.cos(endAngle);
  const y2 = cy + radius * Math.sin(endAngle);

  const ix1 = cx + innerRadius * Math.cos(startAngle);
  const iy1 = cy + innerRadius * Math.sin(startAngle);
  const ix2 = cx + innerRadius * Math.cos(endAngle);
  const iy2 = cy + innerRadius * Math.sin(endAngle);

  return [
    `M ${x1.toFixed(1)} ${y1.toFixed(1)}`,
    `A ${radius} ${radius} 0 ${largeArc} 1 ${x2.toFixed(1)} ${y2.toFixed(1)}`,
    `L ${ix2.toFixed(1)} ${iy2.toFixed(1)}`,
    `A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${ix1.toFixed(1)} ${iy1.toFixed(1)}`,
    "Z",
  ].join(" ");
}