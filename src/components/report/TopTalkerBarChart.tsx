import { formatBytes, formatNumber } from "../../utils/format";

interface TalkerData {
  ip: string;
  packetCount: number;
  byteCount: number;
}

interface TopTalkerBarChartProps {
  talkers: TalkerData[];
  maxItems?: number;
}

const BAR_COLORS = [
  "#22d3ee", "#60a5fa", "#818cf8", "#a78bfa",
  "#34d399", "#fbbf24", "#f472b6", "#fb923c",
];

export function TopTalkerBarChart({ talkers, maxItems = 8 }: TopTalkerBarChartProps) {
  if (talkers.length === 0) {
    return <p className="text-slate-500 text-sm py-8 text-center">No talker data available</p>;
  }

  const items = talkers.slice(0, maxItems);
  const maxVal = Math.max(...items.map(t => t.packetCount), 1);

  return (
    <div className="glass-border rounded-xl bg-slate-800/30 p-4">
      {items.map((talker, i) => {
        const pct = (talker.packetCount / maxVal) * 100;
        const color = BAR_COLORS[i % BAR_COLORS.length];
        return (
          <div key={talker.ip} className="flex items-center gap-3">
            {/* IP label */}
            <div className="w-36 lg:w-44 flex-shrink-0">
              <code className="text-xs text-slate-300 block truncate" title={talker.ip}>
                {talker.ip}
              </code>
            </div>
            {/* Bar */}
            <div className="flex-1 h-5 bg-slate-800 rounded-md overflow-hidden">
              <div
                className="h-full rounded-md transition-all duration-500 flex items-center px-2 glow-authority"
                style={{
                  width: `${Math.max(2, pct)}%`,
                  backgroundColor: color,
                  opacity: 0.85,
                }}
              >
                <span className="text-[10px] text-white font-medium tabular-nums whitespace-nowrap">
                  {formatNumber(talker.packetCount)}
                </span>
              </div>
            </div>
            {/* Byte count */}
            <div className="w-20 text-right flex-shrink-0">
              <span className="text-xs text-slate-500 tabular-nums">
                {formatBytes(talker.byteCount)}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}