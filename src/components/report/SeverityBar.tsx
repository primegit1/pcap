interface SeverityBarProps {
  counts: Record<string, number>;
  total: number;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string; order: number }> = {
  Critical: { label: "Critical", color: "#ef4444", order: 0 },
  High: { label: "High", color: "#f97316", order: 1 },
  Medium: { label: "Medium", color: "#eab308", order: 2 },
  Low: { label: "Low", color: "#3b82f6", order: 3 },
  Info: { label: "Info", color: "#64748b", order: 4 },
};

export function SeverityBar({ counts, total }: SeverityBarProps) {
  if (total === 0) {
    return (
      <p className="text-slate-500 text-sm py-4 text-center">
        No security findings — traffic appears clean
      </p>
    );
  }

  const entries = Object.entries(SEVERITY_CONFIG)
    .filter(([key]) => (counts[key] || 0) > 0)
    .sort((a, b) => a[1].order - b[1].order);

  return (
    <div className="glass-border rounded-xl bg-slate-800/30 p-4">
      {/* Stacked bar */}
      <div className="h-4 bg-slate-800/50 rounded-full overflow-hidden flex">
        {entries.map(([key, config]) => {
          const count = counts[key] || 0;
          const pct = (count / total) * 100;
          if (pct === 0) return null;
          return (
            <div
              key={key}
              className="h-full transition-all duration-500 first:rounded-l-full last:rounded-r-full glow-authority"
              style={{
                width: `${pct}%`,
                backgroundColor: config.color,
              }}
              title={`${config.label}: ${count}`}
            />
          );
        })}
      </div>

      {/* Labels */}
      <div className="flex flex-wrap gap-3 mt-3">
        {entries.map(([key, config]) => {
          const count = counts[key] || 0;
          return (
            <div key={key} className="flex items-center gap-1.5 text-xs">
              <div
                className="w-2 h-2 rounded-full flex-shrink-0 glow-authority"
                style={{ backgroundColor: config.color }}
              />
              <span className="text-slate-400">{config.label}</span>
              <span className="text-slate-500 font-mono tabular-nums">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}