import type { ProtocolCount } from "../../types/analysis";

interface ProtocolChartProps {
  protocols: ProtocolCount[];
  totalPackets: number;
}

const IT_COLORS = [
  "bg-cyan-500",
  "bg-blue-500",
  "bg-indigo-500",
  "bg-violet-500",
  "bg-sky-500",
  "bg-teal-500",
];

const OT_COLOR = "bg-amber-500";

export function ProtocolChart({ protocols, totalPackets }: ProtocolChartProps) {
  if (protocols.length === 0) {
    return <p className="text-slate-500 text-sm py-8 text-center">No protocols detected</p>;
  }

  const itProtocols = protocols.filter((p) => !p.isOT).slice(0, 8);
  const otProtocols = protocols.filter((p) => p.isOT);

  return (
    <div className="space-y-4">
      {/* IT Protocols */}
      {itProtocols.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-2">IT Protocols</h4>
          <div className="space-y-2">
            {itProtocols.map((p, i) => {
              const pct = totalPackets > 0 ? (p.packetCount / totalPackets) * 100 : 0;
              const color = IT_COLORS[i % IT_COLORS.length];
              return (
                <div key={p.protocol} className="glass-border rounded-lg bg-slate-800/30 px-3 py-2">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-300">{p.protocol}</span>
                    <span className="text-slate-500">
                      {p.packetCount.toLocaleString()} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${color} transition-all duration-500 glow-authority`}
                      style={{ width: `${Math.min(100, pct)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* OT Protocols */}
      {otProtocols.length > 0 && (
        <div className="pt-3 border-t border-slate-800">
          <h4 className="text-xs font-medium text-amber-400 uppercase tracking-wider mb-2">OT/ICS Protocols</h4>
          <div className="space-y-2">
            {otProtocols.map((p) => {
              const pct = totalPackets > 0 ? (p.packetCount / totalPackets) * 100 : 0;
              return (
                <div key={p.protocol} className="glass-border rounded-lg bg-slate-800/30 px-3 py-2">
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-amber-300">{p.protocol}</span>
                    <span className="text-slate-500">
                      {p.packetCount.toLocaleString()} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${OT_COLOR} transition-all duration-500`}
                      style={{ width: `${Math.min(100, pct)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}