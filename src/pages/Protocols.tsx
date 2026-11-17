import { useAppContext } from "../context/AppContext";
import { useSort } from "../components/shared/useSort";

export default function ProtocolsPage() {
  const { state } = useAppContext();

  if (!state.result) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <svg className="w-12 h-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
        </svg>
        <p className="text-sm">No protocols — upload a PCAP to begin analysis</p>
      </div>
    );
  }

  const itProtocols = state.protocolCounts.filter(p => !p.isOT);
  const otProtocols = state.protocolCounts.filter(p => p.isOT);
  const totalPackets = state.summary?.totalPackets ?? 0;

  return (
    <div>
      {/* IT Protocol section */}
      <h3 className="text-white font-medium mb-3">IT Protocols ({itProtocols.length})</h3>
      <ProtocolTable protocols={itProtocols} totalPackets={totalPackets} />

      {/* OT Protocol section */}
      {otProtocols.length > 0 && (
        <div className="mt-8">
          <h3 className="text-amber-400 font-medium mb-3">OT/ICS Protocols ({otProtocols.length})</h3>
          <ProtocolTable protocols={otProtocols} totalPackets={totalPackets} highlight />
        </div>
      )}
    </div>
  );
}

function ProtocolTable({
  protocols,
  totalPackets,
  highlight = false,
}: {
  protocols: { protocol: string; packetCount: number; byteCount: number }[];
  totalPackets: number;
  highlight?: boolean;
}) {
  const { sort, toggleSort, applySort, SortIndicator } = useSort("packetCount", "desc");

  if (protocols.length === 0) {
    return <p className="text-sm text-slate-500 py-4">No protocols detected</p>;
  }

  const sorted = applySort(protocols, (p) => {
    if (sort.key === "protocol") return p.protocol;
    if (sort.key === "packetCount") return p.packetCount;
    if (sort.key === "byteCount") return p.byteCount;
    if (sort.key === "pct") return totalPackets > 0 ? (p.packetCount / totalPackets) * 100 : 0;
    return p.packetCount;
  });

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-left text-slate-500">
            <SortableHeader columnKey="protocol" label="Protocol" toggleSort={toggleSort} SortIndicator={SortIndicator} />
            <SortableHeader columnKey="packetCount" label="Packets" toggleSort={toggleSort} SortIndicator={SortIndicator} />
            <SortableHeader columnKey="pct" label="% Traffic" toggleSort={toggleSort} SortIndicator={SortIndicator} />
            <SortableHeader columnKey="byteCount" label="Bytes" toggleSort={toggleSort} SortIndicator={SortIndicator} />
          </tr>
        </thead>
        <tbody>
          {sorted.map((p) => {
            const pct = totalPackets > 0 ? ((p.packetCount / totalPackets) * 100).toFixed(1) : "0";
            return (
              <tr
                key={p.protocol}
                className={`border-b border-slate-800/50 hover:bg-slate-900/50 ${highlight ? "bg-amber-900/5" : ""}`}
              >
                <td className="py-3 pr-4">
                  <span className={`font-medium ${highlight ? "text-amber-300" : "text-white"}`}>
                    {p.protocol}
                  </span>
                </td>
                <td className="py-3 pr-4 text-white">{p.packetCount.toLocaleString()}</td>
                <td className="py-3 pr-4">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 bg-slate-800 rounded-full w-24 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${highlight ? "bg-amber-500" : "bg-cyan-500"}`}
                        style={{ width: `${Math.min(100, parseFloat(pct))}%` }}
                      />
                    </div>
                    <span className="text-slate-400 text-xs">{pct}%</span>
                  </div>
                </td>
                <td className="py-3 text-slate-400">{formatBytes(p.byteCount)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ──────────── Sortable column header ──────────── */

function SortableHeader({
  columnKey,
  label,
  toggleSort,
  SortIndicator,
}: {
  columnKey: string;
  label: string;
  toggleSort: (key: string) => void;
  SortIndicator: ReturnType<typeof useSort>["SortIndicator"];
}) {
  return (
    <th
      className="pb-3 pr-4 font-medium cursor-pointer select-none hover:text-slate-300 transition-colors"
      onClick={() => toggleSort(columnKey)}
    >
      {label}
      <SortIndicator columnKey={columnKey} />
    </th>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1000));
  return `${(bytes / Math.pow(1000, i)).toFixed(1)} ${units[i]}`;
}
