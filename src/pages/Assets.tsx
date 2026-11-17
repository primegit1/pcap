import { useMemo } from "react";
import { useAppContext } from "../context/AppContext";
import { CopyableValue } from "../components/shared/CopyableValue";
import { useSort } from "../components/shared/useSort";

export default function AssetsPage() {
  const { state } = useAppContext();
  const { sort, toggleSort, applySort, SortIndicator } = useSort("byteCount", "desc");

  const allHosts = useMemo(
    () =>
      Array.from(state.hosts.entries()).map(([ip, info]) => ({
        ip,
        mac: info.mac,
        packetCount: info.packetCount,
        byteCount: info.byteCount,
        protocols: info.protocols,
        firstSeenUs: info.firstSeenUs,
        lastSeenUs: info.lastSeenUs,
        isPrivate: info.isPrivate,
      })),
    [state.hosts]
  );

  const sortedHosts = applySort(allHosts, (h) => {
    if (sort.key === "packetCount") return h.packetCount;
    if (sort.key === "byteCount") return h.byteCount;
    if (sort.key === "ip") return h.ip;
    if (sort.key === "mac") return h.mac;
    return h.byteCount;
  });

  // Early return only after every hook has run (hooks may not be called conditionally).
  if (!state.result) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <svg className="w-12 h-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 17.25v-.228a4.5 4.5 0 00-.12-1.03l-2.268-9.64a3.375 3.375 0 00-3.285-2.602H7.923a3.375 3.375 0 00-3.285 2.602l-2.268 9.64a4.5 4.5 0 00-.12 1.03v.228m19.5 0a3 3 0 01-3 3H5.25a3 3 0 01-3-3m19.5 0a3 3 0 00-3-3H5.25a3 3 0 00-3 3m16.5 0h.008v.008h-.008v-.008zm-3 0h.008v.008h-.008v-.008z" />
        </svg>
        <p className="text-sm">No assets — upload a PCAP to begin analysis</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-6">
        <span className="text-sm text-slate-400">Total hosts:</span>
        <span className="text-white font-semibold">{allHosts.length}</span>
      </div>

      {allHosts.length === 0 ? (
        <div className="text-center py-16 text-slate-500">
          <p className="text-sm">No hosts discovered</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left text-slate-500">
                <SortableHeader columnKey="ip" label="IP Address" toggleSort={toggleSort} SortIndicator={SortIndicator} />
                <SortableHeader columnKey="mac" label="MAC" toggleSort={toggleSort} SortIndicator={SortIndicator} />
                <SortableHeader columnKey="packetCount" label="Packets" toggleSort={toggleSort} SortIndicator={SortIndicator} />
                <SortableHeader columnKey="byteCount" label="Bytes" toggleSort={toggleSort} SortIndicator={SortIndicator} />
                <th className="pb-3 pr-4 font-medium">Protocols</th>
                <th className="pb-3 font-medium">Private</th>
              </tr>
            </thead>
            <tbody>
              {sortedHosts.map((host) => (
                <tr key={host.ip} className="border-b border-slate-800/50 hover:bg-slate-900/50">
                  <td className="py-3 pr-4">
                    <CopyableValue value={host.ip} />
                  </td>
                  <td className="py-3 pr-4">
                    {host.mac ? (
                      <CopyableValue value={host.mac} className="text-xs" />
                    ) : (
                      <span className="text-slate-400 text-xs">-</span>
                    )}
                  </td>
                  <td className="py-3 pr-4 text-white">{host.packetCount.toLocaleString()}</td>
                  <td className="py-3 pr-4 text-white">{formatBytes(host.byteCount)}</td>
                  <td className="py-3 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {Array.from(host.protocols).filter(p => p !== "Unknown").map(p => (
                        <span key={p} className="px-1.5 py-0.5 rounded bg-slate-800 text-xs text-slate-400">
                          {p}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3">
                    {host.isPrivate ? (
                      <span className="text-green-400 text-xs">Yes</span>
                    ) : (
                      <span className="text-slate-600 text-xs">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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
