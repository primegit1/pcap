import { useState, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { useAppContext } from "../context/AppContext";
import type { Packet } from "../types/packets";
import { isClearTextProtocol, isOTProtocol } from "../types/packets";
import { CopyableValue } from "../components/shared/CopyableValue";

const PAGE_SIZE = 50;
const NO_PACKETS: Packet[] = [];

/** Optional navigation state set by the Findings page ("View packets"). */
interface PacketNavState {
  packetIndices?: number[];
  label?: string;
}

interface FilterState {
  protocol: string;
  srcIp: string;
  dstIp: string;
  port: string;
  search: string;
}

const emptyFilter: FilterState = {
  protocol: "",
  srcIp: "",
  dstIp: "",
  port: "",
  search: "",
};

export default function PacketViewerPage() {
  const { state } = useAppContext();
  const [currentPage, setCurrentPage] = useState(0);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);
  const [filter, setFilter] = useState<FilterState>(emptyFilter);
  const location = useLocation();
  const navState = location.state as PacketNavState | null;
  const [indexFilter, setIndexFilter] = useState<{ indices: Set<number>; label: string } | null>(
    navState?.packetIndices?.length
      ? { indices: new Set(navState.packetIndices), label: navState.label ?? "finding" }
      : null
  );

  // Hooks must run on every render, so the empty state is returned only after the last one.
  const allPackets = state.result?.packets ?? NO_PACKETS;


  // Derive unique values for filter dropdowns
  const { uniqueProtocols, uniqueSrcIps, uniqueDstIps } = useMemo(() => {
    const protos = new Set<string>();
    const srcs = new Set<string>();
    const dsts = new Set<string>();

    for (const pkt of allPackets) {
      protos.add(pkt.protocol);
      if (pkt.ip?.srcIp) srcs.add(pkt.ip.srcIp);
      if (pkt.ip?.dstIp) dsts.add(pkt.ip.dstIp);
    }

    return {
      uniqueProtocols: [...protos].sort(),
      uniqueSrcIps: [...srcs].sort(),
      uniqueDstIps: [...dsts].sort(),
    };
  }, [allPackets]);

  // Apply all filters (AND logic)
  const filtered = useMemo(() => {
    return allPackets.filter((pkt) => {
      // Packets referenced by a finding
      if (indexFilter && !indexFilter.indices.has(pkt.index)) return false;

      // Protocol filter
      if (filter.protocol && pkt.protocol !== filter.protocol) return false;

      // Source IP filter
      if (filter.srcIp) {
        const src = pkt.ip?.srcIp ?? "";
        if (!src.toLowerCase().includes(filter.srcIp.toLowerCase())) return false;
      }

      // Destination IP filter
      if (filter.dstIp) {
        const dst = pkt.ip?.dstIp ?? "";
        if (!dst.toLowerCase().includes(filter.dstIp.toLowerCase())) return false;
      }

      // Port filter
      if (filter.port) {
        const portNum = parseInt(filter.port, 10);
        if (!isNaN(portNum) && pkt.transport && "srcPort" in pkt.transport) {
          if (pkt.transport.srcPort !== portNum && pkt.transport.dstPort !== portNum) return false;
        }
      }

      // Text search filter
      if (filter.search) {
        const q = filter.search.toLowerCase();
        const matches =
          pkt.info.toLowerCase().includes(q) ||
          (pkt.ip?.srcIp ?? "").includes(q) ||
          (pkt.ip?.dstIp ?? "").includes(q) ||
          pkt.protocol.toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [allPackets, filter, indexFilter]);

  if (!state.result) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <svg className="w-12 h-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 6.75h12M8.25 12h12m-12 5.25h12M3.75 6.75h.007v.008H3.75V6.75zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zM3.75 12h.007v.008H3.75V12zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm-.375 5.25h.007v.008H3.75v-.008zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" />
        </svg>
        <p className="text-sm">No packets — upload a PCAP to begin analysis</p>
      </div>
    );
  }
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages - 1);
  const pagePackets = filtered.slice(
    safePage * PAGE_SIZE,
    (safePage + 1) * PAGE_SIZE
  );

  function setFilterField<K extends keyof FilterState>(key: K, value: FilterState[K]) {
    setFilter((prev) => ({ ...prev, [key]: value }));
    setCurrentPage(0);
  }

  function clearFilters() {
    setFilter(emptyFilter);
    setIndexFilter(null);
    setCurrentPage(0);
  }

  const hasActiveFilters =
    filter.protocol || filter.srcIp || filter.dstIp || filter.port || filter.search || indexFilter;

  return (
    <div>
      {indexFilter && (
        <div className="mb-4 flex items-center justify-between gap-3 rounded-lg border border-cyan-500/40 bg-cyan-500/5 px-4 py-2 text-xs text-cyan-300">
          <span className="truncate">
            Showing packets referenced by: <span className="font-medium">{indexFilter.label}</span>
          </span>
          <button
            onClick={() => {
              setIndexFilter(null);
              setCurrentPage(0);
            }}
            className="shrink-0 text-slate-400 hover:text-cyan-300 transition-colors"
          >
            Show all packets
          </button>
        </div>
      )}

      {/* ── Page header ── */}
      <div className="flex items-center justify-between mb-4">
        <span className="text-sm text-slate-400">
          {filtered.length.toLocaleString()} packets
          {hasActiveFilters && ` (filtered from ${allPackets.length.toLocaleString()})`}
        </span>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="text-xs text-slate-500 hover:text-cyan-400 transition-colors"
          >
            Clear all filters
          </button>
        )}
      </div>

      {/* ── Filter bar ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2 mb-4">
        {/* Protocol select */}
        <select
          value={filter.protocol}
          onChange={(e) => setFilterField("protocol", e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500/50"
          aria-label="Filter by protocol"
        >
          <option value="">All Protocols</option>
          {uniqueProtocols.map((proto) => (
            <option key={proto} value={proto}>
              {proto}
            </option>
          ))}
        </select>

        {/* Source IP with datalist */}
        <div className="relative">
          <input
            type="text"
            list="srcIpList"
            placeholder="Source IP..."
            value={filter.srcIp}
            onChange={(e) => setFilterField("srcIp", e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            aria-label="Filter by source IP"
          />
          <datalist id="srcIpList">
            {uniqueSrcIps.map((ip) => (
              <option key={ip} value={ip} />
            ))}
          </datalist>
        </div>

        {/* Destination IP with datalist */}
        <div className="relative">
          <input
            type="text"
            list="dstIpList"
            placeholder="Dest. IP..."
            value={filter.dstIp}
            onChange={(e) => setFilterField("dstIp", e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
            aria-label="Filter by destination IP"
          />
          <datalist id="dstIpList">
            {uniqueDstIps.map((ip) => (
              <option key={ip} value={ip} />
            ))}
          </datalist>
        </div>

        {/* Port filter */}
        <input
          type="text"
          inputMode="numeric"
          placeholder="Port..."
          value={filter.port}
          onChange={(e) => setFilterField("port", e.target.value.replace(/\D/g, ""))}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          aria-label="Filter by port number"
        />

        {/* Text search */}
        <input
          type="text"
          placeholder="Search text..."
          value={filter.search}
          onChange={(e) => setFilterField("search", e.target.value)}
          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          aria-label="Search in packet info, IP, or protocol"
        />
      </div>

      {/* ── Empty state ── */}
      {filtered.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-slate-500">
          <svg className="w-10 h-10 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <p className="text-sm mb-1">No packets match your filters</p>
          <button
            onClick={clearFilters}
            className="text-xs text-cyan-500 hover:text-cyan-400 transition-colors"
          >
            Clear filters to see all packets
          </button>
        </div>
      )}

      {/* ── Packet table ── */}
      {filtered.length > 0 && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-slate-500">
                  <th className="pb-3 pr-3 font-medium w-12">#</th>
                  <th className="pb-3 pr-3 font-medium">Timestamp</th>
                  <th className="pb-3 pr-3 font-medium">Source</th>
                  <th className="pb-3 pr-3 font-medium">Destination</th>
                  <th className="pb-3 pr-3 font-medium">Protocol</th>
                  <th className="pb-3 pr-3 font-medium">Length</th>
                  <th className="pb-3 font-medium">Info</th>
                </tr>
              </thead>
              <tbody>
                {pagePackets.map((pkt) => (
                  <PacketRow
                    key={pkt.index}
                    packet={pkt}
                    isExpanded={expandedIndex === pkt.index}
                    onToggle={() =>
                      setExpandedIndex(
                        expandedIndex === pkt.index ? null : pkt.index
                      )
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* ── Pagination ── */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-slate-800">
              <span className="text-xs text-slate-500">
                Page {safePage + 1} of {totalPages}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setCurrentPage(Math.max(0, safePage - 1))}
                  disabled={safePage === 0}
                  className="px-3 py-1 rounded bg-slate-800 text-sm text-slate-300 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Previous
                </button>
                <button
                  onClick={() => setCurrentPage(Math.min(totalPages - 1, safePage + 1))}
                  disabled={safePage >= totalPages - 1}
                  className="px-3 py-1 rounded bg-slate-800 text-sm text-slate-300 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ──────────────────────── Row Components ──────────────────────── */

function PacketRow({
  packet,
  isExpanded,
  onToggle,
}: {
  packet: Packet;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const ts = packet.timestampUs > 0
    ? new Date(Math.floor(packet.timestampUs / 1000)).toLocaleTimeString()
    : "-";

  return (
    <>
      <tr
        className="border-b border-slate-800/50 hover:bg-slate-900/50 cursor-pointer"
        onClick={onToggle}
      >
        <td className="py-2 pr-3 text-slate-500 text-xs">{packet.index}</td>
        <td className="py-2 pr-3 text-slate-400 text-xs">{ts}</td>
        <td className="py-2 pr-3">
          <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
            <CopyableValue value={packet.ip?.srcIp ?? ""} />
          </span>
          {packet.transport && "srcPort" in packet.transport && (
            <span className="text-slate-600 ml-1">:{packet.transport.srcPort}</span>
          )}
        </td>
        <td className="py-2 pr-3">
          <span className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
            <CopyableValue value={packet.ip?.dstIp ?? ""} />
          </span>
          {packet.transport && "srcPort" in packet.transport && (
            <span className="text-slate-600 ml-1">:{packet.transport.dstPort}</span>
          )}
        </td>
        <td className="py-2 pr-3">
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-xs text-slate-300">
            {packet.protocol}
          </span>
        </td>
        <td className="py-2 pr-3 text-slate-400 text-xs">{packet.length}</td>
        <td className="py-2 text-slate-400 text-xs truncate max-w-xs">{packet.info}</td>
      </tr>

      {isExpanded && (
        <ExpandedDetails packet={packet} />
      )}
    </>
  );
}

/* ──────────────────── Expanded Packet Details ──────────────────── */

function ExpandedDetails({ packet }: { packet: Packet }) {
  const [highlightRange, setHighlightRange] = useState<{ start: number; end: number } | null>(null);

  // Compute layer byte boundaries within the raw frame
  const layers = useMemo(() => {
    const ranges: { name: string; start: number; end: number; color: string }[] = [];
    let pos = 0;
    if (packet.ethernet) {
      const ethEnd = packet.ethernet.payloadOffset;
      ranges.push({ name: "Ethernet", start: pos, end: ethEnd, color: "text-sky-400" });
      pos = ethEnd;

      if (packet.ip) {
        const ipEnd = pos + packet.ip.payloadOffset;
        ranges.push({ name: `IPv${packet.ip.version}`, start: pos, end: ipEnd, color: "text-green-400" });

        if (packet.transport) {
          let transportHeaderLen = 0;
          if ("payloadOffset" in packet.transport) {
            transportHeaderLen = packet.transport.payloadOffset;
          }
          const tEnd = ipEnd + transportHeaderLen;
          const protoName = "srcPort" in packet.transport ? "TCP/UDP" :
            "type" in packet.transport ? "ICMP" : "L4";
          ranges.push({ name: protoName, start: ipEnd, end: tEnd, color: "text-amber-400" });
          pos = tEnd;

          // App payload
          let appLen = 0;
          if ("payloadLength" in packet.transport && typeof packet.transport.payloadLength === "number") {
            appLen = packet.transport.payloadLength;
          }
          if (appLen > 0 && tEnd + appLen <= packet.raw.byteLength) {
            ranges.push({ name: "Payload", start: tEnd, end: tEnd + appLen, color: "text-slate-300" });
          }
        }
      }
    }
    // Remainder of frame
    if (pos < packet.raw.byteLength) {
      ranges.push({ name: "Rest", start: pos, end: packet.raw.byteLength, color: "text-slate-600" });
    }
    return ranges;
  }, [packet]);

  /** Map a byte offset to its layer color */
  function getByteColor(offset: number): string {
    for (const l of layers) {
      if (offset >= l.start && offset < l.end) return l.color;
    }
    return "text-slate-600";
  }

  return (
    <tr className="bg-slate-900/70">
      <td colSpan={7} className="p-4">
        <h4 className="text-white text-sm font-medium mb-3">Packet Details</h4>

        {/* ── Hex Dump (moved to top) ── */}
        <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 mb-4">
          <div className="flex items-center justify-between mb-2">
            <h5 className="text-slate-400 font-medium uppercase tracking-wider text-[10px]">Raw Frame</h5>
            <div className="flex items-center gap-2">
              <CopyHexButton data={packet.raw} />
              <CopyBase64Button data={packet.raw} />
            </div>
          </div>
          {/* Layer legend */}
          <div className="flex flex-wrap gap-x-4 gap-y-0.5 mb-2">
            {layers.map((l) => (
              <div key={l.name} className="flex items-center gap-1">
                <span className={l.color + " text-[10px] font-medium"}>{l.name}</span>
                <span className="text-[9px] text-slate-600">[{l.start}–{l.end - 1}]</span>
              </div>
            ))}
            {highlightRange && (
              <button
                onClick={() => setHighlightRange(null)}
                className="text-[9px] text-cyan-400 hover:text-cyan-300"
              >
                Clear highlight
              </button>
            )}
          </div>
          <ColorizedHexDump
            data={packet.raw}
            maxBytes={256}
            getByteColor={getByteColor}
            highlightRange={highlightRange}
          />
        </div>

        {/* ── App Payload Decoder ── */}
        {packet.appPayload && packet.appPayload.byteLength > 0 && (
          <DecodedPayload packet={packet} />
        )}

        {/* ── Structured Fields (clickable to highlight) ── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {packet.ethernet && (
            <div className="bg-slate-950 rounded-lg p-3 border border-slate-800">
              <h5 className="text-sky-400 font-medium mb-2 uppercase tracking-wider text-[10px]">Ethernet</h5>
              <dl className="space-y-1">
                <HighlightRow
                  label="Source MAC"
                  value={packet.ethernet.srcMac}
                  rangeStart={6}
                  rangeLen={6}
                  onHover={setHighlightRange}
                />
                <HighlightRow
                  label="Dest MAC"
                  value={packet.ethernet.dstMac}
                  rangeStart={0}
                  rangeLen={6}
                  onHover={setHighlightRange}
                />
                <HighlightRow
                  label="EtherType"
                  value={`0x${packet.ethernet.etherType.toString(16).padStart(4, "0")}`}
                  rangeStart={12}
                  rangeLen={2}
                  onHover={setHighlightRange}
                />
              </dl>
            </div>
          )}

          {packet.ip && (
            <div className="bg-slate-950 rounded-lg p-3 border border-slate-800">
              <h5 className="text-green-400 font-medium mb-2 uppercase tracking-wider text-[10px]">IPv{packet.ip.version}</h5>
              <dl className="space-y-1">
                <HighlightRow
                  label="Source IP"
                  value={packet.ip.srcIp}
                  rangeStart={packet.ethernet ? packet.ethernet.payloadOffset + 12 : 0}
                  rangeLen={4}
                  onHover={setHighlightRange}
                />
                <HighlightRow
                  label="Dest IP"
                  value={packet.ip.dstIp}
                  rangeStart={packet.ethernet ? packet.ethernet.payloadOffset + 16 : 0}
                  rangeLen={4}
                  onHover={setHighlightRange}
                />
                {"ttl" in packet.ip && (
                  <HighlightRow
                    label="TTL"
                    value={String(packet.ip.ttl)}
                    rangeStart={packet.ethernet ? packet.ethernet.payloadOffset + 8 : 0}
                    rangeLen={1}
                    onHover={setHighlightRange}
                  />
                )}
                {"hopLimit" in packet.ip && (
                  <HighlightRow
                    label="Hop Limit"
                    value={String(packet.ip.hopLimit)}
                    rangeStart={packet.ethernet ? packet.ethernet.payloadOffset + 7 : 0}
                    rangeLen={1}
                    onHover={setHighlightRange}
                  />
                )}
                <HighlightRow
                  label="Protocol"
                  value={String(packet.ip.protocol)}
                  rangeStart={packet.ethernet ? packet.ethernet.payloadOffset + 9 : 0}
                  rangeLen={1}
                  onHover={setHighlightRange}
                />
              </dl>
            </div>
          )}

          {packet.transport && (
            <div className="bg-slate-950 rounded-lg p-3 border border-slate-800">
              <h5 className="text-amber-400 font-medium mb-2 uppercase tracking-wider text-[10px]">Transport</h5>
              <dl className="space-y-1">
                {"srcPort" in packet.transport && (() => {
                  const base = packet.ethernet
                    ? packet.ethernet.payloadOffset + (packet.ip ? packet.ip.payloadOffset : 0)
                    : 0;
                  return (
                    <>
                      <HighlightRow label="Source Port" value={String(packet.transport.srcPort)} rangeStart={base} rangeLen={2} onHover={setHighlightRange} />
                      <HighlightRow label="Dest Port" value={String(packet.transport.dstPort)} rangeStart={base + 2} rangeLen={2} onHover={setHighlightRange} />
                      {"syn" in packet.transport && (
                        <HighlightRow
                          label="Flags"
                          value={[
                            packet.transport.syn ? "SYN" : null,
                            packet.transport.ack ? "ACK" : null,
                            packet.transport.fin ? "FIN" : null,
                            packet.transport.rst ? "RST" : null,
                            packet.transport.psh ? "PSH" : null,
                          ].filter(Boolean).join(" ")}
                          rangeStart={base + 13}
                          rangeLen={1}
                          onHover={setHighlightRange}
                        />
                      )}
                    </>
                  );
                })()}
                {"type" in packet.transport && (
                  <Row label="ICMP Type" value={String(packet.transport.type)} />
                )}
                {"code" in packet.transport && (
                  <Row label="ICMP Code" value={String(packet.transport.code)} />
                )}
              </dl>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

/* ──────────────────── Colorized Hex Dump ──────────────────── */

function ColorizedHexDump({
  data,
  maxBytes = 256,
  getByteColor,
  highlightRange,
}: {
  data: ArrayBuffer;
  maxBytes?: number;
  getByteColor: (offset: number) => string;
  highlightRange: { start: number; end: number } | null;
}) {
  const bytes = new Uint8Array(data.slice(0, maxBytes));

  // Build rows with offsets
  const rows: { offset: number; hexCols: string[]; hexColors: string[]; ascii: string; asciiHigh: boolean[] }[] = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const slice = Array.from(bytes.slice(i, i + 16));
    const hexCols = slice.map((b) => b.toString(16).padStart(2, "0"));
    const hexColors = slice.map((_, j) => getByteColor(i + j));
    const ascii = slice.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");

    let asciiHigh: boolean[] = [];
    if (highlightRange) {
      asciiHigh = slice.map((_, j) => {
        const bo = i + j;
        return bo >= highlightRange.start && bo < highlightRange.end;
      });
    }

    rows.push({ offset: i, hexCols, hexColors, ascii, asciiHigh });
  }

  // Split hex into groups of 2 for readability (8+8 = two groups of 8 bytes)
  return (
    <pre className="text-[10px] font-mono leading-[1.65] text-slate-400 overflow-x-auto select-none">
      {rows.map((row, ri) => {
        // Build hex part with color spans
        const hexParts: JSX.Element[] = [];
        for (let g = 0; g < 2; g++) {
          for (let b = 0; b < 8; b++) {
            const idx = g * 8 + b;
            if (idx >= row.hexCols.length) break;
            const isHighlighted = highlightRange
              ? (row.offset + idx >= highlightRange.start && row.offset + idx < highlightRange.end)
              : false;
            hexParts.push(
              <span
                key={idx}
                className={
                  isHighlighted
                    ? "bg-cyan-500/30 text-white rounded-sm"
                    : row.hexColors[idx]
                }
              >
                {row.hexCols[idx]}
              </span>
            );
            if (idx < row.hexCols.length - 1) hexParts.push(<span key={`sp-${idx}`}> </span>);
          }
          if (g === 0 && row.hexCols.length > 8) {
            hexParts.push(<span key="mid" className="mr-1"> </span>);
          }
        }

        // Pad if row has < 16 bytes

        return (
          <div key={ri} className="whitespace-pre">
            <span className="text-slate-600 select-none">{row.offset.toString(16).padStart(4, "0").toUpperCase()}</span>
            <span className="text-slate-700 select-none">  </span>
            {hexParts}
            <span className="text-slate-700 select-none">  </span>
            {/* ASCII column with highlight */}
            <span>
              {Array.from(row.ascii).map((ch, ai) => {
                const isHigh = row.asciiHigh[ai];
                return (
                  <span
                    key={ai}
                    className={
                      isHigh
                        ? "bg-cyan-500/30 text-white"
                        : "text-slate-400"
                    }
                  >
                    {ch}
                  </span>
                );
              })}
            </span>
          </div>
        );
      })}
      {bytes.length < data.byteLength && (
        <div className="text-slate-600 mt-1">
          ... {data.byteLength - bytes.length} more bytes not shown (showing first {maxBytes})
        </div>
      )}
    </pre>
  );
}

/* ──────────────────── Copy Buttons ──────────────────── */

function CopyHexButton({ data }: { data: ArrayBuffer }) {
  const [copied, setCopied] = useState(false);
  const bytes = new Uint8Array(data.slice(0, 256));

  function handleCopy() {
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    navigator.clipboard.writeText(hex).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      onClick={handleCopy}
      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 rounded text-[10px] text-slate-400 hover:text-white transition-colors"
      title="Copy hex bytes to clipboard"
    >
      {copied ? "Copied!" : "Copy Hex"}
    </button>
  );
}

function CopyBase64Button({ data }: { data: ArrayBuffer }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    const bytes = new Uint8Array(data.slice(0, 256));
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const b64 = btoa(binary);
    navigator.clipboard.writeText(b64).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      onClick={handleCopy}
      className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 rounded text-[10px] text-slate-400 hover:text-white transition-colors"
      title="Copy base64-encoded frame to clipboard"
    >
      {copied ? "Copied!" : "Copy Base64"}
    </button>
  );
}

/* ──────────────────── Highlightable Row ──────────────────── */

function HighlightRow({
  label,
  value,
  rangeStart,
  rangeLen,
  onHover,
}: {
  label: string;
  value: string;
  rangeStart: number;
  rangeLen: number;
  onHover: React.Dispatch<React.SetStateAction<{ start: number; end: number } | null>>;
}) {
  return (
    <div
      className="flex justify-between group cursor-pointer"
      onMouseEnter={() => onHover({ start: rangeStart, end: rangeStart + rangeLen })}
      onMouseLeave={() => onHover(null)}
      title={`Bytes ${rangeStart}–${rangeStart + rangeLen - 1} in raw frame`}
    >
      <span className="text-slate-500 group-hover:text-cyan-400 transition-colors">{label}</span>
      <span className="text-cyan-300 font-mono group-hover:text-white transition-colors">{value}</span>
    </div>
  );
}

/* ──────────────────── Decoded Payload ──────────────────── */

function DecodedPayload({ packet }: { packet: Packet }) {
  const payload = packet.appPayload!;
  const isText = isClearTextProtocol(packet.protocol);
  const isOT = isOTProtocol(packet.protocol);

  let headerLabel = "Application Payload";
  if (isText) headerLabel = `${packet.protocol} Payload (decoded)`;
  else if (isOT) headerLabel = `${packet.protocol} Payload`;

  return (
    <div className="mb-4 bg-slate-950 rounded-lg p-3 border border-slate-800">
      <div className="flex items-center justify-between mb-2">
        <h5 className="text-slate-400 font-medium uppercase tracking-wider text-[10px]">{headerLabel}</h5>
        <span className="text-[10px] text-slate-600">{payload.byteLength} bytes</span>
      </div>
      {isText && <TextPayloadView data={payload} />}
      {isOT && <HexPayloadView data={payload} />}
      {!isText && !isOT && <HexDump data={payload} maxBytes={256} />}
    </div>
  );
}

/* ──────────────────── Text / Hex Payload Views ──────────────────── */

function TextPayloadView({ data }: { data: ArrayBuffer }) {
  const bytes = new Uint8Array(data);
  const text = Array.from(bytes)
    .map((b) => {
      if (b === 0x0a || b === 0x0d || b === 0x09) return String.fromCharCode(b);
      if (b >= 32 && b <= 126) return String.fromCharCode(b);
      return `.`;
    })
    .join("");
  return (
    <pre className="text-[11px] font-mono leading-relaxed text-emerald-300 whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
      {text}
    </pre>
  );
}

function HexPayloadView({ data }: { data: ArrayBuffer }) {
  const bytes = new Uint8Array(data);
  const lines: string[] = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${ascii}`);
  }

  return (
    <pre className="text-[10px] font-mono leading-relaxed text-amber-300/80 overflow-x-auto">
      {lines.join("\n")}
    </pre>
  );
}

/* ──────────────────── Generic Row ──────────────────── */

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-slate-500">{label}</span>
      <span className="text-cyan-300 font-mono">{value}</span>
    </div>
  );
}

/* ──────────────────── Basic Hex Dump (non-colorized) ──────────────────── */

function HexDump({ data, maxBytes }: { data: ArrayBuffer; maxBytes: number }) {
  const bytes = new Uint8Array(data.slice(0, maxBytes));
  const lines: string[] = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48)}  ${ascii}`);
  }

  return (
    <pre className="text-[10px] font-mono leading-relaxed text-slate-400 overflow-x-auto">
      {lines.join("\n")}
    </pre>
  );
}
