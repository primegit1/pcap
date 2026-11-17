import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useAppContext } from "../context/AppContext";
import type { SecurityFinding } from "../types/analysis";
import { FindingCategory } from "../types/analysis";
import { CopyableValue } from "../components/shared/CopyableValue";

type SortKey = "severity" | "category" | "newest" | "oldest";

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

const ALL_CATEGORIES = Object.values(FindingCategory);

export default function FindingsPage() {
  const { state } = useAppContext();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const severityCounts = {
    Critical: state.findings.filter(f => f.severity === "Critical").length,
    High: state.findings.filter(f => f.severity === "High").length,
    Medium: state.findings.filter(f => f.severity === "Medium").length,
    Low: state.findings.filter(f => f.severity === "Low").length,
    Info: state.findings.filter(f => f.severity === "Info").length,
  };

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const cat of ALL_CATEGORIES) {
      counts[cat] = state.findings.filter(f => f.category === cat).length;
    }
    return counts;
  }, [state.findings]);

  // Apply filters + sort
  const processedFindings = useMemo(() => {
    let filtered = state.findings;

    // Severity filter
    if (filterSeverity) {
      filtered = filtered.filter(f => f.severity === filterSeverity);
    }

    // Category filter
    if (filterCategory) {
      filtered = filtered.filter(f => f.category === filterCategory);
    }

    // Text search (title + description + affectedIp)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(
        f =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.affectedIp.toLowerCase().includes(q)
      );
    }

    // Sort
    const sorted = [...filtered];
    switch (sortKey) {
      case "severity":
        sorted.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
        break;
      case "category":
        sorted.sort((a, b) => a.category.localeCompare(b.category));
        break;
      case "newest":
        sorted.sort((a, b) => b.timestamp - a.timestamp);
        break;
      case "oldest":
        sorted.sort((a, b) => a.timestamp - b.timestamp);
        break;
    }

    return sorted;
  }, [state.findings, filterSeverity, filterCategory, searchQuery, sortKey]);

  const activeFilterCount =
    (filterSeverity ? 1 : 0) + (filterCategory ? 1 : 0) + (searchQuery.trim() ? 1 : 0);
  const totalCriticalAndHigh = severityCounts.Critical + severityCounts.High;

  // Early return only after every hook has run (hooks may not be called conditionally).
  if (!state.result) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-slate-500">
        <svg className="w-12 h-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
        </svg>
        <p className="text-sm text-slate-500">No findings — upload a PCAP to begin analysis</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-white">Security Findings</h2>
          <span className="text-sm text-slate-500 bg-slate-800/60 px-2.5 py-0.5 rounded-md">
            {state.findings.length} total
          </span>
          {totalCriticalAndHigh > 0 && (
            <span className="text-sm text-red-400 bg-red-900/20 px-2.5 py-0.5 rounded-md border border-red-800/40">
              {totalCriticalAndHigh} critical/high
            </span>
          )}
        </div>

        {/* Sort dropdown */}
        <div className="flex items-center gap-2">
          <label htmlFor="findings-sort" className="text-xs text-slate-500">Sort:</label>
          <select
            id="findings-sort"
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-white focus:outline-none focus:border-cyan-500/50"
          >
            <option value="severity">Severity (highest)</option>
            <option value="category">Category (A-Z)</option>
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </div>
      </div>

      {/* Filter bar — row 1: search + clear */}
      <div className="flex items-center gap-2 mb-3">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        {activeFilterCount > 0 && (
          <button
            onClick={() => {
              setFilterSeverity(null);
              setFilterCategory(null);
              setSearchQuery("");
            }}
            className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors whitespace-nowrap"
          >
            Clear all ({activeFilterCount})
          </button>
        )}
      </div>

      {/* Filter bar — row 2: severity + category pills */}
      <div className="flex flex-wrap items-center gap-1.5 mb-5">
        {/* Severity pills */}
        <span className="text-[10px] text-slate-600 mr-1 uppercase tracking-wider">Severity</span>
        <button
          onClick={() => setFilterSeverity(null)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-all duration-150 ${
            filterSeverity === null
              ? "bg-slate-700 text-white"
              : "bg-slate-800/50 text-slate-400 hover:text-slate-300"
          }`}
        >
          All
        </button>
        {(["Critical", "High", "Medium", "Low", "Info"] as const).map((sev) => {
          if (severityCounts[sev] === 0) return null;
          return (
            <button
              key={sev}
              onClick={() => setFilterSeverity(filterSeverity === sev ? null : sev)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all duration-150 ${
                filterSeverity === sev
                  ? getSeverityBtnActive(sev)
                  : getSeverityBtnInactive(sev)
              }`}
            >
              {sev} ({severityCounts[sev]})
            </button>
          );
        })}

        {/* Separator */}
        <span className="w-px h-4 bg-slate-800 mx-2" />

        {/* Category pills */}
        <span className="text-[10px] text-slate-600 mr-1 uppercase tracking-wider">Category</span>
        <button
          onClick={() => setFilterCategory(null)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-all duration-150 ${
            filterCategory === null
              ? "bg-slate-700 text-white"
              : "bg-slate-800/50 text-slate-400 hover:text-slate-300"
          }`}
        >
          All
        </button>
        {ALL_CATEGORIES.map((cat) => {
          if (categoryCounts[cat] === 0) return null;
          return (
            <button
              key={cat}
              onClick={() => setFilterCategory(filterCategory === cat ? null : cat)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-all duration-150 ${
                filterCategory === cat
                  ? "bg-slate-700 text-white"
                  : "bg-slate-800/50 text-slate-400 hover:text-slate-300"
              }`}
            >
              {cat} ({categoryCounts[cat]})
            </button>
          );
        })}
      </div>

      {/* Empty state */}
      {processedFindings.length === 0 ? (
        <div className="text-center py-20 text-slate-500">
          {activeFilterCount > 0 ? (
            <>
              <svg className="w-10 h-10 mx-auto mb-3 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9 5.25h.008v.008H12v-.008z" />
              </svg>
              <p className="text-sm">No findings match your filters</p>
              <button
                onClick={() => { setFilterSeverity(null); setFilterCategory(null); setSearchQuery(""); }}
                className="mt-3 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Clear all filters
              </button>
            </>
          ) : (
            <p className="text-sm text-slate-500">No security findings detected — clean traffic</p>
          )}
        </div>
      ) : (
        /* Finding list as cards */
        <div className="space-y-2">
          {processedFindings.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              isExpanded={expandedId === f.id}
              onToggle={() => toggleExpand(f.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/* ========= Single finding card (expandable) ========= */

function FindingCard({
  finding,
  isExpanded,
  onToggle,
}: {
  finding: SecurityFinding;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const navigate = useNavigate();
  const packetCount = finding.packetIndices?.length ?? 0;
  const severityColors: Record<string, string> = {
    Critical: "border-l-red-500 bg-red-900/5",
    High: "border-l-orange-500 bg-orange-900/5",
    Medium: "border-l-yellow-500 bg-yellow-900/5",
    Low: "border-l-blue-400 bg-blue-900/5",
    Info: "border-l-slate-500 bg-slate-800/20",
  };

  return (
    <div
      className={`border border-slate-800 rounded-lg border-l-4 overflow-hidden transition-all duration-150 ${
        severityColors[finding.severity] || severityColors.Info
      }`}
    >
      {/* Clickable header — disclosure button */}
      <button
        onClick={onToggle}
        aria-expanded={isExpanded}
        aria-controls={`finding-detail-${finding.id}`}
        className="w-full flex items-center gap-3 px-4 py-3 text-left cursor-pointer hover:bg-white/[0.02] transition-colors duration-150"
      >
        {/* Chevron */}
        <svg
          className={`w-4 h-4 text-slate-500 shrink-0 transition-transform duration-200 ${
            isExpanded ? "rotate-90" : ""
          }`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>

        {/* Severity badge */}
        <SeverityBadge severity={finding.severity} />

        {/* Title */}
        <span className="text-sm font-medium text-white flex-1 min-w-0 truncate">
          {finding.title}
        </span>

        {/* Category chip */}
        <span className="hidden sm:inline-block text-[11px] text-slate-500 bg-slate-800/60 px-2 py-0.5 rounded shrink-0">
          {finding.category}
        </span>

        {/* Affected IP — now copyable */}
        <span className="hidden md:inline-flex shrink-0" onClick={(e) => e.stopPropagation()}>
          <CopyableValue value={finding.affectedIp} />
        </span>

        {/* Timestamp */}
        <span className="hidden lg:inline-block text-[11px] text-slate-600 shrink-0">
          {formatTimestamp(finding.timestamp)}
        </span>
      </button>

      {/* Expandable detail panel */}
      <div
        id={`finding-detail-${finding.id}`}
        role="region"
        aria-labelledby={`finding-header-${finding.id}`}
        className={`transition-all duration-200 ease-out overflow-hidden ${
          isExpanded ? "max-h-[900px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <div className="px-4 pb-4 pt-1 border-t border-slate-800/50">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Left column: Description + Evidence */}
            <div className="space-y-3">
              {/* Description */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  What happened
                </h4>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {finding.description}
                </p>
              </div>

              {/* Evidence */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Evidence
                </h4>
                <div className="bg-slate-900/80 border border-slate-800 rounded-md px-3 py-2">
                  <code className="text-xs text-slate-300 break-all leading-relaxed whitespace-pre-wrap">
                    {finding.evidence}
                  </code>
                </div>
              </div>

              {/* Metadata */}
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                <span>
                  Affected IP: <CopyableValue value={finding.affectedIp} />
                </span>
                <span>Category: {finding.category}</span>
                <span>ID: {finding.id}</span>
                {finding.confidence && <span>Confidence: {finding.confidence}</span>}
                {(finding.occurrences ?? 1) > 1 && <span>Occurrences: {finding.occurrences}</span>}
                {finding.firstSeenUs !== undefined && finding.firstSeenUs > 0 && (
                  <span>
                    {formatTimestamp(finding.firstSeenUs / 1000)}
                    {finding.lastSeenUs !== undefined && finding.lastSeenUs !== finding.firstSeenUs
                      ? ` → ${formatTimestamp(finding.lastSeenUs / 1000)}`
                      : ""}
                  </span>
                )}
              </div>

              {packetCount > 0 && (
                <button
                  onClick={() =>
                    navigate("/packets", {
                      state: { packetIndices: finding.packetIndices, label: finding.title },
                    })
                  }
                  title={
                    finding.refsApproximate
                      ? "The rule did not record exact packets; these are packets involving the affected IP."
                      : "Packets that triggered this finding"
                  }
                  className="text-xs px-3 py-1.5 rounded-lg glass-border text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  View {packetCount}
                  {packetCount >= 50 ? "+" : ""} {finding.refsApproximate ? "related" : ""} packet
                  {packetCount === 1 ? "" : "s"}
                </button>
              )}
            </div>

            {/* Right column: Recommendation */}
            <div>
              <h4 className="text-xs font-semibold text-emerald-400/90 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                </svg>
                Recommendation
              </h4>
              <div className="bg-slate-900/50 border border-slate-800/70 rounded-md px-3 py-2.5">
                {finding.recommendation ? (
                  <ul className="space-y-1.5">
                    {finding.recommendation
                      .split("\n")
                      .filter((line) => line.trim())
                      .map((line, i) => {
                        const content = line.replace(/^\d+\.\s*/, "").trim();
                        const isHeader = content.endsWith(":") || content.startsWith("Immediately");
                        return (
                          <li
                            key={i}
                            className={`text-xs leading-relaxed pl-4 relative before:absolute before:left-0 before:top-[5px] before:w-1.5 before:h-1.5 before:rounded-full ${
                              isHeader
                                ? "text-emerald-300 font-medium before:bg-emerald-400"
                                : "text-slate-300 before:bg-slate-600"
                            }`}
                          >
                            {content}
                          </li>
                        );
                      })}
                  </ul>
                ) : (
                  <p className="text-xs text-slate-500 italic">No specific recommendation available.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ========= Severity badge ========= */

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    Critical: "bg-red-900/30 text-red-400 border-red-800/50",
    High: "bg-orange-900/30 text-orange-400 border-orange-800/50",
    Medium: "bg-yellow-900/30 text-yellow-400 border-yellow-800/50",
    Low: "bg-blue-900/30 text-blue-400 border-blue-800/50",
    Info: "bg-slate-800 text-slate-400 border-slate-700",
  };

  return (
    <span
      className={`shrink-0 px-2 py-0.5 rounded text-xs font-medium border ${colors[severity] || colors.Info}`}
    >
      {severity}
    </span>
  );
}

/* ========= Helpers ========= */

function getSeverityBtnActive(sev: string): string {
  const map: Record<string, string> = {
    Critical: "bg-red-900/40 text-red-300 border border-red-800/40",
    High: "bg-orange-900/40 text-orange-300 border border-orange-800/40",
    Medium: "bg-yellow-900/40 text-yellow-300 border border-yellow-800/40",
    Low: "bg-blue-900/40 text-blue-300 border border-blue-800/40",
    Info: "bg-slate-700 text-slate-300 border border-slate-600",
  };
  return map[sev] ?? "bg-slate-700 text-white";
}

function getSeverityBtnInactive(sev: string): string {
  const map: Record<string, string> = {
    Critical: "text-red-400/60 hover:text-red-400",
    High: "text-orange-400/60 hover:text-orange-400",
    Medium: "text-yellow-400/60 hover:text-yellow-400",
    Low: "text-blue-400/60 hover:text-blue-400",
    Info: "text-slate-400/60 hover:text-slate-400",
  };
  return map[sev] ?? "text-slate-500 hover:text-slate-300";
}

function formatTimestamp(ts: number): string {
  if (!ts || ts <= 0) return "";
  try {
    // Capture time (not analysis time), so include the date.
    return new Date(ts).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
  } catch {
    return "";
  }
}
