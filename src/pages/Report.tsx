import { useNavigate } from "react-router-dom";
import { useAppContext } from "../context/AppContext";
import { StatCard } from "../components/dashboard/StatCard";
import { TimelineChart } from "../components/dashboard/TimelineChart";
import { NarrativeSection } from "../components/report/NarrativeSection";
import { DonutChart } from "../components/report/DonutChart";
import { SeverityBar } from "../components/report/SeverityBar";
import { TopTalkerBarChart } from "../components/report/TopTalkerBarChart";
import { formatBytes, formatDuration, formatNumber } from "../utils/format";
import {
  generateExecutiveSummary,
  generateTrafficNarrative,
  generateProtocolNarrative,
  generateSecurityPosture,
  generateNotableObservations,
} from "../utils/report-narrative";

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#22d3ee",
  UDP: "#60a5fa",
  HTTP: "#34d399",
  "HTTPS/TLS": "#818cf8",
  DNS: "#a78bfa",
  ICMP: "#fbbf24",
  ARP: "#f472b6",
  SSH: "#fb923c",
  SMB: "#94a3b8",
  DHCP: "#2dd4bf",
  SSDP: "#c084fc",
  LLMNR: "#38bdf8",
  mDNS: "#4ade80",
  IGMP: "#f87171",
  NTP: "#a8a29e",
  SMTP: "#e879f9",
  IMAP: "#f0abfc",
  FTP: "#fdba74",
  Telnet: "#f97316",
  RDP: "#7dd3fc",
  VNC: "#38bdf8",
  MySQL: "#4ade80",
  PostgreSQL: "#60a5fa",
  MSSQL: "#a78bfa",
  Elasticsearch: "#facc15",
  Redis: "#ef4444",
  MongoDB: "#22c55e",
  MQTT: "#06b6d4",
  BGP: "#eab308",
  Kerberos: "#c084fc",
  SIP: "#fb7185",
  QUIC: "#818cf8",
  Docker: "#0ea5e9",
  Kubernetes: "#3b82f6",
  NetBIOS: "#f472b6",
  TFTP: "#fbbf24",
  "Modbus TCP": "#f59e0b",
  DNP3: "#d97706",
  S7Comm: "#b45309",
  "EtherNet/IP": "#92400e",
  "OPC DA": "#92400e",
  "OPC UA": "#78350f",
  "IEC 60870-5-104": "#713f12",
  BACnet: "#065f46",
  Profinet: "#047857",
  RADIUS: "#e11d48",
  CoAP: "#0d9488",
  DHCPv6: "#0891b2",
  WireGuard: "#6366f1",
  "IPSec/IKE": "#f59e0b",
  OpenVPN: "#10b981",
  RTSP: "#ef4444",
  AMQP: "#8b5cf6",
  "Oracle DB": "#dc2626",
  "FF-LR": "#eab308",
  "GE SRTP": "#d97706",
  "Niagara Fox": "#b45309",
  "HART-IP": "#ca8a04",
  POP3: "#f43f5e",
  Kafka: "#0284c7",
  etcd: "#dc2626",
  ZooKeeper: "#0d9488",
  Consul: "#ec4899",
  IRC: "#f97316",
  XMPP: "#14b8a6",
  STUN: "#6366f1",
  RIP: "#8b5cf6",
  OSPF: "#a855f7",
  EIGRP: "#9333ea",
  VRRP: "#3b82f6",
  HSRP: "#2563eb",
  GRE: "#64748b",
  VXLAN: "#475569",
  "DCE/RPC": "#0284c7",
};

export default function ReportPage() {
  const { state } = useAppContext();
  const navigate = useNavigate();

  if (!state.result || !state.summary) {
    return (
      <div className="py-16 text-center">
        <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-slate-800 flex items-center justify-center glass-border">
          <svg className="w-8 h-8 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
          </svg>
        </div>
        <h2 className="text-white text-lg font-medium mb-2">No Analysis Data</h2>
        <p className="text-slate-400 text-sm mb-4 max-w-md mx-auto">
          Upload a PCAP file and run the analysis first to generate a report.
        </p>
        <button
          onClick={() => navigate("/")}
          className="px-4 py-2 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm hover:bg-cyan-500/20 transition-colors"
        >
          Go to Upload
        </button>
      </div>
    );
  }

  const { result, summary, findings, protocolCounts, hosts, flows } = state;
  const executiveSummary = generateExecutiveSummary(state.fileName, summary, findings);
  const trafficNarrative = generateTrafficNarrative(summary, flows);
  const protocolNarrative = generateProtocolNarrative(protocolCounts);
  const posture = generateSecurityPosture(findings, summary.totalPackets);
  const observations = generateNotableObservations(findings, summary, hosts);

  // Prepare donut chart data
  const donutData = protocolCounts
    .filter(p => p.packetCount > 0)
    .slice(0, 10)
    .map((p, i) => ({
      label: p.protocol,
      value: p.packetCount,
      color: PROTOCOL_COLORS[p.protocol] ||
        ["#22d3ee", "#60a5fa", "#818cf8", "#a78bfa", "#34d399", "#fbbf24", "#f472b6", "#fb923c", "#94a3b8", "#2dd4bf"][i % 10],
    }));

  // Severity counts
  const severityCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  const riskColors: Record<string, string> = {
    Clean: "text-green-400 bg-green-500/10 border-green-500/30",
    Low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    Medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
    High: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    Critical: "text-red-400 bg-red-500/10 border-red-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between glass-strong border border-slate-800 rounded-xl px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-violet-500/20 flex items-center justify-center glass-border">
            <svg className="w-5 h-5 text-violet-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
          </div>
          <div>
            <h2 className="text-white text-base font-semibold">Analysis Report</h2>
            <p className="text-slate-500 text-xs">
              {result.fileName} — {new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`px-3 py-1 rounded-lg border text-xs font-semibold ${riskColors[posture.riskRating] || riskColors.Low}`}>
            Risk: {posture.riskRating}
          </span>
          <button
            onClick={() => window.print()}
            className="px-3 py-1.5 glass-border text-slate-300 text-xs rounded-lg transition-colors no-print"
            title="Print to PDF"
          >
            <svg className="w-3.5 h-3.5 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 3v4m6-4v4m-6 4v4m6-4v4m-6 4v4m-6-4v4m6-4v4m6 4v4m-6 4v4m6 4v4" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 19a2 2 0 012-2h12a2 2 0 012 2v2H3v-2z" />
            </svg>
            Print
          </button>
          <button
            onClick={() => navigate("/")}
            className="px-3 py-1.5 glass-border text-slate-300 text-xs rounded-lg transition-colors"
          >
            Back to Dashboard
          </button>
        </div>
      </div>

      {/* Executive Summary */}
      <NarrativeSection
        title="Executive Summary"
        icon="📋"
      >
        <p>{executiveSummary}</p>
      </NarrativeSection>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Packets"
          value={formatNumber(summary.totalPackets)}
          accent="text-cyan-400"
          navigateTo="/packets"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 6.878V6a2.25 2.25 0 012.25-2.25h7.5A2.25 2.25 0 0118 6v.878m-12 0c.235-.083.487-.128.75-.128h10.5c.263 0 .515.045.75.128m-12 0A2.25 2.25 0 004.5 9v.75m6-6V3m0 3v6m0 0v.75M3 18h18M3 18l2.25-9h13.5L21 18M3 18l-2.25-3m18 3l2.25-3" />
            </svg>
          }
        />
        <StatCard
          label="Total Traffic"
          value={formatBytes(summary.totalBytes)}
          accent="text-blue-400"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5" />
            </svg>
          }
        />
        <StatCard
          label="Duration"
          value={formatDuration(summary.durationUs)}
          accent="text-violet-400"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          }
        />
        <StatCard
          label="Unique Hosts"
          value={formatNumber(summary.uniqueHosts)}
          accent="text-teal-400"
          navigateTo="/assets"
          icon={
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
            </svg>
          }
        />
      </div>

      {/* Charts Row: Donut + Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Distribution Donut */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-white font-medium mb-4 text-sm">Protocol Distribution</h3>
          <DonutChart
            data={donutData}
            total={summary.totalPackets}
            centerLabel={summary.totalPackets.toLocaleString()}
          />
        </div>

        {/* Security Findings Severity */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-white font-medium mb-2 text-sm">Security Findings Breakdown</h3>
          <p className="text-slate-500 text-xs mb-4">
            {findings.length} total finding{findings.length !== 1 ? "s" : ""} detected
          </p>
          <SeverityBar counts={severityCounts} total={findings.length} />

          {/* Security posture narrative */}
          <div className="mt-4 pt-4 border-t border-slate-800">
            <p className="text-xs text-slate-400 leading-relaxed">
              {posture.narrative}
            </p>
          </div>
        </div>
      </div>

      {/* Traffic Pattern Narrative */}
      <NarrativeSection
        title="Traffic Pattern Analysis"
        icon="🔍"
      >
        <p>{trafficNarrative}</p>
      </NarrativeSection>

      {/* Top Talkers Bar Chart */}
      {summary.topTalkers.length > 0 && (
        <NarrativeSection
          title="Top Talkers"
          icon="📊"
        >
          <p className="text-xs text-slate-400 mb-3">
            Hosts ranked by packet volume — the busiest sources of network traffic in this capture.
          </p>
          <TopTalkerBarChart talkers={summary.topTalkers} maxItems={8} />
        </NarrativeSection>
      )}

      {/* Protocol Narrative */}
      <NarrativeSection
        title="Protocol Analysis"
        icon="🌐"
      >
        <p>{protocolNarrative}</p>
      </NarrativeSection>

      {/* Timeline */}
      {summary.timelineBuckets && summary.timelineBuckets.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-white font-medium mb-2 text-sm">Traffic Over Time</h3>
          <p className="text-xs text-slate-500 mb-3">
            Timeline of packet activity throughout the capture — spikes may indicate bursts of traffic, scanning, or attacks.
          </p>
          <TimelineChart buckets={summary.timelineBuckets} />
        </div>
      )}

      {/* Notable Observations */}
      {observations.length > 0 && (
        <NarrativeSection
          title="Notable Observations"
          icon="🔔"
        >
          <ul className="space-y-2">
            {observations.map((obs, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300 leading-relaxed">
                <span className="mt-0.5 flex-shrink-0">{obs.startsWith("🚨") ? "" : obs.startsWith("⚠️") ? "" : "•"}</span>
                <span>{obs.replace(/^(?:🚨|⚠️|📊|🌐|🏭|🔗)\s*/u, "")}</span>
              </li>
            ))}
          </ul>
        </NarrativeSection>
      )}

      {/* Security Posture */}
      <NarrativeSection
        title="Security Posture Assessment"
        icon="🛡️"
      >
        <p>
          <span className="font-semibold" style={{ color: posture.riskRating === "Critical" ? "#ef4444" : posture.riskRating === "High" ? "#f97316" : posture.riskRating === "Medium" ? "#eab308" : "#22d3ee" }}>
            Overall Risk: {posture.riskRating}
          </span>
          {" — "}{posture.narrative}
        </p>
        {findings.length > 0 && (
          <div className="mt-4 p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <p className="text-xs text-slate-400 mb-2">Quick summary of top findings:</p>
            <div className="space-y-1">
              {findings.slice(0, 5).map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className={`inline-block w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                    f.severity === "Critical" ? "bg-red-500" :
                    f.severity === "High" ? "bg-orange-500" :
                    f.severity === "Medium" ? "bg-yellow-500" :
                    f.severity === "Low" ? "bg-blue-500" : "bg-slate-500"
                  }`} />
                  <span className="text-slate-500 font-mono w-14 flex-shrink-0">{f.severity}</span>
                  <span className="text-slate-300 truncate">{f.title}</span>
                </div>
              ))}
              {findings.length > 5 && (
                <button
                  onClick={() => navigate("/findings")}
                  className="text-xs text-cyan-400 hover:text-cyan-300 mt-1 inline-block"
                >
                  View all {findings.length} findings →
                </button>
              )}
            </div>
          </div>
        )}
      </NarrativeSection>

      {/* NTP Server Analysis */}
      {result.ntpAnalysis && (
        <NTPAnalysisSection
          ntpAnalysis={result.ntpAnalysis}
        />
      )}

      {/* Footer */}
      <div className="text-center text-xs text-slate-600 pb-4">
        <p>Report generated {new Date().toLocaleString()} — All analysis performed client-side in your browser.</p>
        <p>{summary.flowCount.toLocaleString()} flows analyzed • {findings.length} findings • {hosts.size} hosts identified</p>
      </div>
    </div>
  );
}

/* ========= NTP Analysis Section ========= */

import type { NTPServerInfo, NTPAnalysisResult } from "../types/analysis";

function NTPAnalysisSection({ ntpAnalysis }: { ntpAnalysis: NTPAnalysisResult }) {
  const { clients, servers, conversations } = ntpAnalysis;

  // Only show if we have relevant data
  if (clients.length === 0 && servers.length === 0 && conversations.length === 0) {
    return null;
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h3 className="text-white font-medium mb-4 text-sm flex items-center gap-2">
        <span>🕒 NTP Time Servers</span>
        {clients.length > 0 && servers.length > 0 && (
          <span className="text-xs text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded">
            {servers.length} confirmed
          </span>
        )}
      </h3>

      {/* Confirmed NTP Servers */}
      {servers.length > 0 && (
        <div className="mb-4">
          <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">Confirmed NTP Servers</h4>
          <div className="space-y-2">
            {servers.map((server) => (
              <NTPServerCard key={server.ip} server={server} />
            ))}
          </div>
        </div>
      )}

      {/* NTP Conversations (Client ↔ Server) */}
      {conversations.length > 0 && (
        <div>
          <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">NTP Conversations</h4>
          <div className="space-y-2">
            {conversations.slice(0, 5).map((conv) => (
              <div
                key={`${conv.clientIp}-${conv.serverIp}`}
                className="bg-slate-800/30 border border-slate-700/50 rounded-lg px-3 py-2"
              >
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-3">
                    <div className="font-mono text-cyan-400">
                      {conv.clientIp}:{conv.clientPort}
                    </div>
                    <span className="text-slate-500">→</span>
                    <div className="font-mono text-green-400">
                      {conv.serverIp}:{conv.serverPort}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">
                      {conv.requestCount}↔{conv.responseCount}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-xs ${
                      conv.confidence === "high" ? "bg-green-500/20 text-green-300" :
                      conv.confidence === "medium" ? "bg-yellow-500/20 text-yellow-300" :
                      "bg-slate-500/20 text-slate-300"
                    }`}>
                      {conv.confidence}
                    </span>
                  </div>
                </div>
              </div>
            ))}
            {conversations.length > 5 && (
              <p className="text-xs text-slate-500">
                +{conversations.length - 5} more conversations
              </p>
            )}
          </div>
        </div>
      )}

      {/* NTP Clients (without confirmed server) */}
      {clients.length > servers.length && (
        <div className="mt-4 pt-4 border-t border-slate-800/50">
          <h4 className="text-xs text-slate-400 uppercase tracking-wider mb-2">NTP Clients</h4>
          <div className="flex flex-wrap gap-2">
            {clients.filter(c => !servers.find(s => s.ip === c.ip)).slice(0, 10).map((client) => (
              <span
                key={client.ip}
                className="px-2 py-1 bg-slate-800/50 border border-slate-700/50 rounded text-xs"
              >
                <span className="font-mono text-cyan-400">{client.ip}</span>
                <span className="text-slate-500 text-[10px]"> v{client.version}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ========= NTP Server Card ========= */

function NTPServerCard({ server }: { server: NTPServerInfo }) {
  // Stratum description
  const stratumDesc = server.stratum === 0
    ? "Unsynchronized"
    : server.stratum === NTP_STRATUM_PRIMARY
      ? "Primary (stratum 1)"
      : server.stratum === NTP_STRATUM_KISS_OBR
        ? "Kiss-of-death"
        : server.stratum >= 2 && server.stratum <= 15
          ? `Secondary (stratum ${server.stratum})`
          : "Unknown";

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg px-3 py-2">
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-3">
          <span className="font-mono text-green-400">{server.ip}:{server.port}</span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-300">v{server.version}</span>
          <span className="text-slate-500">|</span>
          <span className={
            server.stratum <= 3 ? "text-emerald-400" :
            server.stratum <= 7 ? "text-yellow-300" :
            "text-slate-300"
          }>
            {stratumDesc}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {server.referenceId && server.stratum === 1 && (
            <span className="text-xs text-slate-400 bg-slate-700/50 px-2 py-0.5 rounded">
              ref: {server.referenceId}
            </span>
          )}
          <span className={`px-1.5 py-0.5 rounded text-xs ${
            server.confidence === "high" ? "bg-green-500/20 text-green-300" :
            server.confidence === "medium" ? "bg-yellow-500/20 text-yellow-300" :
            "bg-slate-500/20 text-slate-300"
          }`}>
            {server.confidence} confidence
          </span>
        </div>
      </div>
    </div>
  );
}

/* Constants for NTP */
const NTP_STRATUM_PRIMARY = 1;
const NTP_STRATUM_KISS_OBR = 255;
