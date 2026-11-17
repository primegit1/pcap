import type { AnalysisResult, SecurityFinding } from "../types/analysis";
import { calculateRiskScore } from "../analysis/risk-scoring";
import { formatBytes, formatDuration, formatNumber } from "./format";

/**
 * Trigger a file download in the browser.
 */
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Generate a timestamp string for filenames.
 */
function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

/** ISO string for a microsecond timestamp; never throws on 0/NaN. */
function isoFromUs(us: number | undefined): string {
  if (!us || !Number.isFinite(us) || us <= 0) return "";
  return new Date(Math.floor(us / 1000)).toISOString();
}

/* ========== JSON Export ========== */

/** Build the JSON export text (pure; exported for tests). */
export function buildJson(result: AnalysisResult, exportedAt = new Date()): string {
  return JSON.stringify(
    {
      fileName: result.fileName,
      exportedAt: exportedAt.toISOString(),
      summary: result.summary,
      captureWarnings: result.captureWarnings ?? [],
      flows: result.flows.map((f) => ({
        id: f.id,
        initiator: `${f.srcIp}:${f.srcPort}`,
        responder: `${f.dstIp}:${f.dstPort}`,
        srcIp: f.srcIp,
        dstIp: f.dstIp,
        srcPort: f.srcPort,
        dstPort: f.dstPort,
        protocol: f.appProtocol,
        ipProtocol: f.ipProtocol,
        packets: f.packetCount,
        bytes: f.byteCount,
        initiatorPackets: f.initiatorPackets,
        responderPackets: f.responderPackets,
        initiatorBytes: f.initiatorBytes,
        responderBytes: f.responderBytes,
        startTime: isoFromUs(f.startTimeUs),
        endTime: isoFromUs(f.endTimeUs),
      })),
      hosts: Array.from(result.hosts.entries()).map(([ip, info]) => ({
        ip,
        mac: info.mac,
        packets: info.packetCount,
        bytes: info.byteCount,
        protocols: Array.from(info.protocols),
        isPrivate: info.isPrivate,
        firstSeen: isoFromUs(info.firstSeenUs),
        lastSeen: isoFromUs(info.lastSeenUs),
      })),
      findings: result.findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        category: f.category,
        description: f.description,
        recommendation: f.recommendation,
        evidence: f.evidence,
        affectedIp: f.affectedIp,
        occurrences: f.occurrences ?? 1,
        firstSeen: isoFromUs(f.firstSeenUs),
        lastSeen: isoFromUs(f.lastSeenUs),
        packetIndices: f.packetIndices ?? [],
        packetRefsApproximate: f.refsApproximate ?? false,
        flowIds: f.flowIds ?? [],
      })),
      protocolCounts: result.protocolCounts.map((p) => ({
        protocol: p.protocol,
        packets: p.packetCount,
        bytes: p.byteCount,
        isOT: p.isOT,
      })),
    },
    null,
    2
  );
}

/**
 * Export the full analysis result as a JSON file.
 */
export function exportAsJson(result: AnalysisResult) {
  const blob = new Blob([buildJson(result)], { type: "application/json" });
  downloadBlob(blob, `pcap-analysis-${timestamp()}.json`);
}

/* ========== CSV Findings Export ========== */

/**
 * Escape one CSV cell.
 *
 * Finding text is partly attacker-controlled (HTTP User-Agents, DNS names, URLs from the
 * capture). A cell that starts with = + - @ (or a tab/CR) is executed as a formula by Excel,
 * LibreOffice and Google Sheets, so it is prefixed with a single quote to force plain text
 * (the OWASP "CSV injection" mitigation). Every cell is quoted.
 */
export function escapeCsv(value: unknown): string {
  let str = value === undefined || value === null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(str)) str = `'${str}`;
  return `"${str.replace(/"/g, '""')}"`;
}

const CSV_HEADERS = [
  "ID",
  "Severity",
  "Confidence",
  "Title",
  "Category",
  "Affected IP",
  "Description",
  "Recommendation",
  "Evidence",
  "Occurrences",
  "First Seen",
  "Last Seen",
  "Packet Indices",
];

/** Build the CSV text, with a UTF-8 BOM so Excel detects the encoding (pure; exported for tests). */
export function buildCsv(findings: SecurityFinding[]): string {
  const rows = findings.map((f) =>
    [
      f.id,
      f.severity,
      f.confidence ?? "",
      f.title,
      f.category,
      f.affectedIp,
      f.description,
      f.recommendation,
      f.evidence,
      f.occurrences ?? 1,
      isoFromUs(f.firstSeenUs),
      isoFromUs(f.lastSeenUs),
      (f.packetIndices ?? []).join(" "),
    ].map(escapeCsv)
  );
  const lines = [CSV_HEADERS.map(escapeCsv), ...rows].map((r) => r.join(","));
  return "\uFEFF" + lines.join("\r\n");
}

/**
 * Export security findings as a CSV file.
 */
export function exportAsCsv(findings: SecurityFinding[]) {
  const blob = new Blob([buildCsv(findings)], { type: "text/csv;charset=utf-8;" });
  downloadBlob(blob, `pcap-findings-${timestamp()}.csv`);
}

/* ========== HTML Report Export ========== */

const SEVERITY_CLASSES = new Set(["critical", "high", "medium", "low", "info"]);

/** Map a severity to a CSS class suffix from a fixed allowlist (never interpolate raw values). */
function severityClass(severity: string): string {
  const c = severity.toLowerCase();
  return SEVERITY_CLASSES.has(c) ? c : "info";
}

/**
 * Generate and download a standalone HTML report.
 */
export function exportAsHtml(result: AnalysisResult) {
  const blob = new Blob([buildHtmlReport(result)], { type: "text/html;charset=utf-8;" });
  downloadBlob(blob, `pcap-report-${timestamp()}.html`);
}

/** Build the standalone HTML report text (pure; exported for tests). */
export function buildHtmlReport(result: AnalysisResult, now = new Date()): string {
  const summary = result.summary;
  const findingsBySeverity = groupFindingsBySeverity(result.findings);
  const hostList = Array.from(result.hosts.entries())
    .map(([ip, info]) => ({
      ip,
      mac: info.mac,
      packetCount: info.packetCount,
      byteCount: info.byteCount,
      protocols: info.protocols,
      isPrivate: info.isPrivate,
    }))
    .sort((a, b) => b.byteCount - a.byteCount);

  // One source of truth for weights and thresholds.
  const { score: riskScore, rating: riskRating } = calculateRiskScore(result.findings);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
  <title>PCAP Analysis Report - ${escapeHtml(result.fileName)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.5; }
    .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 24px; color: #f1f5f9; margin-bottom: 4px; }
    h2 { font-size: 18px; color: #22d3ee; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid #1e293b; }
    h3 { font-size: 14px; color: #94a3b8; margin: 16px 0 8px; }
    .subtitle { color: #64748b; font-size: 14px; margin-bottom: 24px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e293b; font-size: 13px; }
    th { color: #64748b; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
    td { color: #e2e8f0; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: #1e293b; border-radius: 8px; padding: 16px; }
    .stat-label { color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-value { color: #f1f5f9; font-size: 22px; font-weight: 700; margin-top: 4px; }
    .severity-critical { color: #ef4444; }
    .severity-high { color: #f97316; }
    .severity-medium { color: #eab308; }
    .severity-low { color: #60a5fa; }
    .severity-info { color: #94a3b8; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .badge-critical { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .badge-high { background: #431407; color: #fb923c; border: 1px solid #7c2d12; }
    .badge-medium { background: #422006; color: #eab308; border: 1px solid #713f12; }
    .badge-low { background: #1e3a5f; color: #60a5fa; border: 1px solid #1e40af; }
    .badge-info { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
    .risk-box { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; }
    .risk-score { font-size: 36px; font-weight: 700; }
    .risk-rating { font-size: 14px; margin-top: 4px; }
    .finding-table td:first-child { width: 100px; }
    code { color: #22d3ee; font-family: 'SF Mono', Consolas, monospace; font-size: 12px; }
    .mt-4 { margin-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>PCAP Security Analysis Report</h1>
    <p class="subtitle">File: ${escapeHtml(result.fileName)} — Generated ${escapeHtml(now.toLocaleString())}</p>

    <h2>Network Summary</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Packets</div>
        <div class="stat-value">${formatNumber(summary.totalPackets)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Traffic</div>
        <div class="stat-value">${formatBytes(summary.totalBytes)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Duration</div>
        <div class="stat-value">${formatDuration(summary.durationUs)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Unique Hosts</div>
        <div class="stat-value">${formatNumber(summary.uniqueHosts)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Flows</div>
        <div class="stat-value">${formatNumber(summary.flowCount)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Findings</div>
        <div class="stat-value">${formatNumber(summary.findingCount)}</div>
      </div>
    </div>

    <h2>Asset Inventory</h2>
    <table>
      <thead>
        <tr><th>IP Address</th><th>MAC</th><th>Packets</th><th>Bytes</th><th>Protocols</th><th>Type</th></tr>
      </thead>
      <tbody>
        ${hostList.slice(0, 50).map(h => `
          <tr>
            <td><code>${escapeHtml(h.ip)}</code></td>
            <td>${escapeHtml(h.mac || '-')}</td>
            <td>${formatNumber(h.packetCount)}</td>
            <td>${formatBytes(h.byteCount)}</td>
            <td>${Array.from(h.protocols).filter(p => p !== 'Unknown').map(p => escapeHtml(p)).join(', ')}</td>
            <td>${h.isPrivate ? 'Private' : 'Public'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
    ${hostList.length > 50 ? `<p class="subtitle">Showing top 50 of ${hostList.length} hosts</p>` : ''}

    <h2>Protocol Summary</h2>
    <table>
      <thead>
        <tr><th>Protocol</th><th>Packets</th><th>Bytes</th><th>% Traffic</th><th>Type</th></tr>
      </thead>
      <tbody>
        ${summary.protocolCounts.map(p => `
          <tr>
            <td>${escapeHtml(p.protocol)}</td>
            <td>${formatNumber(p.packetCount)}</td>
            <td>${formatBytes(p.byteCount)}</td>
            <td>${summary.totalPackets > 0 ? ((p.packetCount / summary.totalPackets) * 100).toFixed(1) + '%' : '0%'}</td>
            <td>${p.isOT ? 'OT/ICS' : 'IT'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Security Findings (${result.findings.length})</h2>

    <div class="risk-box">
      <h3>Risk Assessment</h3>
      <div class="risk-score ${riskRating === 'Critical Risk' ? 'severity-critical' : riskRating === 'High Risk' ? 'severity-high' : riskRating === 'Medium Risk' ? 'severity-medium' : ''}">${riskScore}</div>
      <div class="risk-rating">${riskRating}</div>
      <div style="margin-top: 12px; font-size: 13px; color: #94a3b8;">
        Critical: ${findingsBySeverity.Critical} | High: ${findingsBySeverity.High} | Medium: ${findingsBySeverity.Medium} | Low: ${findingsBySeverity.Low} | Info: ${findingsBySeverity.Info}
      </div>
    </div>

    <table class="finding-table">
      <thead>
        <tr><th>Severity</th><th>Finding</th><th>Category</th><th>Affected IP</th><th>Evidence</th><th>Recommendation</th></tr>
      </thead>
      <tbody>
        ${result.findings.map(f => `
          <tr>
            <td><span class="badge badge-${severityClass(f.severity)}">${escapeHtml(f.severity)}</span>${f.confidence ? `<br><span style="font-size: 11px; color: #64748b;">${escapeHtml(f.confidence)} confidence</span>` : ''}</td>
            <td><strong>${escapeHtml(f.title)}</strong><br><span style="color: #94a3b8; font-size: 12px;">${escapeHtml(f.description)}</span></td>
            <td>${escapeHtml(f.category)}</td>
            <td><code>${escapeHtml(f.affectedIp)}</code></td>
            <td style="font-size: 12px; color: #94a3b8; white-space: pre-wrap;">${escapeHtml(f.evidence)}${(f.occurrences ?? 1) > 1 ? ` (×${f.occurrences})` : ''}</td>
            <td style="font-size: 12px; color: #94a3b8; white-space: pre-wrap;">${escapeHtml(f.recommendation || '')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; color: #475569; font-size: 11px;">
      <p>Generated by PCAP Security Analyzer — All analysis performed locally in-browser.</p>
    </div>
  </div>
</body>
</html>`;

  return html;
}

/* ========== Helpers ========== */

function groupFindingsBySeverity(findings: SecurityFinding[]): Record<string, number> {
  const groups: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    if (groups[f.severity] !== undefined) groups[f.severity]++;
  }
  return groups;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
