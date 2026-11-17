import type { AnalysisSummary, FlowRecord, SecurityFinding, ProtocolCount, HostInfo } from "../types/analysis";
import { formatBytes, formatDuration, formatNumber } from "./format";

/**
 * Generate an executive summary paragraph from analysis data.
 */
export function generateExecutiveSummary(
  fileName: string,
  summary: AnalysisSummary,
  findings: SecurityFinding[]
): string {
  const topProtocols = summary.protocolCounts.slice(0, 3).map(p => p.protocol);
  const criticalCount = findings.filter(f => f.severity === "Critical").length;
  const highCount = findings.filter(f => f.severity === "High").length;

  const parts: string[] = [];
  parts.push(
    `Analysis of "${fileName}" captured ${formatNumber(summary.totalPackets)} packets totalling ${formatBytes(summary.totalBytes)} over ${formatDuration(summary.durationUs)}.`
  );

  parts.push(
    `The capture involves ${summary.uniqueHosts} unique hosts communicating via ${summary.protocolCounts.length} different protocols${topProtocols.length > 0 ? `, with the most active being ${topProtocols.join(", ")}` : ""}.`
  );

  if (findings.length === 0) {
    parts.push("Security analysis identified no significant threats — the traffic appears routine and non-malicious.");
  } else {
    const severityParts: string[] = [];
    if (criticalCount > 0) severityParts.push(`${criticalCount} critical`);
    if (highCount > 0) severityParts.push(`${highCount} high`);
    const mediumCount = findings.filter(f => f.severity === "Medium").length;
    if (mediumCount > 0) severityParts.push(`${mediumCount} medium`);

    parts.push(
      `Security analysis identified ${findings.length} potential findings${severityParts.length > 0 ? `, including ${severityParts.join(", ")} severity issues that warrant investigation` : ""}.`
    );
  }

  return parts.join(" ");
}

/**
 * Generate notable observation bullet points from findings and traffic patterns.
 */
export function generateNotableObservations(
  findings: SecurityFinding[],
  summary: AnalysisSummary,
  hosts: Map<string, HostInfo>
): string[] {
  const observations: string[] = [];

  // Critical findings
  const critical = findings.filter(f => f.severity === "Critical");
  for (const f of critical.slice(0, 3)) {
    observations.push(`🚨 Critical: ${f.title} — ${simplifyText(f.description, 120)}`);
  }

  // High severity findings
  const high = findings.filter(f => f.severity === "High");
  for (const f of high.slice(0, 3)) {
    observations.push(`⚠️ High: ${f.title} — ${simplifyText(f.description, 120)}`);
  }

  // Traffic pattern observations
  if (summary.totalPackets > 1000) {
    observations.push(
      `📊 High traffic volume: ${formatNumber(summary.totalPackets)} packets in ${formatDuration(summary.durationUs)} — this capture represents a busy network segment or extended monitoring period.`
    );
  }

  // Host observations
  const hostList = Array.from(hosts.entries());
  const publicHosts = hostList.filter(([, info]) => !info.isPrivate);
  if (publicHosts.length > 0) {
    observations.push(
      `🌐 External communication: ${publicHosts.length} public/external IP address(es) were observed, including ${publicHosts.slice(0, 2).map(([ip]) => ip).join(", ")}.`
    );
  }

  // OT protocol observations
  const otProtocols = summary.protocolCounts.filter(p => p.isOT);
  if (otProtocols.length > 0) {
    observations.push(
      `🏭 Industrial protocols: ${otProtocols.map(p => p.protocol).join(", ")} traffic was detected, indicating OT/ICS devices on the network.`
    );
  }

  // ARP activity
  const arpProto = summary.protocolCounts.find(p => p.protocol === "ARP");
  if (arpProto && arpProto.packetCount > 10) {
    observations.push(
      `🔗 High ARP activity: ${arpProto.packetCount} ARP packets — this may indicate active host discovery or a network with many devices resolving addresses.`
    );
  }

  return observations;
}

/**
 * Generate a narrative describing traffic flow patterns.
 */
export function generateTrafficNarrative(
  summary: AnalysisSummary,
  flows: FlowRecord[]
): string {
  const parts: string[] = [];

  if (summary.topTalkers.length > 0) {
    const top = summary.topTalkers[0];
    const pct = summary.totalPackets > 0
      ? ((top.packetCount / summary.totalPackets) * 100).toFixed(1)
      : "0";
    parts.push(
      `The busiest host was ${top.ip}, sending ${formatNumber(top.packetCount)} packets (${pct}% of total traffic, ${formatBytes(top.byteCount)}).`
    );
  }

  if (summary.topTalkers.length > 1) {
    const second = summary.topTalkers[1];
    parts.push(
      `The second most active host was ${second.ip} with ${formatNumber(second.packetCount)} packets (${formatBytes(second.byteCount)}).`
    );
  }

  // Flow patterns
  if (flows.length > 0) {
    // Find the flow with the most packets
    const sortedFlows = [...flows].sort((a, b) => b.packetCount - a.packetCount);
    const busiest = sortedFlows[0];
    parts.push(
      `The busiest communication path was ${busiest.srcIp}:${busiest.srcPort} → ${busiest.dstIp}:${busiest.dstPort} (${busiest.appProtocol}) with ${busiest.packetCount} packets (${formatBytes(busiest.byteCount)}).`
    );
  }

  if (summary.uniqueHosts > 3) {
    parts.push(
      `A total of ${summary.uniqueHosts} unique hosts participated in ${summary.flowCount} distinct network flows, indicating ${summary.flowCount > summary.uniqueHosts * 2 ? "a busy network with many concurrent connections" : "moderate network activity"}.`
    );
  }

  return parts.join(" ");
}

/**
 * Generate a narrative describing the protocol distribution.
 */
export function generateProtocolNarrative(protocolCounts: ProtocolCount[]): string {
  if (protocolCounts.length === 0) return "No protocol data available.";

  const sorted = [...protocolCounts].sort((a, b) => b.packetCount - a.packetCount);
  const top = sorted[0];
  const itProtos = protocolCounts.filter(p => !p.isOT);
  const otProtos = protocolCounts.filter(p => p.isOT);

  const total = protocolCounts.reduce((sum, p) => sum + p.packetCount, 0);
  const topPct = total > 0 ? ((top.packetCount / total) * 100).toFixed(1) : "0";

  const parts: string[] = [];
  parts.push(
    `${top.protocol} was the most prevalent protocol, accounting for ${topPct}% of all packets (${formatNumber(top.packetCount)} of ${formatNumber(total)}).`
  );

  if (sorted.length > 1) {
    parts.push(
      `The top three protocols were ${sorted.slice(0, 3).map(p => p.protocol).join(", ")}.`
    );
  }

  const itCount = itProtos.length;
  const otCount = otProtos.length;
  if (otCount > 0) {
    parts.push(
      `${itCount} IT protocol(s) and ${otCount} OT/ICS protocol(s) were detected, suggesting ${otCount >= 2 ? "a mixed IT/OT environment" : "the presence of industrial control systems alongside standard IT infrastructure"}.`
    );
  } else if (itCount > 0) {
    parts.push(`All ${itCount} detected protocols are standard IT protocols — no industrial (OT/ICS) traffic was observed.`);
  }

  return parts.join(" ");
}

/**
 * Generate a security posture summary.
 */
export function generateSecurityPosture(
  findings: SecurityFinding[],
  _totalPackets: number
): { riskScore: number; riskRating: string; narrative: string } {
  const severityCounts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  const riskScore = severityCounts.Critical * 10 + severityCounts.High * 5 + severityCounts.Medium * 2 + severityCounts.Low * 1;
  const riskRating = riskScore >= 50 ? "Critical" : riskScore >= 20 ? "High" : riskScore >= 5 ? "Medium" : riskScore >= 1 ? "Low" : "Clean";

  const ratingNarratives: Record<string, string> = {
    Clean: "No security threats were detected. The traffic appears normal with no suspicious patterns, unauthorized protocols, or attack signatures. This indicates a well-configured and monitored network segment.",
    Low: "The traffic shows only minor security concerns. While some unusual patterns were detected, they are unlikely to pose immediate risk. Routine monitoring and periodic review are recommended.",
    Medium: "Several moderate security issues were identified that should be investigated. These findings may indicate misconfigurations, policy violations, or early-stage reconnaissance activities that warrant attention.",
    High: "Significant security concerns were detected. The traffic contains patterns consistent with active attacks, policy violations, or exposed services that could be exploited. Investigation and remediation are strongly recommended.",
    Critical: "Critical security threats were identified that require immediate attention. The traffic contains clear indicators of active attacks, compromise, or severe misconfigurations that expose the network to serious risk.",
  };

  return {
    riskScore,
    riskRating,
    narrative: ratingNarratives[riskRating],
  };
}

/**
 * Shorten and clean up a description for display in bullet points.
 */
function simplifyText(text: string, maxLen: number): string {
  // Remove line breaks and excessive whitespace
  let cleaned = text.replace(/\s+/g, " ").trim();
  // Remove recommendation numbers like "1. ", "2. " etc.
  cleaned = cleaned.replace(/\d+\.\s+/g, "");
  if (cleaned.length <= maxLen) return cleaned;
  return cleaned.substring(0, maxLen - 3) + "...";
}
