import type { Packet } from "../types/packets";
import type { FlowRecord, SecurityFinding, AnalysisResult, AnalysisSummary } from "../types/analysis";
import {
  detectPortScanning,
  detectSYNFlood,
  detectLargeTransfer,
  detectICMPFlood,
  detectPingSweep,
} from "./security-rules/network";
import {
  detectHighEntropyDNSNames,
  detectDNSTunnelingTXT,
  detectExcessiveNXDOMAINDeep,
  detectDNSFastFlux,
} from "./security-rules/dns-enhanced";
import {
  detectClearTextCredentials,
  detectSuspiciousUserAgents,
  detectExecutableDownloads,
} from "./security-rules/http";
import {
  detectSuspiciousUserAgentsDeep,
  detectExecutableDownloadsDeep,
  detectHTTPAuthFailures,
  detectUnusualHTTPMethods,
} from "./security-rules/http-enhanced";
import { detectWeakTLS, detectTLSFingerprints } from "./security-rules/tls";
import {
  detectTLSDowngrade,
  detectWeakTLSCiphers,
} from "./security-rules/tls-enhanced";
import { detectBruteForceEnhanced } from "./security-rules/auth-enhanced";
import {
  detectPLCCommunication,
  detectModbusWrites,
  detectS7Writes,
  detectOTScanning,
  detectBACnetTraffic,
  detectProfinetTraffic,
  detectOTOverInternet,
} from "./security-rules/ot-ics";
import {
  detectIGMPFlood,
  detectSuspiciousIGMPGroupMembership,
} from "./security-rules/igmp";
import {
  detectSSDPIGDExposure,
  detectSSDPAmplification,
  detectSSDPRogueDevices,
  detectSSDPByebyeFlood,
} from "./security-rules/ssdp";
import {
  detectARPSpoofing,
  detectARPRequestFlood,
  detectARPStorm,
  detectARPCachePoisoning,
} from "./security-rules/arp";
import { buildFlows, buildHosts } from "./flow-analysis";
import { calculateProtocolDistribution } from "./protocol-detection";
import { detectWeakSNMPCommunity } from "./security-rules/snmp";
import { sortFindingsBySeverity } from "./risk-scoring";
import {
  detectLDAPAnonymousBind,
  detectIMAPClearText,
  detectMDNSReflection,
  detectSyslogSensitiveData,
  detectRedisExposure,
  detectMongoDBExposure,
  detectDockerAPIExposure,
  detectMemcachedExposure,
  detectMQTTExposure,
} from "./security-rules/application";
import { analyzeNTPTraffic } from "./security-rules/ntp";
import {
  detectNTPAmplification,
  detectNTPTimeShift,
  detectNTPSpoofing,
} from "./security-rules/ntp-security";
import {
  detectDHCPStarvation,
  detectDHCPRogueOffer,
  detectDHCPDecline,
  detectDHCPNAK,
} from "./security-rules/dhcp";
import {
  detectSSHWeakConfig,
  detectTelnetCleartext,
  detectFTPCleartext,
  detectRDPWeakEncryption,
  detectVNCWeakAuth,
} from "./security-rules/remote-access";
import {
  detectSMTPCleartext,
  detectSMTPOpenRelay,
} from "./security-rules/email";
import {
  detectMySQLCleartextAuth,
  detectPostgreSQLCleartextAuth,
  detectMSSQLCleartextAuth,
  detectElasticsearchExposure,
} from "./security-rules/database";
import {
  detectSMBv1,
  detectKubernetesExposure,
} from "./security-rules/file-sharing";
import {
  detectOPCUANoSecurity,
  detectOPCUASignOnly,
  detectOPCUAWriteOperations,
  detectOPCUASessionAnomalies,
  detectOPCDATraffic,
  detectOPCUATraffic,
  detectOPCUAEndpointEnumeration,
} from "./security-rules/opc-security";
import {
  detectLLMNRPoisoning,
  detectTFTPCleartext,
  detectRADIUSWeakSecret,
  detectCoAPExposure,
  detectSIPCleartext,
  detectRogueDHCPv6,
  detectDHCPv6Flood,
  detectWireGuardHandshakeScan,
  detectWireGuardFailedHandshakes,
  detectWireGuardDefaultPort,
} from "./security-rules/udp-protocols";
import {
  detectBGPUnauthenticated,
  detectBGPRouteHijack,
  detectBGPNotifications,
} from "./security-rules/bgp-security";
import {
  detectKerberosASREPRoasting,
  detectKerberosWeakEncryption,
  detectKerberoasting,
} from "./security-rules/kerberos-security";
import {
  detectIKEAggressiveMode,
  detectIKEScanning,
  detectOpenVPNDefaultPort,
  detectQUICVersionNegotiation,
} from "./security-rules/ike-vpn-security";
import {
  detectRTSPCleartext,
  detectRTSPNoAuth,
  detectAMQPCleartext,
} from "./security-rules/media-messaging-security";
import {
  detectOracleDBCleartextAuth,
  detectOracleTNSExposure,
  detectNetBIOSSpoofing,
  detectNetBIOSInfoDisclosure,
} from "./security-rules/infrastructure-security";


import { resetFindingIds, MAX_PACKET_REFS } from "./findings";
import { buildPacketIndex, type PacketIndex } from "./packet-index";
import { detectBeaconing } from "./security-rules/beaconing";

export interface RuleTiming {
  rule: string;
  ms: number;
}

/** A packet rule, plus an optional selector that hands it only the packets it can match. */
type PacketRule = [
  name: string,
  fn: (p: Packet[]) => SecurityFinding[],
  select?: (index: PacketIndex) => Packet[],
];

/**
 * Run all security detection rules against flows and packets.
 *
 * - Packet rules get a pre-filtered subset where the rule's own first filter guarantees it
 *   would have ignored every other packet (a safe speed-up; remaining rules still scan all).
 * - Findings are enriched with capture-time timestamps and packet references, then merged
 *   (not dropped) when they share title + affected IP + dedupKey.
 *
 * `onProgress` receives (stage, current, total) for each rule; `timings` (if given) is filled
 * with per-rule wall-clock milliseconds.
 */
export function runAllRules(
  packets: Packet[],
  flows: FlowRecord[],
  onProgress?: (stage: string, current: number, total: number) => void,
  index: PacketIndex = buildPacketIndex(packets),
  timings?: RuleTiming[]
): SecurityFinding[] {
  const packetRuleFns: PacketRule[] = [
    ["Port scanning", detectPortScanning, (i) => i.withPorts],
    ["C2 beaconing", detectBeaconing, (i) => i.withPorts],
    ["SYN flood", detectSYNFlood, (i) => i.tcp],
    ["TLS fingerprints", detectTLSFingerprints],
    ["Weak SNMP", detectWeakSNMPCommunity],
    ["ICMP flood", detectICMPFlood, (i) => i.icmp],
    ["Ping sweep", detectPingSweep, (i) => i.icmp],
    ["LDAP bind", detectLDAPAnonymousBind],
    ["IMAP cleartext", detectIMAPClearText],
    ["mDNS reflection", detectMDNSReflection],
    ["Syslog sensitive data", detectSyslogSensitiveData],
    ["Redis exposure", detectRedisExposure],
    ["MongoDB exposure", detectMongoDBExposure],
    ["Docker API", detectDockerAPIExposure],
    ["Memcached exposure", detectMemcachedExposure],
    ["MQTT exposure", detectMQTTExposure],
    ["IGMP flood", detectIGMPFlood, (i) => i.igmp],
    ["Suspicious IGMP groups", detectSuspiciousIGMPGroupMembership, (i) => i.igmp],
    ["SSDP IGD exposure", detectSSDPIGDExposure],
    ["SSDP amplification", detectSSDPAmplification],
    ["SSDP rogue devices", detectSSDPRogueDevices],
    ["SSDP byebye flood", detectSSDPByebyeFlood],
    ["ARP spoofing", detectARPSpoofing, (i) => i.arp],
    ["ARP cache poisoning", detectARPCachePoisoning, (i) => i.arp],
    ["ARP request flood", detectARPRequestFlood, (i) => i.arp],
    ["ARP storm", detectARPStorm, (i) => i.arp],
    // ── DHCP (previously unwired) ──
    ["DHCP starvation", detectDHCPStarvation],
    ["DHCP rogue offer", detectDHCPRogueOffer],
    ["DHCP decline", detectDHCPDecline],
    ["DHCP NAK", detectDHCPNAK],
    // ── NTP security ──
    ["NTP amplification", detectNTPAmplification],
    ["NTP time shift", detectNTPTimeShift],
    ["NTP spoofing", detectNTPSpoofing],
    // ── Deep DNS analysis ──
    ["DNS high-entropy names", detectHighEntropyDNSNames],
    ["DNS TXT tunneling", detectDNSTunnelingTXT],
    ["DNS NXDOMAIN deep", detectExcessiveNXDOMAINDeep],
    ["DNS fast-flux", detectDNSFastFlux],
    // ── Deep HTTP analysis ──
    ["HTTP suspicious UA deep", detectSuspiciousUserAgentsDeep],
    ["HTTP executable download deep", detectExecutableDownloadsDeep],
    ["HTTP auth failures", detectHTTPAuthFailures],
    ["HTTP unusual methods", detectUnusualHTTPMethods],
    // ── TLS deep analysis ──
    ["TLS downgrade", detectTLSDowngrade],
    ["TLS weak ciphers", detectWeakTLSCiphers],
    // ── Enhanced brute force ──
    ["Brute force enhanced", detectBruteForceEnhanced],
    // ── Remote access protocols ──
    ["SSH weak config", detectSSHWeakConfig],
    ["Telnet cleartext", detectTelnetCleartext],
    ["FTP cleartext", detectFTPCleartext],
    ["RDP weak encryption", detectRDPWeakEncryption],
    ["VNC weak auth", detectVNCWeakAuth],
    // ── Email protocols ──
    ["SMTP cleartext", detectSMTPCleartext],
    ["SMTP open relay", detectSMTPOpenRelay],
    // ── Database protocols ──
    ["MySQL cleartext auth", detectMySQLCleartextAuth],
    ["PostgreSQL cleartext auth", detectPostgreSQLCleartextAuth],
    ["MSSQL cleartext auth", detectMSSQLCleartextAuth],
    ["Elasticsearch exposure", detectElasticsearchExposure],
    // ── File sharing / Container ──
    ["SMBv1 detection", detectSMBv1],
    ["Kubernetes exposure", detectKubernetesExposure],
    // ── OPC protocol ──
    ["OPC UA no security", detectOPCUANoSecurity],
    ["OPC UA sign-only", detectOPCUASignOnly],
    ["OPC UA write operations", detectOPCUAWriteOperations],
    ["OPC UA session anomalies", detectOPCUASessionAnomalies],
    ["OPC UA endpoint enumeration", detectOPCUAEndpointEnumeration],
    // ── UDP protocol security ──
    ["LLMNR poisoning", detectLLMNRPoisoning],
    ["RADIUS weak secret", detectRADIUSWeakSecret],
    ["CoAP exposure", detectCoAPExposure],
    ["SIP cleartext", detectSIPCleartext],
    ["Rogue DHCPv6", detectRogueDHCPv6],
    ["DHCPv6 flood", detectDHCPv6Flood],
    ["WireGuard handshake scan", detectWireGuardHandshakeScan],
    ["WireGuard failed handshakes", detectWireGuardFailedHandshakes],
    // ── BGP security ──
    ["BGP route hijack", detectBGPRouteHijack],
    ["BGP notifications", detectBGPNotifications],
    // ── Kerberos security ──
    ["Kerberos AS-REP roasting", detectKerberosASREPRoasting],
    ["Kerberos weak encryption", detectKerberosWeakEncryption],
    ["Kerberoasting", detectKerberoasting],
    // ── IKE/VPN security ──
    ["IKE aggressive mode", detectIKEAggressiveMode],
    ["IKE scanning", detectIKEScanning],
    ["QUIC version negotiation", detectQUICVersionNegotiation],
    // ── RTSP security ──
    ["RTSP cleartext", detectRTSPCleartext],
    // ── Infrastructure security ──
    ["Oracle DB cleartext auth", detectOracleDBCleartextAuth],
    ["NetBIOS spoofing", detectNetBIOSSpoofing],
  ];

  const flowRuleFns: [string, (f: FlowRecord[]) => SecurityFinding[]][] = [
    ["Large transfers", detectLargeTransfer],
    ["Clear-text creds", detectClearTextCredentials],
    ["Suspicious user agents", detectSuspiciousUserAgents],
    ["Executable downloads", detectExecutableDownloads],
    ["Weak TLS", detectWeakTLS],
    ["PLC communication", detectPLCCommunication],
    ["Modbus writes", detectModbusWrites],
    ["S7 writes", detectS7Writes],
    ["OT scanning", detectOTScanning],
    ["BACnet traffic", detectBACnetTraffic],
    ["Profinet traffic", detectProfinetTraffic],
    ["OT over internet", detectOTOverInternet],
    // ── OPC protocol ──
    ["OPC DA traffic", detectOPCDATraffic],
    ["OPC UA traffic", detectOPCUATraffic],
    // ── UDP protocol security (flow-level) ──
    ["TFTP cleartext", detectTFTPCleartext],
    ["WireGuard default port", detectWireGuardDefaultPort],
    // ── BGP security (flow-level) ──
    ["BGP unauthenticated", detectBGPUnauthenticated],
    // ── IKE/VPN security (flow-level) ──
    ["OpenVPN default port", detectOpenVPNDefaultPort],
    // ── RTSP security (flow-level) ──
    ["RTSP no auth", detectRTSPNoAuth],
    // ── AMQP security (flow-level) ──
    ["AMQP cleartext", detectAMQPCleartext],
    // ── Infrastructure security (flow-level) ──
    ["Oracle TNS exposure", detectOracleTNSExposure],
    ["NetBIOS info disclosure", detectNetBIOSInfoDisclosure],
  ];

  const totalRules = packetRuleFns.length + flowRuleFns.length;
  let ruleIdx = 0;

  const allFindings: SecurityFinding[] = [];
  const time = <T>(rule: string, run: () => T): T => {
    const t0 = performance.now();
    const out = run();
    timings?.push({ rule, ms: performance.now() - t0 });
    return out;
  };

  for (const [name, fn, select] of packetRuleFns) {
    ruleIdx++;
    onProgress?.(name, ruleIdx, totalRules);
    const subset = select ? select(index) : index.all;
    allFindings.push(...time(name, () => fn(subset)));
  }

  for (const [name, fn] of flowRuleFns) {
    ruleIdx++;
    onProgress?.(name, ruleIdx, totalRules);
    allFindings.push(...time(name, () => fn(flows)));
  }

  onProgress?.("Finalizing findings", totalRules, totalRules);
  return sortFindingsBySeverity(mergeFindings(enrichFindings(allFindings, index)));
}

/**
 * Give every finding capture-time timestamps and packet references.
 * Rules that already supplied them keep theirs; the rest fall back to "packets involving the
 * affected IP" (flagged with refsApproximate) so the UI can still pivot to relevant traffic.
 */
function enrichFindings(findings: SecurityFinding[], index: PacketIndex): SecurityFinding[] {
  const needsRefs = findings.filter((f) => !f.packetIndices || f.firstSeenUs === undefined);
  const wanted = new Set(needsRefs.map((f) => f.affectedIp));
  const byIp = new Map<string, { first: number; last: number; indices: number[] }>();

  if (wanted.size > 0) {
    for (const pkt of index.all) {
      if (!pkt.ip) continue;
      for (const ip of [pkt.ip.srcIp, pkt.ip.dstIp]) {
        if (!wanted.has(ip)) continue;
        let e = byIp.get(ip);
        if (!e) byIp.set(ip, (e = { first: 0, last: 0, indices: [] }));
        if (pkt.timestampUs > 0 && (e.first === 0 || pkt.timestampUs < e.first)) e.first = pkt.timestampUs;
        if (pkt.timestampUs > e.last) e.last = pkt.timestampUs;
        if (e.indices.length < MAX_PACKET_REFS) e.indices.push(pkt.index);
      }
    }
  }

  let captureStart = 0;
  for (const pkt of index.all) {
    if (pkt.timestampUs > 0 && (captureStart === 0 || pkt.timestampUs < captureStart)) {
      captureStart = pkt.timestampUs;
    }
  }

  return findings.map((f) => {
    const out: SecurityFinding = { ...f };
    out.confidence = f.confidence ?? "medium";
    out.occurrences = f.occurrences ?? 1;
    if (!out.packetIndices || out.firstSeenUs === undefined) {
      const ref = byIp.get(f.affectedIp);
      if (ref) {
        out.packetIndices = out.packetIndices ?? ref.indices;
        out.firstSeenUs = out.firstSeenUs ?? ref.first;
        out.lastSeenUs = out.lastSeenUs ?? ref.last;
      } else {
        out.packetIndices = out.packetIndices ?? [];
        out.firstSeenUs = out.firstSeenUs ?? captureStart;
        out.lastSeenUs = out.lastSeenUs ?? captureStart;
      }
      out.refsApproximate = true;
    }
    out.timestamp = Math.floor((out.firstSeenUs ?? 0) / 1000);
    return out;
  });
}

/**
 * Merge findings that share title + affected IP + dedupKey instead of discarding the extras:
 * occurrences are summed, evidence is concatenated, and packet refs/time ranges are unioned.
 */
export function mergeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  const merged = new Map<string, SecurityFinding>();

  for (const f of findings) {
    const key = `${f.title}|${f.affectedIp}|${f.dedupKey ?? ""}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...f });
      continue;
    }
    existing.occurrences = (existing.occurrences ?? 1) + (f.occurrences ?? 1);
    if (f.evidence && !existing.evidence.includes(f.evidence) && existing.evidence.length < 2000) {
      existing.evidence += `\n${f.evidence}`;
    }
    existing.firstSeenUs = Math.min(existing.firstSeenUs ?? Infinity, f.firstSeenUs ?? Infinity);
    existing.lastSeenUs = Math.max(existing.lastSeenUs ?? 0, f.lastSeenUs ?? 0);
    existing.timestamp = Math.floor((existing.firstSeenUs ?? 0) / 1000);
    existing.packetIndices = [
      ...new Set([...(existing.packetIndices ?? []), ...(f.packetIndices ?? [])]),
    ].slice(0, MAX_PACKET_REFS);
    existing.flowIds = [...new Set([...(existing.flowIds ?? []), ...(f.flowIds ?? [])])];
    existing.refsApproximate = !!(existing.refsApproximate && f.refsApproximate);
  }

  return [...merged.values()];
}

/**
 * Compute timeline buckets by binning packets into regular time intervals.
 * Uses adaptive bin count (min 20, max 100) based on packet count.
 * Does not assume packets are sorted (pcapng multi-interface and merged files aren't).
 */
function computeTimelineBuckets(
  packets: Packet[]
): { timestampUs: number; packetCount: number; byteCount: number }[] {
  let minTs = Infinity;
  let maxTs = -Infinity;
  let counted = 0;
  for (const p of packets) {
    if (p.timestampUs <= 0) continue;
    counted++;
    if (p.timestampUs < minTs) minTs = p.timestampUs;
    if (p.timestampUs > maxTs) maxTs = p.timestampUs;
  }
  if (counted < 2) return [];

  const rangeUs = maxTs - minTs;
  if (rangeUs <= 0) return [];

  // Adaptive bin count: more packets → more bins
  const binCount = Math.min(100, Math.max(20, Math.ceil(counted / 200)));
  const binSizeUs = rangeUs / binCount;

  const buckets: { timestampUs: number; packetCount: number; byteCount: number }[] = [];
  for (let i = 0; i < binCount; i++) {
    buckets.push({ timestampUs: minTs + i * binSizeUs, packetCount: 0, byteCount: 0 });
  }

  for (const pkt of packets) {
    if (pkt.timestampUs <= 0) continue;
    const idx = Math.min(binCount - 1, Math.floor((pkt.timestampUs - minTs) / binSizeUs));
    buckets[idx].packetCount++;
    buckets[idx].byteCount += pkt.length;
  }

  return buckets;
}

/**
 * Run the full analysis pipeline on a set of parsed packets.
 * Returns a complete AnalysisResult.
 */
export function analyzePackets(
  packets: Packet[],
  fileName: string,
  onProgress?: (stage: string, current: number, total: number) => void
): AnalysisResult {
  const totalSteps = 8;
  resetFindingIds();

  onProgress?.("Building flows", 1, totalSteps);
  const flows = buildFlows(packets);

  onProgress?.("Building hosts", 2, totalSteps);
  const hosts = buildHosts(flows, packets);

  onProgress?.("Protocol distribution", 3, totalSteps);
  const protocolCounts = calculateProtocolDistribution(packets);

  onProgress?.("Indexing packets", 4, totalSteps);
  const index = buildPacketIndex(packets);

  // Run security rules (has its own sub-progress)
  const ruleTimings: RuleTiming[] = [];
  const findings = runAllRules(packets, flows, onProgress, index, ruleTimings);
  ruleTimings.sort((a, b) => b.ms - a.ms);
  if (import.meta.env?.MODE === "development" && ruleTimings.length > 0) {
    console.table(
      ruleTimings.slice(0, 10).map((t) => ({ rule: t.rule, ms: Math.round(t.ms * 10) / 10 }))
    );
  }

  onProgress?.("Building summary", 5, totalSteps);
  const totalPackets = packets.length;
  let totalBytes = 0;
  let minTs = Infinity;
  let maxTs = -Infinity;
  let stamped = 0;
  for (const p of packets) {
    totalBytes += p.length;
    if (p.timestampUs > 0) {
      stamped++;
      if (p.timestampUs < minTs) minTs = p.timestampUs;
      if (p.timestampUs > maxTs) maxTs = p.timestampUs;
    }
  }
  // Loops, not Math.max(...spread): spreading a few hundred thousand values overflows the stack.
  const durationUs = stamped > 1 ? maxTs - minTs : 0;

  // Top talkers
  const talkerList = Array.from(hosts.entries())
    .map(([ip, info]) => ({
      ip,
      packetCount: info.packetCount,
      byteCount: info.byteCount,
    }))
    .sort((a, b) => b.byteCount - a.byteCount)
    .slice(0, 10);

  // Top destinations (responders of flows)
  const dstCounts = new Map<string, { packetCount: number; byteCount: number }>();
  for (const flow of flows) {
    const existing = dstCounts.get(flow.dstIp);
    if (existing) {
      existing.packetCount += flow.packetCount;
      existing.byteCount += flow.byteCount;
    } else {
      dstCounts.set(flow.dstIp, {
        packetCount: flow.packetCount,
        byteCount: flow.byteCount,
      });
    }
  }
  const topDestinations = Array.from(dstCounts.entries())
    .map(([ip, data]) => ({ ip, ...data }))
    .sort((a, b) => b.byteCount - a.byteCount)
    .slice(0, 10);

  const summary: AnalysisSummary = {
    totalPackets,
    totalBytes,
    durationUs,
    uniqueHosts: hosts.size,
    protocolCounts,
    topTalkers: talkerList,
    topDestinations,
    flowCount: flows.length,
    findingCount: findings.length,
    timelineBuckets: computeTimelineBuckets(packets),
  };

  // Perform NTP traffic analysis
  const ntpAnalysis = analyzeNTPTraffic(packets);

  return {
    packets,
    flows,
    hosts,
    findings,
    protocolCounts,
    summary,
    fileName,
    ntpAnalysis,
    ruleTimings,
  };
}

/**
 * Combine multiple per-file analysis results into a single combined result.
 *
 * Re-runs the full analysis pipeline over the union of all packets so flows,
 * hosts, protocol distribution, security findings, and the summary are all
 * correctly deduplicated and aggregated across file boundaries. This is used
 * both for multi-file uploads and for "add for analysis" merging.
 */
export function combineAnalysisResults(results: AnalysisResult[]): AnalysisResult {
  if (results.length === 0) {
    throw new Error("combineAnalysisResults requires at least one result");
  }
  if (results.length === 1) {
    return results[0];
  }

  // Merge in capture-time order and give every packet a unique index (indices restart at 0 in
  // each file). Shallow copies share the underlying buffers, so no packet bytes are duplicated.
  const merged = results.flatMap((r) => r.packets);
  merged.sort((a, b) => a.timestampUs - b.timestampUs);
  const allPackets = merged.map((p, i) => ({ ...p, index: i }));

  const fileName = results.map((r) => r.fileName).join(", ");
  const combined = analyzePackets(allPackets, fileName);
  const warnings = results.flatMap((r) => r.captureWarnings ?? []);
  if (warnings.length > 0) combined.captureWarnings = warnings;
  return combined;
}
