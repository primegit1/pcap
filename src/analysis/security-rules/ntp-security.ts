import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { parseNTPHeader } from "./ntp";

import { nextFindingId as nextId } from "../findings";

/**
 * NTP Mode values
 */
const NTP_MODE_SERVER = 4;

/**
 * Detect NTP amplification attacks — servers responding with large responses
 * to small requests (monlist/peer list commands can produce 100x amplification).
 */
export function detectNTPAmplification(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track request/response sizes per server
  const serverStats = new Map<string, {
    requests: number;
    responses: number;
    requestBytes: number;
    responseBytes: number;
  }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.NTP) continue;
    if (!pkt.ip || !pkt.transport || !pkt.appPayload) continue;

    const udp = pkt.transport as { srcPort: number; dstPort: number };
    const header = parseNTPHeader(pkt.appPayload);
    if (!header) continue;

    // Identify server by the side using port 123 as source
    const isFromServer = udp.srcPort === 123 || header.mode === NTP_MODE_SERVER;
    const serverIp = isFromServer ? pkt.ip.srcIp : pkt.ip.dstIp;

    const stats = serverStats.get(serverIp) || {
      requests: 0, responses: 0, requestBytes: 0, responseBytes: 0,
    };

    if (isFromServer) {
      stats.responses++;
      stats.responseBytes += pkt.length;
    } else {
      stats.requests++;
      stats.requestBytes += pkt.length;
    }

    serverStats.set(serverIp, stats);
  }

  // Flag servers with high response-to-request ratio (amplification)
  for (const [serverIp, stats] of serverStats) {
    if (stats.requests === 0) continue;

    const amplificationRatio = stats.responseBytes / Math.max(stats.requestBytes, 1);

    // NTP monlist can produce ~4680-byte responses to 48-byte requests (~100x)
    if (amplificationRatio > 10 && stats.responses > 5) {
      findings.push({
        id: nextId(),
        title: "NTP Amplification Attack Pattern Detected",
        severity: Severity.High,
        description: `NTP server ${serverIp} shows a ${amplificationRatio.toFixed(1)}x amplification ratio (${stats.requests} requests, ${stats.responses} responses). NTP amplification attacks exploit the monlist (REQ_MON_GETLIST_1) command which returns up to 4680 bytes for a 48-byte request — a 100x amplification factor. This is one of the most powerful DDoS amplification vectors.`,
        recommendation: `1. Upgrade NTP server to ntpd 4.2.7p26+ or chrony which disables monlist by default.
2. Add "disable monitor" to ntp.conf to disable the monlist command.
3. Implement BCP-38 ingress filtering to prevent IP spoofing.
4. Rate-limit NTP responses at the network edge.
5. Consider using NTP authentication (symmetric keys or Autokey) to prevent spoofed requests.
6. Monitor NTP traffic for unusual query patterns.`,
        evidence: `Server: ${serverIp}, amplification: ${amplificationRatio.toFixed(1)}x, requests: ${stats.requests}, responses: ${stats.responses}`,
        affectedIp: serverIp,
        category: FindingCategory.NTP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect NTP time synchronization issues — unsynchronized servers (stratum 0)
 * or Kiss-of-Death responses indicate problems that could affect time-critical
 * security systems (logging, certificate validation, authentication).
 */
export function detectNTPTimeShift(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const unsyncServers = new Set<string>();
  const kodServers = new Map<string, string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.NTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const header = parseNTPHeader(pkt.appPayload);
    if (!header) continue;

    // Stratum 0 = unsynchronized server
    if (header.stratum === 0) {
      const ip = pkt.ip.srcIp;
      if (!unsyncServers.has(ip)) {
        unsyncServers.add(ip);
        findings.push({
          id: nextId(),
          title: "Unsynchronized NTP Server Detected (Stratum 0)",
          severity: Severity.Medium,
          description: `NTP server ${ip} is reporting stratum 0 (unsynchronized). An unsynchronized NTP server cannot provide accurate time. Inaccurate time affects security systems that depend on timestamps: log correlation, certificate validation, authentication protocols (Kerberos), and SIEM alerting. A stratum-0 server may also indicate a misconfigured or compromised time source.`,
          recommendation: `1. Verify the NTP server configuration on ${ip} — check its upstream time source.
2. Ensure the server is configured with valid upstream NTP peers.
3. Replace the unsynchronized server with a reliable stratum-1 or stratum-2 source.
4. Verify network connectivity to upstream NTP servers.
5. Monitor for time drift on all systems using this NTP server.`,
          evidence: `Server: ${ip}, stratum: 0, leap indicator: ${header.leapIndicator}`,
          affectedIp: ip,
          category: FindingCategory.NTP,
          timestamp: 0, // replaced with capture time by runAllRules
        });
      }
    }

    // Kiss-of-Death (stratum 255) — server is refusing to serve time
    if (header.stratum === 16 || header.referenceId.startsWith("KoD:")) {
      const ip = pkt.ip.srcIp;
      const kode = header.referenceId.replace("KoD:", "");
      if (!kodServers.has(ip)) {
        kodServers.set(ip, kode);
        findings.push({
          id: nextId(),
          title: "NTP Kiss-of-Death Response Detected",
          severity: Severity.Low,
          description: `NTP server ${ip} sent a Kiss-of-Death (KoD) response with code "${kode}". KoD responses indicate the server is explicitly refusing to serve time, often due to rate limiting, access restrictions, or policy violations by the client. Repeated KoD responses from a primary time source can cause time synchronization failures across dependent systems.`,
          recommendation: `1. Review the NTP client configuration sending requests to ${ip}.
2. Reduce the polling rate if the server is rate-limiting.
3. Consider using alternative NTP servers as backup time sources.
4. Check if the KoD code indicates a specific policy violation (e.g., RATE, DENY, RSTR).
5. Ensure your NTP client is not sending excessive requests.`,
          evidence: `Server: ${ip}, KoD code: ${kode}`,
          affectedIp: ip,
          category: FindingCategory.NTP,
          timestamp: 0, // replaced with capture time by runAllRules
        });
      }
    }
  }

  return findings;
}

/**
 * Detect NTP spoofing — multiple servers claiming the same stratum and
 * reference ID, which may indicate NTP-based DDoS or time manipulation.
 */
export function detectNTPSpoofing(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track (stratum, refId) → set of server IPs
  const refIdMap = new Map<string, Set<string>>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.NTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const header = parseNTPHeader(pkt.appPayload);
    if (!header || header.stratum === 0 || header.stratum >= 16) continue;

    // Only check servers (mode 4 or srcPort 123)
    const transport = pkt.transport as { srcPort: number } | null;
    if (!transport || transport.srcPort !== 123) continue;

    const key = `stratum=${header.stratum}|ref=${header.referenceId}`;
    const ips = refIdMap.get(key) || new Set<string>();
    ips.add(pkt.ip.srcIp);
    refIdMap.set(key, ips);
  }

  // Flag when multiple IPs claim identical NTP identity (possible spoofing)
  for (const [refKey, ips] of refIdMap) {
    if (ips.size >= 3) {
      findings.push({
        id: nextId(),
        title: "Potential NTP Spoofing — Multiple Servers with Same Identity",
        severity: Severity.Medium,
        description: `${ips.size} different IP addresses are claiming the same NTP identity (${refKey}). This could indicate NTP spoofing, where an attacker impersonates a legitimate time server to manipulate time synchronization on client systems. Time manipulation can undermine log integrity, certificate validation, and Kerberos authentication.`,
        recommendation: `1. Verify the legitimate NTP server IP(s) for this reference identity.
2. Configure NTP clients with explicit server IP addresses, not DNS names.
3. Enable NTP authentication (symmetric keys) to prevent spoofed responses.
4. Check for network-level attacks (ARP spoofing, route manipulation).
5. Monitor for time drift anomalies on NTP clients.`,
        evidence: `Identity: ${refKey}, IPs: ${Array.from(ips).slice(0, 10).join(", ")}`,
        affectedIp: Array.from(ips)[0],
        category: FindingCategory.NTP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
