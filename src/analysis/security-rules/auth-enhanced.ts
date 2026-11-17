import type { Packet } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { TCPHeader } from "../../types/packets";

import { nextFindingId as nextId } from "../findings";

/**
 * Auth service ports and their names.
 */
const AUTH_SERVICE_PORTS: Map<number, string> = new Map([
  [22, "SSH"],
  [21, "FTP"],
  [23, "Telnet"],
  [3389, "RDP"],
  [5900, "VNC"],
  [1433, "MSSQL"],
  [3306, "MySQL"],
  [5432, "PostgreSQL"],
  [6379, "Redis"],
  [389, "LDAP"],
  [143, "IMAP"],
  [25, "SMTP"],
  [445, "SMB"],
  [993, "IMAPS"],
  [995, "POP3S"],
  [27017, "MongoDB"],
]);

/**
 * Time window for brute force detection (in microseconds).
 * 5 minutes = 5 * 60 * 1,000,000 μs
 */
const BRUTE_FORCE_WINDOW_US = 5 * 60 * 1_000_000;

/**
 * Minimum connection attempts within the window to trigger a finding.
 */
const BRUTE_FORCE_THRESHOLD = 8;

/**
 * Detect brute force attacks with per-source tracking and time-windowed analysis.
 * Tracks each source IP individually and detects rapid connection attempts
 * to the same auth service within a 5-minute window.
 */
export function detectBruteForceEnhanced(
  packets: Packet[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track per source-IP → per target (ip:port) → list of timestamps
  const attempts = new Map<string, Map<string, number[]>>();

  for (const pkt of packets) {
    if (!pkt.ip || !pkt.transport) continue;
    if (!("syn" in pkt.transport)) continue;

    const tcp = pkt.transport as TCPHeader;
    // Only count SYN packets (connection attempts)
    if (!tcp.syn || tcp.ack) continue;

    const dstPort = tcp.dstPort;
    if (!AUTH_SERVICE_PORTS.has(dstPort)) continue;

    const srcIp = pkt.ip.srcIp;
    const targetKey = `${pkt.ip.dstIp}:${dstPort}`;

    if (!attempts.has(srcIp)) {
      attempts.set(srcIp, new Map());
    }
    const targetMap = attempts.get(srcIp)!;
    const timestamps = targetMap.get(targetKey) || [];
    timestamps.push(pkt.timestampUs);
    targetMap.set(targetKey, timestamps);
  }

  // Analyze each source for brute force patterns
  for (const [srcIp, targetMap] of attempts) {
    let totalAttempts = 0;
    const targetedServices: string[] = [];

    for (const [targetKey, timestamps] of targetMap) {
      if (timestamps.length < BRUTE_FORCE_THRESHOLD) continue;

      // Sort timestamps
      timestamps.sort((a, b) => a - b);

      // Sliding window: find the maximum attempts within the time window
      let maxInWindow = 0;
      let windowStart = 0;

      for (let i = 0; i < timestamps.length; i++) {
        while (
          windowStart < i &&
          timestamps[i] - timestamps[windowStart] > BRUTE_FORCE_WINDOW_US
        ) {
          windowStart++;
        }
        const inWindow = i - windowStart + 1;
        if (inWindow > maxInWindow) {
          maxInWindow = inWindow;
        }
      }

      if (maxInWindow >= BRUTE_FORCE_THRESHOLD) {
        const [dstIp, portStr] = targetKey.split(":");
        const port = parseInt(portStr, 10);
        const serviceName = AUTH_SERVICE_PORTS.get(port) || `Port ${port}`;
        targetedServices.push(`${serviceName} (${dstIp})`);
        totalAttempts += timestamps.length;

        const windowSec = BRUTE_FORCE_WINDOW_US / 1_000_000;
        const ratePerMin = (maxInWindow / windowSec * 60).toFixed(1);

        findings.push({
          id: nextId(),
          title: `Brute Force Attack — ${serviceName} on ${dstIp}`,
          severity: Severity.High,
          description: `Source ${srcIp} made ${maxInWindow} connection attempts to ${serviceName} on ${dstIp}:${port} within a ${windowSec / 60}-minute window (${ratePerMin} attempts/min). ${timestamps.length} total attempts observed. Rapid connection attempts to authentication services are characteristic of automated brute-force password guessing tools.`,
          recommendation: `1. Block ${srcIp} at the firewall if external.
2. Enable account lockout policies on the ${serviceName} service.
3. Implement rate limiting on authentication attempts.
4. Use fail2ban or similar tools to auto-block repeat offenders.
5. Enable multi-factor authentication (MFA) on all remote access services.
6. Review ${serviceName} logs for successful logins after the brute force — the account may be compromised.`,
          evidence: `Service: ${serviceName}, attempts in window: ${maxInWindow}, total: ${timestamps.length}, rate: ${ratePerMin}/min`,
          affectedIp: dstIp,
          category: FindingCategory.Auth,
          timestamp: 0, // replaced with capture time by runAllRules
        });
      }
    }

    // Detect credential stuffing: same source targeting multiple auth services
    if (targetedServices.length >= 2) {
      findings.push({
        id: nextId(),
        title: "Multi-Service Brute Force — Possible Credential Stuffing",
        severity: Severity.Critical,
        description: `Source ${srcIp} is brute-forcing ${targetedServices.length} different services: ${targetedServices.join(", ")}. Attacking multiple authentication services simultaneously is characteristic of credential stuffing — using leaked username/password databases to try against multiple services. This indicates a high-confidence attack.`,
        recommendation: `1. Immediately block ${srcIp} at the network perimeter.
2. Reset passwords for all accounts accessed from ${srcIp}.
3. Enable MFA on all targeted services.
4. Check haveibeenpwned.com for known credential leaks matching your domain.
5. Implement IP-based rate limiting across all auth services.
6. Review all auth service logs for successful logins from this source.`,
        evidence: `Source: ${srcIp}, targeted services: ${targetedServices.join(", ")}, total attempts: ${totalAttempts}`,
        affectedIp: srcIp,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
