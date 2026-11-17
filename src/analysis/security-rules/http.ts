import { Protocol } from "../../types/packets";
import type { SecurityFinding, FlowRecord } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect potential clear-text credentials in HTTP traffic.
 * Looks for patterns like password=, passwd=, Authorization: Basic.
 */
export function detectClearTextCredentials(
  flows: FlowRecord[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.HTTP) continue;
    // HTTP on non-standard port is more suspicious
    if (flow.dstPort !== 80 && flow.dstPort !== 8080) {
      findings.push({
        id: nextId(),
        title: "HTTP Service on Non-Standard Port",
        severity: Severity.Low,
        description: `HTTP traffic detected on port ${flow.dstPort} (not 80/8080) between ${flow.srcIp} and ${flow.dstIp}. HTTP on non-standard ports may indicate a hidden web service, a misconfigured application, or an attempt to evade detection by using unusual ports.`,
        recommendation: `1. Verify the web service on ${flow.dstIp}:${flow.dstPort} is authorized.
2. Check if the service should be using HTTPS instead of plain HTTP.
3. Ensure the service is patched and properly configured.
4. If unauthorized, block the port and investigate the host.`,
        evidence: `Source: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}`,
        affectedIp: flow.dstIp,
        category: FindingCategory.HTTP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect suspicious user agents in HTTP flows.
 * Note: For MVP we rely on flow-level analysis since we don't
 * deep-inspect HTTP payload in the parser.
 */
export function detectSuspiciousUserAgents(
  flows: FlowRecord[]
): SecurityFinding[] {
  // Full implementation would require HTTP payload inspection.
  // For MVP we flag HTTP flows that are small and frequent
  // (potential scanning pattern).
  const findings: SecurityFinding[] = [];

  const httpFlowsMap = new Map<string, { count: number; flows: FlowRecord[] }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.HTTP) continue;
    const key = flow.srcIp;
    const existing = httpFlowsMap.get(key);
    if (existing) {
      existing.count++;
      existing.flows.push(flow);
    } else {
      httpFlowsMap.set(key, { count: 1, flows: [flow] });
    }
  }

  for (const [srcIp, data] of httpFlowsMap) {
    if (data.count > 50) {
      // High number of unique HTTP flows to different destinations
      const uniqueDsts = new Set(data.flows.map(f => f.dstIp));
      if (uniqueDsts.size > 10) {
        findings.push({
          id: nextId(),
          title: "HTTP Scanning Activity",
          severity: Severity.High,
          description: `Source IP ${srcIp} made HTTP requests to ${uniqueDsts.size} different destinations (${data.count} total flows). A single host making HTTP requests to many different destinations may indicate web reconnaissance, where an attacker probes for vulnerable web applications.`,
          recommendation: `1. Investigate ${srcIp} for automated scanning tools (e.g., gobuster, dirbuster, nikto).
2. Review web server logs for unusual request patterns from this IP.
3. If external, block at the WAF or perimeter firewall.
4. If internal, check for compromised hosts or unauthorized vulnerability scanning.`,
          evidence: `Unique destinations: ${uniqueDsts.size}, total flows: ${data.count}`,
          affectedIp: srcIp,
          category: FindingCategory.HTTP,
          timestamp: 0, // replaced with capture time by runAllRules
        });
      }
    }
  }

  return findings;
}

/**
 * Detect executable downloads via HTTP.
 */
export function detectExecutableDownloads(
  flows: FlowRecord[]
): SecurityFinding[] {
  // For MVP: flag HTTP flows with large outbound data (response)
  // as potential file downloads
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.HTTP) continue;
    // Large response bodies may be file downloads
    if (flow.byteCount > 5 * 1024 * 1024) {
      // More than 5MB
      findings.push({
        id: nextId(),
        title: "Large HTTP Response — Possible File Download",
        severity: Severity.Low,
        description: `Large HTTP response from ${flow.dstIp} to ${flow.srcIp}: ${(flow.byteCount / (1024 * 1024)).toFixed(1)}MB transferred. Large HTTP responses may indicate file downloads including executables, archives, or documents that could contain malicious content.`,
        recommendation: `1. Verify the downloaded file is legitimate and expected.
2. Check the source ${flow.dstIp} against known safe/unsafe domains.
3. If the download was unexpected, scan the client ${flow.srcIp} for malware.
4. Consider deploying a web proxy with content filtering.
5. Inspect the MIME type and file extension if available from HTTP headers.`,
        evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Bytes: ${flow.byteCount.toLocaleString()}`,
        affectedIp: flow.srcIp,
        category: FindingCategory.HTTP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
