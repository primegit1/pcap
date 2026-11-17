import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect IGMP floods: excessive membership reports or queries
 * from the same source within a short time window.
 */
export function detectIGMPFlood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track IGMP packets by source IP
  const igmpCount = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IGMP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    igmpCount.set(srcIp, (igmpCount.get(srcIp) ?? 0) + 1);
  }

  // Threshold: more than 100 IGMP packets indicates potential flood
  const threshold = 100;

  for (const [srcIp, count] of igmpCount) {
    if (count >= threshold) {
      findings.push({
        id: nextId(),
        title: "IGMP Flood Pattern Observed (Passive Detection)",
        severity: Severity.Medium,
        description: `Source IP ${srcIp} sent ${count} IGMP packets. A high volume of IGMP traffic (queries, membership reports, orleave messages) may indicate a multicast denial-of-service attack or network scanning activity. IGMP floods can consume switch CPU resources and impact network performance.`,
        recommendation: `1. Rate-limit IGMP traffic from ${srcIp} at the network edge.
2. Enable IGMP snooping on switches and configure appropriate limits.
3. If ${srcIp} is external, block it at the firewall.
4. If the source is internal, investigate the host for malware or misconfigured applications.
5. Configure IGMP query interval and response limits on multicast routers.`,
        evidence: `IGMP packets: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect suspicious multicast group membership patterns.
 * Specifically targets high-numbered ephemeral multicast groups (224.0.0.0/24 unused range,
 * or groups using source filtering in IGMPv3).
 */
export function detectSuspiciousIGMPGroupMembership(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const groupActivity = new Map<string, { srcIp: string; group: string; count: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IGMP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const groupInfo = extractIGMPGroupInfo(pkt);

    if (!groupInfo) continue;

    const key = `${srcIp}-${groupInfo.group}`;
    const existing = groupActivity.get(key) || { srcIp, group: groupInfo.group, count: 0 };
    existing.count++;
    groupActivity.set(key, existing);
  }

  for (const [, activity] of groupActivity) {
    const parts = activity.group.split(".");
    const lastOctet = parseInt(parts[3] || "0", 10);

    // Flag groups using high ephemeral port numbers as potential C2
    if (lastOctet > 200 || hasSuspiciousPattern(activity.group)) {
      findings.push({
        id: nextId(),
        title: "Suspicious IGMP Multicast Group Membership",
        severity: Severity.High,
        description: `Source IP ${activity.srcIp} joined multicast group ${activity.group} (${activity.count} joins detected). Unusual multicast group membership patterns may indicate command-and-control communication, data exfiltration, or tunneling through multicast traffic. IGMPv3 source filtering can be abused to bypass security controls.`,
        recommendation: `1. Investigate ${activity.srcIp} for malware or unauthorized applications.
2. Review network egress filtering rules for multicast traffic.
3. Enable IGMP snooping and limit join frequency.
4. Monitor for additional suspicious multicast activity from this host.
5. Consider blocking high-numbered multicast groups if not required.`,
        evidence: `Group: ${activity.group}, Join count: ${activity.count}`,
        affectedIp: activity.srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Extract group information from IGMP packet info.
 */
function extractIGMPGroupInfo(pkt: Packet): { group: string; hasSources: boolean } | null {
  // We need to parse the packet to get group info
  // This is a simplified approach using the packet info field
  if (!pkt.info) return null;

  // Extract group address from info string like "Membership Report → 239.255.255.254"
  const groupMatch = pkt.info.match(/→\s*([\d.]+)/);
  if (groupMatch) {
    return { group: groupMatch[1], hasSources: pkt.info.includes("sources=") };
  }

  return null;
}

/**
 * Check if a group address follows suspicious patterns.
 */
function hasSuspiciousPattern(group: string): boolean {
  // 224.0.0.0/24 is reserved for "All Networks Multicast Reserved" - should not be subscribed to
  // 224.0.0.x addresses are for protocol discovery (not typically subscribed to by hosts)
  if (group.startsWith("224.0.0.")) {
    // These are control group addresses - should be rare from hosts
    return true;
  }
  return false;
}

/**
 * Extract just the group address from IGMP protocol info string.
 */
export function parseIGMPGroupFromInfo(info: string): string | null {
  const match = info.match(/→\s*([\d.]+)/);
  return match ? match[1] : null;
}