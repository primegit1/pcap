import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * BGP (Border Gateway Protocol) — TCP port 179
 * ======================================================================== */

/**
 * Detect BGP sessions with unauthenticated peers.
 * BGP without MD5/TCP-AO authentication is vulnerable to session hijacking,
 * where an attacker can inject, modify, or withdraw routes by spoofing
 * BGP packets. This is the foundation of BGP route hijacking attacks.
 *
 * We detect BGP flows and flag them for authentication review.
 */
export function detectBGPUnauthenticated(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const bgpPeers = new Map<string, { count: number; peers: Set<string> }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.BGP) continue;
    if (flow.packetCount < 3) continue;

    const srcIp = flow.srcIp;
    const dstIp = flow.dstIp;

    const entry = bgpPeers.get(srcIp);
    if (entry) {
      entry.count++;
      entry.peers.add(dstIp);
    } else {
      bgpPeers.set(srcIp, { count: 1, peers: new Set([dstIp]) });
    }
  }

  for (const [peerIp, data] of bgpPeers) {
    findings.push({
      id: nextId(),
      title: "BGP Session Detected (Verify MD5/TCP-AO Authentication)",
      severity: Severity.High,
      description: `BGP peer ${peerIp} has ${data.count} session(s) with ${data.peers.size} neighbor(s). BGP is the protocol that controls internet routing — unauthorized or unauthenticated BGP sessions can result in route hijacking, traffic interception, or global routing disruptions. Without MD5 or TCP-AO authentication, BGP sessions are vulnerable to TCP reset attacks and session spoofing. A single compromised BGP session can redirect traffic for entire network blocks.`,
      recommendation: `1. Ensure all BGP sessions use MD5 authentication or TCP-AO (RFC 5925).
2. Implement BGPsec (RFC 8205) or RPKI Route Origin Validation to prevent route hijacking.
3. Configure prefix-lists and AS-path filters to limit accepted and advertised routes.
4. Enable BGP Graceful Restart to reduce disruption from session flaps.
5. Monitor BGP route announcements against IRR (Internet Routing Registry) databases.
6. Implement BGP monitoring tools (BGPmon, RIPE RIS) for route anomaly detection.`,
      evidence: `BGP peer: ${peerIp}, Sessions: ${data.count}, Neighbors: ${[...data.peers].join(", ")}`,
      affectedIp: peerIp,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect BGP route hijacking indicators.
 * Flags BGP speakers advertising routes for prefixes that are:
 * - More specific than expected (sub-prefix hijacking)
 * - Originating from unexpected AS numbers
 * - Advertising an unusually large number of prefixes
 *
 * At the packet/flow level, we detect unusual patterns like a single
 * BGP speaker advertising to many peers or excessive UPDATE messages.
 */
export function detectBGPRouteHijack(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const bgpUpdaters = new Map<string, { updateCount: number; peers: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.BGP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const dstIp = pkt.ip.dstIp;
    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();

    // BGP UPDATE messages carry route announcements/withdrawals
    if (summary.includes("update")) {
      const entry = bgpUpdaters.get(srcIp);
      if (entry) {
        entry.updateCount++;
        entry.peers.add(dstIp);
      } else {
        bgpUpdaters.set(srcIp, { updateCount: 1, peers: new Set([dstIp]) });
      }
    }
  }

  for (const [srcIp, data] of bgpUpdaters) {
    // Excessive updates may indicate route flapping or hijacking attempts
    if (data.updateCount >= 20) {
      findings.push({
        id: nextId(),
        title: "High Volume of BGP UPDATE Messages",
        severity: Severity.High,
        description: `BGP speaker ${srcIp} sent ${data.updateCount} UPDATE messages to ${data.peers.size} peer(s). A high volume of BGP updates may indicate route flapping (dampening needed), a route hijacking attempt, or a BGP feed being injected. Route flapping degrades global routing stability, while excessive prefix announcements can signal a hijack in progress.`,
        recommendation: `1. Check if ${srcIp} is an authorized BGP speaker for this network.
2. Review the specific prefixes being advertised — look for unexpected or more-specific routes.
3. Compare advertised prefixes against RPKI ROA (Route Origin Authorization) records.
4. Enable BGP route dampening to reduce instability from flapping.
5. Verify max-prefix limits are configured on all BGP neighbors.
6. Check Route Views or RIPE RIS for external visibility of these announcements.`,
        evidence: `Speaker: ${srcIp}, UPDATEs: ${data.updateCount}, Peers: ${data.peers.size}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect BGP NOTIFICATION errors — session errors that cause tear-downs.
 * Repeated NOTIFICATION messages may indicate misconfiguration, attacks
 * attempting to disrupt BGP sessions, or incompatible BGP implementations.
 */
export function detectBGPNotifications(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const notificationSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.BGP) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    if (summary.includes("notification") || summary.includes("cease") || summary.includes("error")) {
      const srcIp = pkt.ip.srcIp;
      notificationSources.set(srcIp, (notificationSources.get(srcIp) || 0) + 1);
    }
  }

  for (const [srcIp, count] of notificationSources) {
    if (count >= 3) {
      findings.push({
        id: nextId(),
        title: "Repeated BGP NOTIFICATION Errors",
        severity: Severity.Medium,
        description: `BGP speaker ${srcIp} sent ${count} NOTIFICATION messages. BGP NOTIFICATIONs cause session termination and are sent when errors are detected. Repeated notifications indicate persistent misconfiguration, incompatible BGP features, or potential attacks attempting to disrupt routing sessions (TCP RST injection, malformed UPDATE attacks).`,
        recommendation: `1. Review BGP logs on ${srcIp} for specific NOTIFICATION error codes.
2. Common errors: Cease (6) — check if max-prefix limit is being hit; Open Message Error (2) — version/capability mismatch; Update Message Error (3) — malformed attributes.
3. Verify BGP configuration consistency (AS numbers, hold timers, capabilities).
4. Check for TCP reset attacks targeting the BGP session.
5. Ensure MD5 authentication is enabled to prevent session spoofing.`,
        evidence: `Source: ${srcIp}, NOTIFICATION count: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
