import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * IPSec/IKE — UDP 500/4500
 * ======================================================================== */

/**
 * Detect IKE Aggressive Mode — exposes PSK to offline cracking.
 * IKE Main Mode (6 messages) protects the identity behind DH encryption,
 * but Aggressive Mode (3 messages) sends the PSK hash in cleartext,
 * allowing offline brute-force or dictionary attacks.
 */
export function detectIKEAggressiveMode(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ikeInitiators = new Map<string, { count: number; responders: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IPSecIKE) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // Aggressive mode is IKE phase 1 with fewer messages; identify by ID payload in initial exchange
    if (summary.includes("aggressive") || summary.includes("identity") || summary.includes("id payload")) {
      const srcIp = pkt.ip.srcIp;
      const dstIp = pkt.ip.dstIp;
      const entry = ikeInitiators.get(srcIp);
      if (entry) {
        entry.count++;
        entry.responders.add(dstIp);
      } else {
        ikeInitiators.set(srcIp, { count: 1, responders: new Set([dstIp]) });
      }
    }
  }

  for (const [srcIp, data] of ikeInitiators) {
    findings.push({
      id: nextId(),
      title: "IKE Aggressive Mode Detected (PSK Vulnerable to Offline Cracking)",
      severity: Severity.High,
      description: `IKE Aggressive Mode traffic detected from ${srcIp} to ${data.responders.size} responder(s). Aggressive Mode sends the pre-shared key hash in cleartext as part of the IKE exchange, enabling offline dictionary or brute-force attacks (tools: ikecrack, ikescan). Main Mode protects the identity behind Diffie-Hellman encryption but Aggressive Mode does not. Once the PSK is cracked, the attacker can establish unauthorized IPsec tunnels.`,
      recommendation: `1. Switch all IKE Phase 1 negotiations to Main Mode or IKEv2.
2. If Aggressive Mode is required for remote access, use certificate-based auth instead of PSK.
3. If PSK is mandatory, ensure it is high-entropy (32+ characters, random).
4. Use IKEv2 which does not have Aggressive Mode.
5. Audit VPN configurations for Aggressive Mode enablement.
6. Monitor for IKE scanning tools (ike-scan, nmap IKE scripts) targeting the VPN gateway.`,
      evidence: `Source: ${srcIp}, Aggressive Mode packets: ${data.count}, Responders: ${data.responders.size}`,
      affectedIp: srcIp,
      category: FindingCategory.Auth,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect IKE enumeration / scanning — probing VPN gateways for
 * supported transforms and identities. Tools like ike-scan and nmap
 * can enumerate IKE proposals and extract VPN gateway fingerprints.
 */
export function detectIKEScanning(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ikeSources = new Map<string, { count: number; targets: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IPSecIKE) continue;
    if (!pkt.ip) continue;

    // Count all IKE initiation packets (SA initiation)
    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    if (summary.includes("sa") || summary.includes("init") || summary.includes("request")) {
      const srcIp = pkt.ip.srcIp;
      const dstIp = pkt.ip.dstIp;
      const entry = ikeSources.get(srcIp);
      if (entry) {
        entry.count++;
        entry.targets.add(dstIp);
      } else {
        ikeSources.set(srcIp, { count: 1, targets: new Set([dstIp]) });
      }
    }
  }

  for (const [srcIp, data] of ikeSources) {
    // Scanning = many IKE SA initiations to different targets, or high volume to one
    if (data.count >= 15 || data.targets.size >= 5) {
      findings.push({
        id: nextId(),
        title: "IKE Scanning Activity Detected",
        severity: Severity.Medium,
        description: `Source ${srcIp} sent ${data.count} IKE SA initiation messages to ${data.targets.size} VPN gateway(s). High-volume IKE initiations may indicate VPN gateway enumeration using tools like ike-scan or nmap. Attackers probe IKE to discover supported encryption proposals, authentication methods, and VPN vendor fingerprints for targeted attacks.`,
        recommendation: `1. Investigate ${srcIp} — determine if it is an authorized VPN client.
2. If unauthorized, block UDP/500 and UDP/4500 from ${srcIp} at the firewall.
3. Implement IKE rate-limiting on VPN gateways.
4. Use IKE fragmentation (RFC 7383) to reduce information leakage.
5. Configure VPN gateways to not respond to unsupported IKE proposals.
6. Monitor for repeated IKE SA initiations without completion (scan fingerprint).`,
        evidence: `Source: ${srcIp}, IKE initiations: ${data.count}, Targets: ${data.targets.size}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ========================================================================
 * OpenVPN — UDP 1194 (also TCP 1194)
 * ======================================================================== */

/**
 * Detect OpenVPN on default port with static key mode.
 * OpenVPN supports two modes: TLS (certificate-based, secure) and
 * static key (pre-shared key, no forward secrecy). Static key mode
 * is simpler but less secure and should be flagged for review.
 */
export function detectOpenVPNDefaultPort(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const vpnEndpoints = new Map<string, { count: number; peers: Set<string> }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.OpenVPN) continue;
    if (flow.packetCount < 3) continue;

    const server = flow.dstPort === 1194 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 1194 ? flow.srcIp : flow.dstIp;

    const entry = vpnEndpoints.get(server);
    if (entry) {
      entry.count++;
      entry.peers.add(client);
    } else {
      vpnEndpoints.set(server, { count: 1, peers: new Set([client]) });
    }
  }

  for (const [server, data] of vpnEndpoints) {
    findings.push({
      id: nextId(),
      title: "OpenVPN on Default Port 1194",
      severity: Severity.Low,
      description: `OpenVPN server ${server} is running on the default port 1194 with ${data.peers.size} connected peer(s). The default port is well-known and routinely scanned. Additionally, if using static key mode (instead of TLS), the VPN lacks forward secrecy and the pre-shared key is a single point of compromise. Modern VPNs should use TLS mode with certificates and consider WireGuard or IKEv2 as alternatives.`,
      recommendation: `1. Consider changing the OpenVPN port to a non-standard port.
2. Verify TLS mode (not static key) is in use — check for "secret" vs "ca/cert/key" in config.
3. If using static key mode, migrate to TLS mode with unique client certificates.
4. Use AES-256-GCM cipher and SHA2 authentication (not BF-CBC or SHA1).
5. Consider migrating to WireGuard or IKEv2 for modern VPN requirements.
6. Restrict UDP/1194 access at the firewall to authorized client IPs only.`,
      evidence: `Server: ${server}, Flows: ${data.count}, Peers: ${data.peers.size}, Port: 1194`,
      affectedIp: server,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/* ========================================================================
 * QUIC — UDP 443
 * ======================================================================== */

/**
 * Detect QUIC version negotiation / downgrade attempts.
 * QUIC is encrypted by design (TLS 1.3 inside), but version negotiation
 * packets are sent in cleartext. An attacker could force a version
 * downgrade to an older, potentially weaker QUIC version, or use
 * version negotiation as a fingerprinting vector.
 */
export function detectQUICVersionNegotiation(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const vnSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.QUIC) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    if (summary.includes("version negotiation") || summary.includes("version mismatch")) {
      const srcIp = pkt.ip.srcIp;
      vnSources.set(srcIp, (vnSources.get(srcIp) || 0) + 1);
    }
  }

  for (const [srcIp, count] of vnSources) {
    if (count >= 5) {
      findings.push({
        id: nextId(),
        title: "QUIC Version Negotiation Flood (Potential Downgrade Attack)",
        severity: Severity.Low,
        description: `Source ${srcIp} sent ${count} QUIC version negotiation packets. While QUIC is encrypted by design (TLS 1.3), version negotiation happens in cleartext before encryption is established. Repeated version negotiation attempts could indicate a version downgrade attack, where an attacker forces negotiation of an older QUIC version with weaker security properties, or fingerprinting of QUIC server capabilities.`,
        recommendation: `1. Investigate ${srcIp} to determine if it is a legitimate client with version compatibility issues.
2. Ensure the QUIC server only supports the latest QUIC version (RFC 9000/9369).
3. Configure the server to reject unsupported version negotiations.
4. Monitor for patterns consistent with QUIC scanning tools.
5. If using HTTP/3, ensure the Alt-Svc header advertises only supported versions.`,
        evidence: `Source: ${srcIp}, Version negotiation packets: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
