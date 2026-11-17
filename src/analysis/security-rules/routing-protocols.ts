import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * RIP / RIPv2 — Routing Information Protocol (UDP 520/521)
 * ======================================================================== */

/**
 * Detect RIP routing protocol traffic.
 * RIPv1 has no authentication. RIPv2 supports MD5 authentication but it's
 * often disabled. Both versions are vulnerable to route injection attacks.
 */
export function detectRIPTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ripSources = new Map<string, { count: number; version: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.RIP) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.srcIp;
    let version = 1;

    // Detect RIP version from payload (byte 1: command, byte 2: version)
    if (pkt.appPayload && pkt.appPayload.byteLength >= 4) {
      const view = new Uint8Array(pkt.appPayload);
      version = view[1] || 1; // byte 1 is RIP version
    }

    const entry = ripSources.get(key) || { count: 0, version };
    entry.count++;
    if (version > entry.version) entry.version = version;
    ripSources.set(key, entry);
  }

  for (const [ip, data] of ripSources) {
    const isV1 = data.version === 1;
    findings.push({
      id: nextId(),
      title: isV1
        ? "RIPv1 Traffic Detected — No Authentication (Route Injection Risk)"
        : "RIPv2 Traffic Detected — Verify Authentication",
      severity: isV1 ? Severity.High : Severity.Medium,
      description: isV1
        ? `RIPv1 traffic from ${ip} (${data.count} packets). RIPv1 has absolutely no authentication mechanism — any host on the network can send forged RIP updates and poison the routing table. An attacker can redirect traffic through a malicious router (man-in-the-middle), cause traffic blackholing (denial of service), or create routing loops. RIPv1 should not be used on any production network.`
        : `RIPv2 traffic from ${ip} (${data.count} packets). RIPv2 supports MD5 authentication but it is often misconfigured or disabled. Without authentication, forged RIP updates can inject malicious routes. RIPv2 also sends routes to the broadcast address which can expose internal routing topology.`,
      recommendation: isV1
        ? `1. Immediately disable RIPv1 and migrate to OSPF or BGP with authentication.\n2. If RIP is required, upgrade to RIPv2 with MD5 authentication.\n3. Configure passive interfaces on segments where routing updates should not be sent.\n4. Implement route filtering to reject unexpected route advertisements.\n5. Consider replacing RIP entirely — it has a maximum hop count of 15 and slow convergence.`
        : `1. Enable MD5 authentication on all RIPv2 neighbors.\n2. Restrict RIP updates to trusted interfaces only.\n3. Implement route filtering (prefix-lists) to block unexpected routes.\n4. Consider migrating to OSPF or BGP for better security and scalability.`,
      evidence: `RIP${data.version} source: ${ip}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * HSRP — Hot Standby Router Protocol (UDP 1985)
 * ======================================================================== */

/**
 * Detect HSRP traffic — Cisco's gateway redundancy protocol.
 * HSRP v1 uses a simple text password; HSRP v2 uses MD5.
 * HSRP hijacking lets an attacker become the active gateway (MITM all traffic).
 */
export function detectHSRPTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const hsrpSources = new Map<string, { count: number; hasAuth: boolean }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HSRP) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.srcIp;
    let hasAuth = false;

    // HSRP v1 payload: check if authentication TLV is present (type 1)
    if (pkt.appPayload && pkt.appPayload.byteLength >= 20) {
      const view = new Uint8Array(pkt.appPayload);
      // HSRP v1: byte 0=version, byte 8-15=auth string (non-zero = configured)
      if (pkt.appPayload.byteLength >= 16) {
        const authBytes = view.slice(8, 16);
        hasAuth = authBytes.some((b) => b !== 0);
      }
    }

    const entry = hsrpSources.get(key) || { count: 0, hasAuth };
    entry.count++;
    if (hasAuth) entry.hasAuth = true;
    hsrpSources.set(key, entry);
  }

  for (const [ip, data] of hsrpSources) {
    findings.push({
      id: nextId(),
      title: data.hasAuth
        ? "HSRP Traffic with Authentication Detected"
        : "HSRP Traffic Without Authentication — Gateway Hijacking Risk",
      severity: data.hasAuth ? Severity.Low : Severity.High,
      description: data.hasAuth
        ? `HSRP traffic with authentication detected from ${ip} (${data.count} packets). Note that HSRP v1 uses a simple text password which is transmitted in cleartext and easily sniffed. Prefer HSRP v2 with MD5 authentication.`
        : `HSRP traffic from ${ip} (${data.count} packets) with no authentication detected. An attacker can send forged HSRP Hello packets with a higher priority to become the active default gateway for the VLAN. All traffic from hosts using this virtual IP will then flow through the attacker's machine (man-in-the-middle), enabling credential theft, session hijacking, and traffic manipulation.`,
      recommendation: `1. Enable HSRP MD5 authentication on all HSRP groups (HSRP v2 preferred).\n2. Restrict HSRP multicast (224.0.0.102) to trusted router interfaces only.\n3. Implement DAI (Dynamic ARP Inspection) to prevent ARP spoofing in conjunction with HSRP attacks.\n4. Consider migrating to VRRP with authentication or using BFD for faster failure detection.\n5. Monitor for unexpected HSRP state changes — Active/Standby transitions should be rare.`,
      evidence: `HSRP source: ${ip}, packets: ${data.count}, auth: ${data.hasAuth ? "yes" : "NO"}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * OSPF — Open Shortest Path First (IP protocol 89)
 * ======================================================================== */

/**
 * Detect OSPF routing protocol traffic.
 * OSPF without authentication allows route injection and topology disclosure.
 * Note: OSPF uses IP protocol 89, not a port.
 */
export function detectOSPFTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ospfSources = new Map<string, { count: number; authType: number }>();

  for (const pkt of packets) {
    if (!pkt.ip) continue;
    // OSPF uses IP protocol 89
    if (pkt.ip.protocol !== 89) continue;

    const key = pkt.ip.srcIp;
    let authType = 0; // 0=None, 1=Simple, 2=MD5

    // OSPF header: byte 14-15 = Auth Type field
    if (pkt.appPayload && pkt.appPayload.byteLength >= 16) {
      const view = new Uint8Array(pkt.appPayload);
      authType = (view[14] << 8) | view[15];
    }

    const entry = ospfSources.get(key) || { count: 0, authType };
    entry.count++;
    if (authType > entry.authType) entry.authType = authType;
    ospfSources.set(key, entry);
  }

  for (const [ip, data] of ospfSources) {
    const authNames = ["None", "Simple Password", "MD5 Cryptographic"];
    const authName = authNames[data.authType] || "Unknown";

    findings.push({
      id: nextId(),
      title: data.authType === 0
        ? "OSPF Traffic Without Authentication — Route Injection Risk"
        : data.authType === 1
        ? "OSPF Simple Password Authentication — Upgrade to MD5"
        : "OSPF MD5 Authentication Detected",
      severity: data.authType === 0 ? Severity.High : data.authType === 1 ? Severity.Medium : Severity.Info,
      description: data.authType === 0
        ? `OSPF traffic from ${ip} (${data.count} packets) with no authentication (Type 0). An attacker can inject forged OSPF LSAs (Link State Advertisements) to manipulate the routing table, redirecting traffic through attacker-controlled paths or causing routing loops and denial of service. OSPF without authentication is unacceptable on any network.`
        : data.authType === 1
        ? `OSPF traffic from ${ip} with simple password authentication (Type 1). Simple password auth transmits the password in plaintext within OSPF packets — easily captured and reused for route injection. Upgrade to cryptographic (MD5/SHA) authentication.`
        : `OSPF MD5 authenticated traffic from ${ip} (${data.count} packets). Authentication type: ${authName}. This is good practice. Ensure key rollover procedures are in place.`,
      recommendation: data.authType === 2
        ? `1. Continue using MD5/SHA authentication.\n2. Implement OSPF key chain rotation regularly.\n3. Consider upgrading to OSPFv3 with IPSec for stronger security.`
        : `1. Enable OSPF cryptographic authentication (MD5 or SHA-HMAC) on all interfaces.\n2. Use OSPF key chains for seamless key rotation.\n3. Apply passive-interface to all non-router interfaces to prevent OSPF Hello flooding.\n4. Implement route filtering to reject unexpected LSA types.\n5. Enable OSPF stub areas to limit topology disclosure.`,
      evidence: `OSPF source: ${ip}, packets: ${data.count}, auth-type: ${authName} (${data.authType})`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * EIGRP — Enhanced Interior Gateway Routing Protocol (IP protocol 88)
 * ======================================================================== */

/**
 * Detect EIGRP routing protocol traffic.
 * EIGRP is Cisco proprietary. Without authentication, route injection is possible.
 * Note: EIGRP uses IP protocol 88.
 */
export function detectEIGRPTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const eigrpSources = new Map<string, number>();

  for (const pkt of packets) {
    if (!pkt.ip) continue;
    // EIGRP uses IP protocol 88
    if (pkt.ip.protocol !== 88) continue;

    const key = pkt.ip.srcIp;
    eigrpSources.set(key, (eigrpSources.get(key) || 0) + 1);
  }

  for (const [ip, count] of eigrpSources) {
    findings.push({
      id: nextId(),
      title: "EIGRP Routing Protocol Traffic Detected",
      severity: Severity.Medium,
      description: `EIGRP (Enhanced Interior Gateway Routing Protocol) traffic from ${ip} (${count} packets). EIGRP is Cisco-proprietary and uses IP protocol 88. Without MD5 or SHA authentication configured, EIGRP neighbors are accepted from any device, allowing an attacker to become an EIGRP neighbor and inject malicious routes. Even with authentication, the neighbor relationship itself discloses network topology and address ranges.`,
      recommendation: `1. Enable EIGRP MD5 or SHA-256 authentication on all EIGRP-enabled interfaces.\n2. Use EIGRP named mode (Cisco IOS XE) which supports stronger SHA-256 HMAC.\n3. Apply passive-interface on all access-layer and WAN interfaces.\n4. Implement route filtering using prefix-lists and distribute-lists.\n5. Restrict EIGRP to router-to-router links only — never enable on user-facing VLANs.`,
      evidence: `EIGRP source: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * GRE — Generic Routing Encapsulation (IP protocol 47)
 * ======================================================================== */

/**
 * Detect GRE tunnel traffic.
 * GRE tunnels encapsulate traffic (including inner IP/TCP/UDP) in plaintext.
 * Without encryption, inner traffic is fully readable. GRE is also used
 * for covert channels and traffic evasion.
 */
export function detectGRETraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const greTunnels = new Map<string, { count: number; bytes: number }>();

  for (const pkt of packets) {
    if (!pkt.ip) continue;
    // GRE uses IP protocol 47
    if (pkt.ip.protocol !== 47) continue;

    const key = `${pkt.ip.srcIp} → ${pkt.ip.dstIp}`;
    const entry = greTunnels.get(key) || { count: 0, bytes: 0 };
    entry.count++;
    entry.bytes += pkt.length;
    greTunnels.set(key, entry);
  }

  for (const [pair, data] of greTunnels) {
    const srcIp = pair.split(" → ")[0];
    findings.push({
      id: nextId(),
      title: "GRE Tunnel Traffic Detected — Inner Traffic Not Analyzed",
      severity: Severity.Medium,
      description: `GRE (Generic Routing Encapsulation) tunnel detected on flow ${pair} (${data.count} packets, ${(data.bytes / 1024).toFixed(1)} KB). GRE is a bare tunneling protocol with no encryption or authentication. All traffic inside the GRE tunnel — which may include HTTP, database queries, authentication flows, or sensitive data — is transmitted in cleartext and is completely invisible to current protocol-level security analysis. GRE is also used by attackers to bypass network controls and exfiltrate data covertly.`,
      recommendation: `1. Encrypt GRE tunnels using GRE over IPSec or replace with IPSec/WireGuard natively.\n2. Investigate unexpected GRE tunnels — they may indicate data exfiltration or covert C2 channels.\n3. Restrict GRE (IP protocol 47) at network perimeters to known tunnel endpoints only.\n4. Deploy inspection tools that can decapsulate GRE and analyze the inner traffic.\n5. Verify that all GRE tunnels are documented and authorized.`,
      evidence: `GRE tunnel: ${pair}, packets: ${data.count}, bytes: ${data.bytes}`,
      affectedIp: srcIp,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}
