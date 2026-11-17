import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { parseARP } from "../../parsers/arp";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect ARP spoofing: different MAC addresses claiming the same IP.
 * Classic sign of ARP cache poisoning / man-in-the-middle attacks.
 * Also detects one MAC claiming multiple IPs (ARP masquerading).
 */
export function detectARPSpoofing(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track IP → set of MACs that claimed it (via ARP reply)
  const ipMacs = new Map<string, Map<string, number>>();
  // Track MAC → set of IPs it claimed
  const macIps = new Map<string, Set<string>>();
  // Track (IP, MAC) pairs and when they were first seen with a different MAC
  const firstSeen = new Map<string, string>(); // key: ip, value: first mac seen

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ARP) continue;
    if (!pkt.appPayload) continue;

    const arp = parseARP(pkt.appPayload);
    if (!arp) continue;

    if (arp.operation !== 2) continue; // Only ARP replies matter for spoofing

    const ip = arp.senderIp;
    const mac = arp.senderMac;

    // Skip zero/broadcast addresses
    if (ip === "0.0.0.0" || mac === "00:00:00:00:00:00") continue;

    // Track IP → MAC mapping
    if (!ipMacs.has(ip)) {
      ipMacs.set(ip, new Map());
    }
    const macCounts = ipMacs.get(ip)!;
    macCounts.set(mac, (macCounts.get(mac) || 0) + 1);

    // Track MAC → IP mapping
    if (!macIps.has(mac)) {
      macIps.set(mac, new Set());
    }
    macIps.get(mac)!.add(ip);

    // Track first MAC seen for each IP
    if (!firstSeen.has(ip)) {
      firstSeen.set(ip, mac);
    }
  }

  // Check for IPs claimed by multiple MACs (classic spoofing)
  for (const [ip, macs] of ipMacs) {
    if (macs.size >= 2) {
      const macList = Array.from(macs.entries())
        .map(([m, c]) => `${m} (${c}x)`)
        .join(", ");

      findings.push({
        id: nextId(),
        title: "ARP Spoofing Detected — Multiple MACs Claiming Same IP",
        severity: Severity.Critical,
        description: `IP address ${ip} is being claimed by ${macs.size} different MAC addresses: ${macList}. This is a definitive indicator of ARP spoofing, where an attacker sends forged ARP replies to associate their MAC address with a legitimate IP. This enables man-in-the-middle attacks, session hijacking, and denial of service.`,
        recommendation: `1. Identify the legitimate MAC for ${ip} (check DHCP bindings / ARP table on router).
2. Block the rogue MAC(s) at the switch port level.
3. Enable Dynamic ARP Inspection (DAI) on your switches.
4. Configure static ARP entries for critical infrastructure IPs.
5. Deploy ARP monitoring/alerting (arpwatch, Snort, etc.).
6. Investigate the attacker host for further compromise.`,
        evidence: `IP: ${ip}, Claiming MACs: ${macList}`,
        affectedIp: ip,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  // Check for MACs claiming many IPs (ARP masquerading)
  for (const [mac, ips] of macIps) {
    if (ips.size >= 3) {
      findings.push({
        id: nextId(),
        title: "ARP Masquerading — Single MAC Claiming Multiple IPs",
        severity: Severity.High,
        description: `MAC address ${mac} is claiming ${ips.size} different IP addresses: ${Array.from(ips).join(", ")}. A single host claiming multiple IPs via ARP may indicate an attacker performing ARP masquerading to intercept traffic destined for multiple hosts, or a host with multiple virtual IPs configured (unusual outside of router/cluster scenarios).`,
        recommendation: `1. Verify whether ${mac} is a legitimate router/firewall/cluster node.
2. If ${mac} is not a known multi-IP device, block it immediately.
3. Investigate the host for ARP spoofing tools (ettercap, arpspoof, bettercap).
4. Review switch CAM/MAC tables for anomalies.`,
        evidence: `MAC: ${mac}, IPs claimed: ${Array.from(ips).join(", ")}`,
        affectedIp: Array.from(ips)[0],
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect ARP cache poisoning: ARP reply changes the IP→MAC mapping
 * previously established by another source.
 */
export function detectARPCachePoisoning(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  // Track IP → (first MAC, timestamp)
  const ipToInitial = new Map<string, { mac: string; tsUs: number }>();
  // Track poisoning events: sourceMAC injected { ip: newMAC } replacing oldMAC
  const poisoningEvents: { ip: string; originalMac: string; attackerMac: string }[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ARP) continue;
    if (!pkt.appPayload) continue;

    const arp = parseARP(pkt.appPayload);
    if (!arp) continue;

    if (arp.operation !== 2) continue; // Only replies

    const ip = arp.senderIp;
    const mac = arp.senderMac;

    if (ip === "0.0.0.0" || mac === "00:00:00:00:00:00") continue;

    const existing = ipToInitial.get(ip);
    if (!existing) {
      ipToInitial.set(ip, { mac, tsUs: pkt.timestampUs });
    } else if (existing.mac !== mac) {
      // MAC changed for this IP — potential poisoning
      const alreadyReported = poisoningEvents.some(
        e => e.ip === ip && e.originalMac === existing.mac && e.attackerMac === mac
      );
      if (!alreadyReported) {
        poisoningEvents.push({ ip, originalMac: existing.mac, attackerMac: mac });
      }
    }
  }

  for (const event of poisoningEvents) {
    findings.push({
      id: nextId(),
      title: "ARP Cache Poisoning Attempt Detected",
      severity: Severity.Critical,
      description: `ARP cache poisoning detected: IP ${event.ip} was first associated with MAC ${event.originalMac}, but later a new ARP reply from MAC ${event.attackerMac} attempted to redirect traffic to a different host. This is the hallmark of ARP cache poisoning — an attacker injects forged ARP replies to redirect traffic through their machine, enabling eavesdropping, modification, or denial of service.`,
      recommendation: `1. Immediately isolate the attacker MAC: ${event.attackerMac}.
2. Clear ARP caches on affected devices.
3. Enable Dynamic ARP Inspection (DAI) and DHCP snooping on switches.
4. Configure static ARP for critical servers and default gateway.
5. Check ${event.attackerMac} for ARP spoofing tools (arpspoof, ettercap, Cain & Abel).
6. Review network logs for suspicious traffic redirection.`,
      evidence: `IP: ${event.ip}, Original MAC: ${event.originalMac}, Attacker MAC: ${event.attackerMac}`,
      affectedIp: event.ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect ARP request flood: excessive ARP requests from a single source.
 * High volumes may indicate ARP scanning, host discovery, or DoS.
 */
export function detectARPRequestFlood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const srcCounts = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ARP) continue;
    if (!pkt.appPayload) continue;

    const arp = parseARP(pkt.appPayload);
    if (!arp) continue;

    if (arp.operation !== 1) continue; // Only requests

    // Track by sender MAC + IP combination
    const key = `${arp.senderMac}`;
    srcCounts.set(key, (srcCounts.get(key) || 0) + 1);
  }

  for (const [key, count] of srcCounts) {
    if (count >= 10) {
      findings.push({
        id: nextId(),
        title: "ARP Request Flood Detected",
        severity: Severity.High,
        description: `Source MAC ${key} sent ${count} ARP requests. A high volume of ARP requests from a single host often indicates ARP-based host discovery (network scanning) or an ARP flood denial-of-service attack. Excessive ARP traffic can degrade switch performance and enable reconnaissance.`,
        recommendation: `1. Investigate the host ${key} for scanning tools (nmap, arp-scan, netdiscover).
2. Rate-limit ARP traffic at the switch port.
3. If the host is unauthorized, disable its switch port.
4. Enable port security to limit MACs per port.
5. Monitor for follow-up attacks using discovered hosts.`,
        evidence: `Source MAC: ${key}, ARP Requests: ${count}`,
        affectedIp: key,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect ARP storm: total ARP traffic volume exceeds threshold.
 * Indicates widespread ARP activity (scanning, worm propagation, network loop).
 */
export function detectARPStorm(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  let arpCount = 0;

  for (const pkt of packets) {
    if (pkt.protocol === Protocol.ARP) {
      arpCount++;
    }
  }

  if (arpCount >= 20) {
    findings.push({
      id: nextId(),
      title: "ARP Storm Detected — High ARP Traffic Volume",
      severity: Severity.Medium,
      description: `${arpCount} ARP packets were observed. A high volume of ARP traffic across the network may indicate active host discovery, malware propagation (worms often ARP-scan for targets), a network loop causing broadcast storms, or an ARP-based denial-of-service attack.`,
      recommendation: `1. Review the network for loops (STP misconfiguration).
2. Identify the top ARP sources and investigate them.
3. Enable broadcast storm control on switch ports.
4. Check for malware/worm activity on endpoint hosts.
5. Consider segmenting the network to limit broadcast domains.`,
      evidence: `Total ARP packets: ${arpCount}`,
      affectedIp: "network",
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
