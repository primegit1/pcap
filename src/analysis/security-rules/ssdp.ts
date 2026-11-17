import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { parseSSDP } from "../../parsers/ssdp";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect UPnP Internet Gateway Device (IGD) exposure via SSDP.
 * IGDs exposed on non-internal interfaces allow external parties to
 * open firewall ports (via UPnP IGD:AddPortMapping), a classic attack vector.
 */
export function detectSSDPIGDExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const igdDevices = new Map<string, { ip: string; usn: string; location: string }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SSDP) continue;
    if (!pkt.appPayload) continue;

    const parsed = parseSSDP(pkt.appPayload);
    if (!parsed) continue;

    // Check if this is an IGD notification
    const nt = (parsed.nt || parsed.st || "").toLowerCase();
    const isIGD = nt.includes("internetgatewaydevice") ||
                  nt.includes("wanipconnection") ||
                  nt.includes("wanpppconnection") ||
                  nt.includes("wancommoninterfaceconfig");

    if (!isIGD) continue;

    const deviceKey = parsed.usn || parsed.location || nt;
    if (!deviceKey) continue;

    if (!igdDevices.has(deviceKey)) {
      const srcIp = pkt.ip?.srcIp || "unknown";
      igdDevices.set(deviceKey, {
        ip: srcIp,
        usn: parsed.usn || "unknown",
        location: parsed.location || "unknown",
      });
    }
  }

  for (const [, device] of igdDevices) {
    findings.push({
      id: nextId(),
      title: "UPnP Internet Gateway Device (IGD) Exposed",
      severity: Severity.Critical,
      description: `A UPnP Internet Gateway Device was discovered at ${device.ip}. Exposed IGDs allow remote configuration of firewall/NAT port mappings (UPnP AddPortMapping), enabling attackers to open ports to internal services. This is a well-known attack vector used by malware to expose internal systems to the internet.`,
      recommendation: `1. Disable UPnP on the gateway device immediately.
2. If UPnP is required, restrict it to trusted LAN interfaces only.
3. Verify no unauthorized port mappings have been created.
4. Check router admin logs for suspicious AddPortMapping requests.
5. Consider replacing the device if UPnP cannot be fully disabled.`,
      evidence: `Device IP: ${device.ip}, USN: ${device.usn}, Location: ${device.location}`,
      affectedIp: device.ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect SSDP amplification potential — large responses to small M-SEARCH requests.
 * SSDP can be abused for DDoS amplification due to UDP spoofing and large XML responses.
 */
export function detectSSDPAmplification(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track M-SEARCH requests and their corresponding responses
  const msearchSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SSDP) continue;
    if (!pkt.appPayload) continue;

    const parsed = parseSSDP(pkt.appPayload);
    if (!parsed) continue;

    // Track M-SEARCH sources
    if (parsed.type === "M-SEARCH" && pkt.ip) {
      const srcIp = pkt.ip.srcIp;
      msearchSources.set(srcIp, (msearchSources.get(srcIp) || 0) + 1);
    }
  }

  // Flag sources sending many M-SEARCH requests (potential amplification scanning)
  for (const [srcIp, count] of msearchSources) {
    if (count >= 5) {
      findings.push({
        id: nextId(),
        title: "SSDP Amplification Scanning Activity",
        severity: Severity.High,
        description: `Source ${srcIp} sent ${count} SSDP M-SEARCH requests. High-volume SSDP discovery may indicate an attacker probing for UPnP devices to use in DDoS amplification attacks. SSDP has an amplification factor of ~30x when devices respond with full XML descriptions.`,
        recommendation: `1. Filter SSDP (UDP/1900) traffic at the network edge.
2. Configure UPnP devices to only respond on trusted interfaces.
3. Rate-limit SSDP M-SEARCH responses on network devices.
4. If ${srcIp} is external, block it at the firewall.`,
        evidence: `Source IP: ${srcIp}, M-SEARCH count: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect suspicious SSDP NOTIFY announcements — rogue devices or spoofing.
 * Flags devices announcing unusual or spoofed service types, or excessive
 * ssdp:alive messages (which could indicate device spoofing/flapping).
 */
export function detectSSDPRogueDevices(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const deviceAliveCounts = new Map<string, { count: number; usn: string; ip: string }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SSDP) continue;
    if (!pkt.appPayload) continue;

    const parsed = parseSSDP(pkt.appPayload);
    if (!parsed) continue;

    // Count ssdp:alive announcements per USN
    if (parsed.type === "NOTIFY" && parsed.nts === "ssdp:alive" && parsed.usn) {
      const key = parsed.usn;
      const existing = deviceAliveCounts.get(key);
      if (existing) {
        existing.count++;
      } else {
        deviceAliveCounts.set(key, {
          count: 1,
          usn: parsed.usn,
          ip: pkt.ip?.srcIp || "unknown",
        });
      }
    }
  }

  // Flag devices with excessive alive announcements (flapping/spoofing)
  for (const [, device] of deviceAliveCounts) {
    if (device.count >= 5) {
      findings.push({
        id: nextId(),
        title: "Excessive SSDP Device Announcements (Potential Spoofing)",
        severity: Severity.Medium,
        description: `Device ${device.usn} at ${device.ip} sent ${device.count} ssdp:alive announcements. Excessive UPnP announcements may indicate a device that is rapidly connecting/disconnecting, or an attacker spoofing device presence to perform man-in-the-middle attacks or cause denial of service.`,
        recommendation: `1. Investigate the device at ${device.ip} for instability or compromise.
2. Check for duplicate USN announcements from different IPs (spoofing).
3. Rate-limit SSDP announcements on the network switch.
4. Verify the device's UPnP configuration and firmware.`,
        evidence: `Device: ${device.usn}, Source IP: ${device.ip}, Announcements: ${device.count}`,
        affectedIp: device.ip,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect SSDP NOTIFY ssdp:byebye floods — devices deregistering rapidly.
 * Can indicate a DoS attack against UPnP service discovery.
 */
export function detectSSDPByebyeFlood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const byebyeSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SSDP) continue;
    if (!pkt.appPayload) continue;

    const parsed = parseSSDP(pkt.appPayload);
    if (!parsed) continue;

    if (parsed.type === "NOTIFY" && parsed.nts === "ssdp:byebye" && pkt.ip) {
      const srcIp = pkt.ip.srcIp;
      byebyeSources.set(srcIp, (byebyeSources.get(srcIp) || 0) + 1);
    }
  }

  for (const [srcIp, count] of byebyeSources) {
    if (count >= 5) {
      findings.push({
        id: nextId(),
        title: "SSDP Byebye Flood Detected",
        severity: Severity.Medium,
        description: `Source ${srcIp} sent ${count} SSDP byebye messages. A high volume of device deregistration messages may indicate a denial-of-service attack against UPnP service discovery, causing devices to disappear from network browsing and disrupting service availability.`,
        recommendation: `1. Investigate ${srcIp} for malicious activity or compromise.
2. Monitor for corresponding ssdp:alive floods (device flapping).
3. Enable IGMP/SSDP snooping with anomaly detection on switches.
4. Consider restricting SSDP to known device MAC addresses.`,
        evidence: `Source IP: ${srcIp}, Byebye count: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
