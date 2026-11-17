import { Protocol } from "../../types/packets";
import type { SecurityFinding, FlowRecord } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * OT/ICS protocol detection rules.
 * These identify industrial control system traffic and flag potentially
 * dangerous operations (e.g., writes to PLCs).
 */

/**
 * Detect PLC communication — Modbus, S7Comm, and other OT protocols.
 */
export function detectPLCCommunication(
  flows: FlowRecord[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const otProtocols = new Set<Protocol>([
    Protocol.Modbus,
    Protocol.S7Comm,
    Protocol.DNP3,
    Protocol.BACnet,
    Protocol.Profinet,
    Protocol.OPCDA,
    Protocol.OPCUA,
  ]);

  for (const flow of flows) {
    if (!otProtocols.has(flow.appProtocol)) continue;

    findings.push({
      id: nextId(),
      title: `${flow.appProtocol} Communication Detected`,
      severity: Severity.Info,
      description: `${flow.appProtocol} traffic detected between ${flow.srcIp} and ${flow.dstIp}. ${flow.appProtocol} is a critical operational technology (OT) protocol used in industrial control systems. OT protocols generally lack authentication, encryption, and integrity checks, making them vulnerable to tampering and injection attacks.`,
      recommendation: `1. Ensure ${flow.appProtocol} traffic is restricted to the OT network segment only.
2. Use OT-specific firewalls or unidirectional gateways to isolate OT from IT networks.
3. Monitor OT traffic for anomalous commands (writes, configuration changes).
4. Maintain an inventory of all OT devices communicating via ${flow.appProtocol}.
5. Implement network segmentation following the Purdue model for ICS security.`,
      evidence: `Source: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, packets: ${flow.packetCount}, bytes: ${flow.byteCount.toLocaleString()}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Modbus write commands — these can modify PLC operation.
 * Function codes 5 (Write Single Coil), 6 (Write Single Register),
 * 15 (Write Multiple Coils), 16 (Write Multiple Registers).
 *
 * For MVP: We detect Modbus TCP flows (port 502) and flag them.
 * Full function code inspection requires deep packet inspection.
 */
export function detectModbusWrites(
  flows: FlowRecord[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.Modbus) continue;

    // Flag Modbus traffic as potentially dangerous since it controls industrial equipment
    findings.push({
      id: nextId(),
      title: "Modbus TCP Traffic — Industrial Control Protocol",
      severity: Severity.Medium,
      description: `Modbus TCP traffic detected from ${flow.srcIp} to ${flow.dstIp} on port 502. Modbus is a widely-used industrial control protocol that lacks authentication, encryption, or integrity checks. An attacker with network access can send commands to read or write registers, potentially disrupting industrial processes.`,
      recommendation: `1. Isolate Modbus traffic to the OT network using VLANs or physical separation.
2. Deploy an OT firewall or industrial demilitarized zone (IDMZ) between IT and OT.
3. Monitor for Modbus function codes 5, 6, 15, 16 (write operations) — these modify PLC states.
4. Consider using Modbus/TCP Security (MBTS) or a VPN tunnel for remote access.
5. Implement an OT SIEM or industrial IDS (e.g., Nozomi, Claroty) to monitor protocol anomalies.`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect S7 write operations (Siemens S7 protocol).
 * S7Comm on port 102 is used by Siemens PLCs.
 */
export function detectS7Writes(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.S7Comm) continue;

    findings.push({
      id: nextId(),
      title: "S7 Protocol Traffic — Siemens PLC Communication",
      severity: Severity.Medium,
      description: `S7 (Siemens) protocol traffic detected from ${flow.srcIp} to ${flow.dstIp} on port 102. The S7 protocol is used to communicate with Siemens SIMATIC PLCs and can perform read/write operations on PLC memory, start/stop PLCs, and upload/download programs. Unauthorized access could cause significant operational disruption.`,
      recommendation: `1. Restrict S7 communication to known engineering workstations only.
2. Isolate Siemens PLCs on dedicated OT network segments.
3. Use Siemens Security Configuration Assistant to harden PLC communication.
4. Monitor for S7 function codes that perform writes or PLC control (e.g., STOP, START).
5. Keep PLC firmware updated and disable unnecessary S7 functions.`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect industrial network scanning — probing multiple OT ports
 * from the same source.
 */
export function detectOTScanning(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const otPorts = new Set([502, 102, 20000, 44818, 135, 4840, 2404, 47808, 34962, 34964]);
  const srcOtMap = new Map<string, Set<number>>();

  for (const flow of flows) {
    if (otPorts.has(flow.dstPort)) {
      const existing = srcOtMap.get(flow.srcIp);
      if (existing) {
        existing.add(flow.dstPort);
      } else {
        srcOtMap.set(flow.srcIp, new Set([flow.dstPort]));
      }
    }
  }

  for (const [srcIp, ports] of srcOtMap) {
    if (ports.size >= 3) {
      findings.push({
        id: nextId(),
        title: "OT/ICS Network Scanning Detected",
        severity: Severity.High,
        description: `Source ${srcIp} probed ${ports.size} different OT/ICS protocol ports. Scanning OT-specific ports (e.g., Modbus 502, S7 102, BACnet 47808) is a strong indicator of industrial control system reconnaissance. This could be a prelude to targeted attacks on critical infrastructure.`,
        recommendation: `1. Immediately investigate ${srcIp} — this is not typical endpoint behavior.
2. Block ${srcIp} at OT network boundaries if external.
3. Review OT firewall logs for additional probing activity.
4. Verify that OT network segments are properly isolated from IT and guests.
5. Conduct a threat hunt for other indicators of OT-specific intrusion activity.`,
        evidence: `Probed ports: ${Array.from(ports).join(", ")}`,
        affectedIp: srcIp,
        category: FindingCategory.OTICS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect BACnet traffic — used in building automation (HVAC, lighting, access control).
 * BACnet/IP uses UDP port 47808 (0xBAC0).
 */
export function detectBACnetTraffic(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.BACnet) continue;

    findings.push({
      id: nextId(),
      title: "BACnet Building Automation Traffic Detected",
      severity: Severity.Medium,
      description: `BACnet (building automation) traffic detected from ${flow.srcIp} to ${flow.dstIp} on port 47808. BACnet controls HVAC, lighting, fire alarms, and access control systems. Unauthorized BACnet commands could modify building environmental controls or disable safety systems.`,
      recommendation: `1. Verify the BACnet devices are authorized and inventoried.
2. Restrict BACnet traffic to building management system (BMS) network segments.
3. Monitor for BACnet service choices that write values (WriteProperty, DeviceCommunicationControl).
4. Use BACnet/SC (Secure Connect) with TLS encryption where supported.
5. Implement network access control (NAC) for BMS devices.`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Profinet traffic — used in industrial automation (Siemens).
 * Profinet IO uses UDP ports 34962 (RT), 34963 (RT), 34964 (DCP/RPC).
 */
export function detectProfinetTraffic(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.Profinet) continue;

    findings.push({
      id: nextId(),
      title: "Profinet Industrial Automation Traffic Detected",
      severity: Severity.Medium,
      description: `Profinet (industrial automation) traffic detected from ${flow.srcIp} to ${flow.dstIp}. Profinet is used for real-time I/O communication with Siemens PLCs, drives, and field devices. It typically uses UDP ports 34962–34964 and carries time-critical process data and configuration commands.`,
      recommendation: `1. Ensure Profinet traffic is confined to the automation network segment.
2. Use Profinet Security Class 2 or 3 features for device authentication.
3. Monitor for unexpected configuration changes via Profinet DCE/RPC.
4. Isolate Profinet real-time channels from non-real-time IT traffic.
5. Use OT-specific monitoring tools to detect anomalous Profinet FrameIDs.`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Generic "OT over the internet" detection — flags when OT/ICS protocols
 * communicate with public (non-private, non-loopback) IP addresses,
 * suggesting operational technology exposed to the open internet.
 */
export function detectOTOverInternet(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const otProtocols = new Set<Protocol>([
    Protocol.Modbus,
    Protocol.S7Comm,
    Protocol.DNP3,
    Protocol.EtherNetIP,
    Protocol.OPCDA,
    Protocol.OPCUA,
    Protocol.IEC104,
    Protocol.BACnet,
    Protocol.Profinet,
  ]);

  function isPublicIp(ip: string): boolean {
    if (ip === "127.0.0.1" || ip === "::1") return false;
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4) return false;
    // Private ranges
    if (parts[0] === 10) return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
    if (parts[0] === 192 && parts[1] === 168) return false;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false; // CGNAT
    return true;
  }

  for (const flow of flows) {
    if (!otProtocols.has(flow.appProtocol)) continue;
    const srcPublic = isPublicIp(flow.srcIp);
    const dstPublic = isPublicIp(flow.dstIp);
    if (!srcPublic && !dstPublic) continue;

    const exposure = srcPublic ? `Source ${flow.srcIp} is public` : `Destination ${flow.dstIp} is public`;
    findings.push({
      id: nextId(),
      title: `${flow.appProtocol} Exposed to the Internet`,
      severity: Severity.High,
      description: `${flow.appProtocol} traffic detected between ${flow.srcIp} and ${flow.dstIp} where one endpoint is a public IP address. OT/ICS protocols were not designed for internet connectivity and lack essential security features like encryption, authentication, or integrity verification. Exposing industrial protocols to the internet creates significant risk of remote compromise.`,
      recommendation: `1. Immediately remove direct internet access for the OT device.
2. Use a VPN or secure jump host for all remote OT access.
3. Deploy an OT firewall or industrial DMZ to mediate all external connections.
4. Review Shodan/Censys for internet-exposed OT devices on your IP ranges.
5. Implement the Purdue enterprise reference architecture for ICS network segmentation.`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}. ${exposure}. Packets: ${flow.packetCount}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OTICS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
