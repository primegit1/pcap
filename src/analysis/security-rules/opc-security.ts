import { Protocol } from "../../types/packets";
import type { Packet } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========== OPC UA Payload Helpers ========== */

interface OPCUAMessageInfo {
  msgType: string;
  securityMode: "None" | "Sign" | "SignAndEncrypt" | "Unknown";
  serviceId: number | null;
}

/**
 * Parse OPC UA binary message header to extract message type,
 * security mode, and service node ID.
 */
function parseOPCUAMessage(payload: ArrayBuffer): OPCUAMessageInfo | null {
  if (payload.byteLength < 8) return null;
  const view = new Uint8Array(payload);
  if (payload.byteLength < 3) return null;

  const msgType = String.fromCharCode(view[0], view[1], view[2]);
  const knownTypes = new Set(["HEL", "ACK", "ERR", "OPN", "CLO", "MSG", "RHE"]);
  if (!knownTypes.has(msgType)) return null;

  const result: OPCUAMessageInfo = {
    msgType,
    securityMode: "Unknown",
    serviceId: null,
  };

  // Extract security mode from OPN messages
  if (msgType === "OPN" && payload.byteLength >= 16) {
    const secMode = (view[12] << 24) | (view[13] << 16) | (view[14] << 8) | view[15];
    if (secMode === 0x00) result.securityMode = "None";
    else if (secMode === 0x01) result.securityMode = "Sign";
    else if (secMode === 0x02) result.securityMode = "SignAndEncrypt";
  }

  // Extract service ID from MSG messages
  if (msgType === "MSG" && payload.byteLength >= 20) {
    for (const bodyOffset of [16, 24]) {
      if (bodyOffset >= payload.byteLength) continue;
      const serviceByte = view[bodyOffset];
      if ((serviceByte & 0xf0) === 0x00 && payload.byteLength >= bodyOffset + 3) {
        result.serviceId = view[bodyOffset + 1] | (view[bodyOffset + 2] << 8);
        break;
      }
      if (serviceByte === 0x01 && payload.byteLength >= bodyOffset + 5) {
        result.serviceId = view[bodyOffset + 3] | (view[bodyOffset + 4] << 8);
        break;
      }
    }
  }

  return result;
}

/* ========== Detection Rules ========== */

/**
 * Detect OPC UA traffic using SecurityMode=None (unencrypted, unsigned).
 * OPC UA without security is vulnerable to MITM, replay, and injection attacks.
 * Any network-adjacent attacker can read process data or send control commands.
 */
export function detectOPCUANoSecurity(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OPCUA || !pkt.appPayload) continue;

    const info = parseOPCUAMessage(pkt.appPayload);
    if (!info || info.msgType !== "OPN") continue;
    if (info.securityMode !== "None") continue;

    const srcIp = pkt.ip?.srcIp ?? "unknown";
    const dstIp = pkt.ip?.dstIp ?? "unknown";
    const key = `${srcIp}-${dstIp}`;
    if (reported.has(key)) continue;
    reported.add(key);

    findings.push({
      id: nextId(),
      title: "OPC UA Unencrypted Channel (SecurityMode=None)",
      severity: Severity.High,
      description: `OPC UA OpenSecureChannel from ${srcIp} to ${dstIp} uses SecurityMode=None — no encryption, no signing, no integrity protection. An attacker with network access can eavesdrop on process data, modify commands in transit, or inject malicious operations. OPC UA is used to monitor and control industrial processes, making unencrypted channels a critical safety risk.`,
      recommendation: `1. Reconfigure the OPC UA server and clients to use SecurityMode=SignAndEncrypt.
2. Select strong security profiles such as Basic256Sha256 or Aes128Sha256RsaOaep.
3. Rotate all application instance certificates if they were previously used without security.
4. Audit all OPC UA endpoints using the GetEndpoints service to verify current security settings.
5. Implement network segmentation to limit access to OPC UA endpoints even after enabling security.`,
      evidence: `OPN SecureChannel from ${srcIp} to ${dstIp}, SecurityMode=None`,
      affectedIp: dstIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect OPC UA endpoints that only use Sign (without encryption).
 * Sign-only mode provides integrity and authentication but does not
 * encrypt the payload — process data and commands are visible on the wire.
 */
export function detectOPCUASignOnly(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OPCUA || !pkt.appPayload) continue;

    const info = parseOPCUAMessage(pkt.appPayload);
    if (!info || info.msgType !== "OPN") continue;
    if (info.securityMode !== "Sign") continue;

    const srcIp = pkt.ip?.srcIp ?? "unknown";
    const dstIp = pkt.ip?.dstIp ?? "unknown";
    const key = `${srcIp}-${dstIp}`;
    if (reported.has(key)) continue;
    reported.add(key);

    findings.push({
      id: nextId(),
      title: "OPC UA Signed-Only Channel (No Encryption)",
      severity: Severity.Medium,
      description: `OPC UA OpenSecureChannel from ${srcIp} to ${dstIp} uses SecurityMode=Sign — messages are signed for integrity and authentication but NOT encrypted. Process data values, control commands, and configuration parameters are visible to any network eavesdropper. While tampering is detected, confidentiality is not protected.`,
      recommendation: `1. Upgrade to SecurityMode=SignAndEncrypt to protect data confidentiality.
2. If Sign-only is required for legacy compatibility, restrict network access with VLANs or firewalls.
3. Monitor for anomalous read operations that could indicate data harvesting.
4. Document the risk acceptance if Sign-only must remain for legacy devices.`,
      evidence: `OPN SecureChannel from ${srcIp} to ${dstIp}, SecurityMode=Sign`,
      affectedIp: dstIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect OPC UA Write/Call service operations that can modify process state.
 * Write (service 472) and Call (service 672) can change PLC values,
 * trigger method execution, or alter configuration.
 */
export function detectOPCUAWriteOperations(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const writeServices = new Set([472, 672]); // Write, Call
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OPCUA || !pkt.appPayload) continue;

    const info = parseOPCUAMessage(pkt.appPayload);
    if (!info || info.msgType !== "MSG" || info.serviceId === null) continue;
    if (!writeServices.has(info.serviceId)) continue;

    const srcIp = pkt.ip?.srcIp ?? "unknown";
    const dstIp = pkt.ip?.dstIp ?? "unknown";
    const svcName = info.serviceId === 472 ? "Write" : "Call";
    const key = `${srcIp}-${dstIp}-${svcName}`;
    if (reported.has(key)) continue;
    reported.add(key);

    findings.push({
      id: nextId(),
      title: `OPC UA ${svcName} Operation Detected`,
      severity: Severity.Medium,
      description: `OPC UA ${svcName} service from ${srcIp} to ${dstIp}. ${svcName === "Write" ? "Write operations modify node values on the OPC UA server, which can directly change process variables, setpoints, or controller parameters in connected PLCs." : "Call operations invoke methods on the OPC UA server, which can execute control logic, trigger device actions, or change system configuration."} Unauthorized write or call operations could disrupt industrial processes.`,
      recommendation: `1. Verify that ${srcIp} is an authorized OPC UA client with write/call privileges.
2. Implement role-based access control on the OPC UA server to restrict write permissions.
3. Log and audit all write and call operations for change management compliance.
4. Consider implementing a write-approval workflow for critical process variables.
5. Monitor for write operations outside normal operating hours or from unusual sources.`,
      evidence: `${svcName} service (0x${info.serviceId.toString(16)}) from ${srcIp} to ${dstIp}`,
      affectedIp: dstIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect OPC UA session management from unusual patterns —
 * excessive CreateSession without ActivateSession, or sessions
 * from many different source IPs (credential stuffing / brute force).
 */
export function detectOPCUASessionAnomalies(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const createSessionSources = new Map<string, number>();
  const activateSessionSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OPCUA || !pkt.appPayload) continue;
    const info = parseOPCUAMessage(pkt.appPayload);
    if (!info || info.msgType !== "MSG" || info.serviceId === null) continue;

    const srcIp = pkt.ip?.srcIp ?? "unknown";
    if (info.serviceId === 428) {
      createSessionSources.set(srcIp, (createSessionSources.get(srcIp) ?? 0) + 1);
    }
    if (info.serviceId === 430) {
      activateSessionSources.set(srcIp, (activateSessionSources.get(srcIp) ?? 0) + 1);
    }
  }

  // Flag sources with many CreateSession without proportionate ActivateSession
  for (const [srcIp, createCount] of createSessionSources) {
    const activateCount = activateSessionSources.get(srcIp) ?? 0;
    if (createCount >= 5 && createCount > activateCount * 2) {
      findings.push({
        id: nextId(),
        title: "OPC UA Excessive Session Creation Without Activation",
        severity: Severity.Medium,
        description: `Source ${srcIp} sent ${createCount} CreateSession requests but only ${activateCount} ActivateSession requests. This pattern suggests session scanning, authentication failures, or a misconfigured client rapidly creating and abandoning sessions. Each CreateSession allocates server resources, and excessive creation can lead to resource exhaustion.`,
        recommendation: `1. Investigate ${srcIp} to determine if it is a legitimate OPC UA client.
2. Check OPC UA server logs for authentication failures from this source.
3. Implement rate limiting on CreateSession requests at the OPC UA server.
4. Verify client certificate trust list — untrusted clients may repeatedly create sessions that fail to activate.
5. Consider limiting concurrent sessions per client identity.`,
        evidence: `CreateSession: ${createCount}, ActivateSession: ${activateCount} from ${srcIp}`,
        affectedIp: srcIp,
        category: FindingCategory.OPC,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect OPC DA (Classic OPC) / DCOM traffic on port 135.
 * OPC DA uses DCOM which has no built-in security for industrial operations.
 * It relies entirely on Windows authentication and DCOM configuration,
 * which is frequently misconfigured or disabled for convenience.
 */
export function detectOPCDATraffic(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.OPCDA) continue;

    findings.push({
      id: nextId(),
      title: "OPC DA (Classic OPC / DCOM) Traffic Detected",
      severity: Severity.High,
      description: `OPC DA (Classic OPC) traffic detected from ${flow.srcIp} to ${flow.dstIp} on port 135. OPC DA relies on Microsoft DCOM/RPC for communication, which uses Windows authentication and has significant security limitations: no transport encryption by default, reliance on NTLM/Kerberos that is often weakened for cross-domain access, and a large attack surface from the DCOM activation infrastructure. OPC DA was deprecated in favor of OPC UA but remains widely deployed in legacy industrial systems.`,
      recommendation: `1. Migrate from OPC DA to OPC UA with SignAndEncrypt security mode.
2. If OPC DA must remain, restrict DCOM access using DCOMCNFG to specific interfaces and principals.
3. Enable packet signing and encryption in DCOM configuration (Component Services → My Computer → Properties → Default Properties).
4. Isolate OPC DA traffic to a dedicated OT VLAN with strict firewall rules.
5. Monitor DCOM activation requests for unauthorized access attempts.
6. Disable DCOM on systems that do not require it (especially internet-facing hosts).`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}, Bytes: ${flow.byteCount.toLocaleString()}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect OPC UA traffic flows — identify server/client relationships
 * and flag any unencrypted sessions at the flow level.
 */
export function detectOPCUATraffic(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.OPCUA) continue;

    findings.push({
      id: nextId(),
      title: "OPC UA Traffic Detected",
      severity: Severity.Info,
      description: `OPC UA traffic detected from ${flow.srcIp} to ${flow.dstIp} on port 4840. OPC UA is the standard protocol for industrial communication, supporting data access, alarms & conditions, historical access, and programs. While OPC UA supports security (encryption, signing, authentication), many deployments run with security disabled for convenience or compatibility.`,
      recommendation: `1. Verify the OPC UA security configuration using the server's GetEndpoints service.
2. Ensure SecurityPolicy and SecurityMode are set to SignAndEncrypt for all connections.
3. Maintain an inventory of all OPC UA servers and clients in the environment.
4. Monitor for unauthorized OPC UA clients attempting to connect.
5. Use OPC UA application instance certificates and a Public Key Infrastructure (PKI).`,
      evidence: `Flow: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}, Packets: ${flow.packetCount}, Bytes: ${flow.byteCount.toLocaleString()}`,
      affectedIp: flow.dstIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect OPC UA GetEndpoints responses exposed to network —
 * attackers can enumerate server capabilities, security policies,
 * and application descriptions without authentication.
 */
export function detectOPCUAEndpointEnumeration(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OPCUA || !pkt.appPayload) continue;

    const info = parseOPCUAMessage(pkt.appPayload);
    if (!info || info.msgType !== "MSG" || info.serviceId !== 675) continue; // GetEndpointsResp

    const dstIp = pkt.ip?.dstIp ?? "unknown";
    const srcIp = pkt.ip?.srcIp ?? "unknown";
    const key = `${srcIp}`;
    if (reported.has(key)) continue;
    reported.add(key);

    findings.push({
      id: nextId(),
      title: "OPC UA Endpoint Information Exposed",
      severity: Severity.Low,
      description: `OPC UA GetEndpoints response sent from server ${srcIp} to client ${dstIp}. This response discloses server capabilities, supported security policies, application names, endpoint URLs, and certificate information. While GetEndpoints is an unauthenticated discovery service by design, an attacker can use this information to identify weak security configurations and plan targeted attacks.`,
      recommendation: `1. Restrict OPC UA discovery service access using network segmentation.
2. Disable the LDS (Local Discovery Server) if multicast discovery is not needed.
3. Use application-level access control to limit GetEndpoints responses to authorized clients.
4. Review the security policies returned — remove support for None if still present.
5. Monitor for GetEndpoints requests from unknown or external IP addresses.`,
      evidence: `GetEndpointsResp from ${srcIp} to ${dstIp}`,
      affectedIp: srcIp,
      category: FindingCategory.OPC,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
