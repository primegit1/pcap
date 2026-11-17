import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * Oracle DB — TCP 1521
 * ======================================================================== */

/**
 * Detect Oracle DB cleartext TNS authentication.
 * Oracle TNS (Transparent Network Substrate) can transmit authentication
 * credentials in cleartext when not using TLS/Oracle Net Encryption.
 * Older auth mechanisms (OS authentication, legacy SHA1) are weak.
 */
export function detectOracleDBCleartextAuth(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const oracleServers = new Map<string, { authCount: number; clients: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.OracleDB) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // Oracle auth packets: CONNECT, AUTH, login
    if (summary.includes("auth") || summary.includes("connect") || summary.includes("login")) {
      const serverIp = pkt.ip.dstIp;
      const clientIp = pkt.ip.srcIp;

      const entry = oracleServers.get(serverIp);
      if (entry) {
        entry.authCount++;
        entry.clients.add(clientIp);
      } else {
        oracleServers.set(serverIp, { authCount: 1, clients: new Set([clientIp]) });
      }
    }
  }

  for (const [server, data] of oracleServers) {
    if (data.authCount < 1) continue;

    findings.push({
      id: nextId(),
      title: "Oracle DB Cleartext Authentication Detected",
      severity: Severity.High,
      description: `Oracle database ${server} received ${data.authCount} authentication request(s) from ${data.clients.size} client(s). Without Oracle Net Encryption (ANO) or TLS, Oracle TNS transmits credentials and all SQL data in cleartext. Older Oracle authentication methods use weak hashing (SHA1 with known salt format). Default accounts (SCOTT/TIGER, DBSNMP/DBSNMP) are common in legacy deployments and provide a foothold for privilege escalation.`,
      recommendation: `1. Enable Oracle Net Encryption (Native Network Encryption) or TLS for all connections.
2. Configure SQLNET.ENCRYPTION_SERVER=REQUIRED and SQLNET.ENCRYPTION_TYPES_SERVER=AES256.
3. Disable legacy authentication: set SQLNET.ALLOWED_LOGON_VERSION_SERVER=12 or higher.
4. Remove or lock default accounts: SCOTT, DBSNMP, OUTLN, XS$NULL.
5. Use strong password policies and rotate credentials regularly.
6. Restrict TNS listener access (port 1521) to authorized client IPs.
7. Enable audit logging for all privileged connections (SYS, SYSTEM).`,
      evidence: `Server: ${server}, Auth attempts: ${data.authCount}, Clients: ${data.clients.size}`,
      affectedIp: server,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Oracle TNS listener exposure.
 * The TNS listener on port 1521 is a high-value target — it controls
 * database registration, service discovery, and can be exploited for
 * remote code execution (CVE-2012-1675, CVE-2021-35611).
 */
export function detectOracleTNSExposure(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const oracleListeners = new Map<string, { flows: number; clients: Set<string> }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.OracleDB) continue;
    if (flow.packetCount < 3) continue;

    const server = flow.dstPort === 1521 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 1521 ? flow.srcIp : flow.dstIp;

    const entry = oracleListeners.get(server);
    if (entry) {
      entry.flows++;
      entry.clients.add(client);
    } else {
      oracleListeners.set(server, { flows: 1, clients: new Set([client]) });
    }
  }

  for (const [server, data] of oracleListeners) {
    findings.push({
      id: nextId(),
      title: "Oracle TNS Listener Exposure",
      severity: Severity.Medium,
      description: `Oracle TNS listener at ${server} has ${data.flows} active connection(s) from ${data.clients.size} client(s). The TNS listener is a critical attack surface — vulnerabilities in the listener have led to remote code execution (CVE-2012-1675: TNS listener poisoning, CVE-2021-35611: privilege escalation). An exposed listener allows database service enumeration, registration of malicious services, and connection hijacking.`,
      recommendation: `1. Restrict TNS listener access to authorized client IPs only.
2. Enable TCP.VALIDNODE_CHECKING in listener.ora.
3. Set ADMIN_RESTRICTIONS_LISTENER=ON to prevent remote listener administration.
4. Apply all Oracle Critical Patch Updates (CPU).
5. Monitor listener.log for suspicious SERVICE_REGISTER attempts.
6. Consider using Oracle Connection Manager (CMAN) as a proxy to reduce direct listener exposure.`,
      evidence: `Server: ${server}, Flows: ${data.flows}, Clients: ${data.clients.size}`,
      affectedIp: server,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/* ========================================================================
 * NetBIOS — UDP 137/138, TCP 139
 * ======================================================================== */

/**
 * Detect NetBIOS name service spoofing / information disclosure.
 * NetBIOS Name Service (UDP 137) broadcasts name queries and responses
 * across the subnet, revealing hostnames, workgroup names, domain
 * controllers, and browsing information. An attacker can respond to
 * queries with spoofed names to redirect SMB/authentication traffic.
 */
export function detectNetBIOSSpoofing(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const nbnsResponders = new Map<string, { count: number; names: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.NetBIOS) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // NetBIOS Name Service responses
    if (summary.includes("response") || summary.includes("positive") || summary.includes("registered")) {
      const srcIp = pkt.ip.srcIp;
      const entry = nbnsResponders.get(srcIp);
      if (entry) {
        entry.count++;
        const nameMatch = summary.match(/name[:\s]+(\S+)/i);
        if (nameMatch) entry.names.add(nameMatch[1]);
      } else {
        const names = new Set<string>();
        const nameMatch = summary.match(/name[:\s]+(\S+)/i);
        if (nameMatch) names.add(nameMatch[1]);
        nbnsResponders.set(srcIp, { count: 1, names });
      }
    }
  }

  for (const [srcIp, data] of nbnsResponders) {
    if (data.count >= 5) {
      const names = data.names.size > 0 ? [...data.names].join(", ") : "unknown";
      findings.push({
        id: nextId(),
        title: "High Volume of NetBIOS Name Service Responses (Potential Spoofing)",
        severity: Severity.Medium,
        description: `Host ${srcIp} sent ${data.count} NetBIOS Name Service responses (names: ${names}). Excessive NBNS responses may indicate NetBIOS name spoofing, where an attacker responds to name queries before the legitimate owner, redirecting SMB traffic and capturing NTLM authentication hashes. NetBIOS is a broadcast protocol with no authentication, making spoofing trivial on the local subnet.`,
        recommendation: `1. Disable NetBIOS over TCP/IP on hosts that don't require it (most modern networks use DNS).
2. Configure NetBIOS node type to P-node (peer-to-peer) or H-node to reduce broadcast dependency.
3. Enable SMB signing to prevent NTLM relay attacks even if NBNS is spoofed.
4. Isolate legacy NetBIOS systems on a separate VLAN.
5. Monitor for NBNS responses from IPs that don't match the claimed name (spoofing indicator).
6. Use LLMNR/NBNS spoofing detection tools (Responder detection mode).`,
        evidence: `Source: ${srcIp}, Responses: ${data.count}, Names: ${names}`,
        affectedIp: srcIp,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect NetBIOS information disclosure via broadcast queries.
 * NetBIOS broadcasts reveal hostnames, domain/workgroup names, master
 * browsers, and domain controllers to every host on the subnet.
 */
export function detectNetBIOSInfoDisclosure(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const nbFlows = flows.filter(f => f.appProtocol === Protocol.NetBIOS && f.packetCount >= 3);

  if (nbFlows.length === 0) return findings;

  const subnets = new Map<string, { hosts: Set<string>; flowCount: number }>();
  for (const flow of nbFlows) {
    const subnet = flow.srcIp.split(".").slice(0, 3).join(".") + ".0/24";
    const entry = subnets.get(subnet);
    if (entry) {
      entry.hosts.add(flow.srcIp);
      entry.hosts.add(flow.dstIp);
      entry.flowCount++;
    } else {
      subnets.set(subnet, { hosts: new Set([flow.srcIp, flow.dstIp]), flowCount: 1 });
    }
  }

  for (const [subnet, data] of subnets) {
    if (data.flowCount >= 3) {
      findings.push({
        id: nextId(),
        title: "NetBIOS Broadcast Information Disclosure",
        severity: Severity.Low,
        description: `NetBIOS broadcast traffic detected on ${subnet} (${data.flowCount} flows from ${data.hosts.size} hosts). NetBIOS Name Service (UDP 137) and Datagram Service (UDP 138) broadcasts reveal hostnames, workgroup/domain names, master browsers, and logon names to all hosts on the subnet. This information aids reconnaissance by revealing the network topology and naming conventions.`,
        recommendation: `1. Disable NetBIOS over TCP/IP on modern hosts that use DNS for name resolution.
2. If NetBIOS is required for legacy applications, restrict it with firewall rules.
3. Switch to DNS-only name resolution where possible.
4. Segment legacy NetBIOS-dependent systems into isolated VLANs.
5. Disable the Computer Browser service on modern Windows hosts.`,
        evidence: `Subnet: ${subnet}, Hosts: ${data.hosts.size}, Flows: ${data.flowCount}`,
        affectedIp: subnet,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
