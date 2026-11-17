import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * LLMNR (Link-Local Multicast Name Resolution) — UDP port 5355
 * ======================================================================== */

/**
 * Detect LLMNR poisoning / spoofing conditions.
 * LLMNR is a fallback name resolution protocol that is trivially exploited:
 * any host on the same subnet can respond to an LLMNR query before the
 * legitimate owner, capturing the NTLM hash of the requester.
 *
 * Indicators:
 * - LLMNR responses from IPs that never sent queries (potential poisoners)
 * - High volume of LLMNR queries (names not resolving via DNS = misconfiguration)
 * - Responses to .local or WPAD queries (classic attack targets)
 */
export function detectLLMNRPoisoning(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const querySenders = new Set<string>();
  const responders = new Map<string, { ip: string; count: number; names: Set<string> }>();
  const queryNames = new Map<string, { count: number; srcs: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.LLMNR) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const summary = pkt.appPayloadSummary?.toLowerCase() || pkt.info?.toLowerCase() || "";

    // LLMNR queries are sent to multicast 224.0.0.252; responses are unicast back
    const isResponse = summary.includes("response") || pkt.ip.dstIp !== "224.0.0.252";

    if (isResponse) {
      const existing = responders.get(srcIp);
      if (existing) {
        existing.count++;
      } else {
        responders.set(srcIp, { ip: srcIp, count: 1, names: new Set() });
      }
    } else {
      querySenders.add(srcIp);
      // Extract queried name from summary (e.g. "Standard query A wpad.local")
      const nameMatch = summary.match(/query\s+(?:\S+\s+)?([a-z0-9][\w.-]+)/);
      if (nameMatch) {
        const name = nameMatch[1];
        const entry = queryNames.get(name);
        if (entry) {
          entry.count++;
          entry.srcs.add(srcIp);
        } else {
          queryNames.set(name, { count: 1, srcs: new Set([srcIp]) });
        }
      }
    }
  }

  // Flag responders that never sent queries — potential poisoners
  for (const [, responder] of responders) {
    if (!querySenders.has(responder.ip) && responder.count >= 2) {
      findings.push({
        id: nextId(),
        title: "LLMNR Responder Without Prior Queries (Potential Poisoning)",
        severity: Severity.High,
        description: `Host ${responder.ip} is responding to LLMNR queries but never sends LLMNR queries itself. This is a strong indicator of LLMNR poisoning, where an attacker responds to name resolution queries to capture authentication hashes (NTLM/Kerberos). LLMNR poisoning is one of the most common lateral movement techniques in enterprise networks.`,
        recommendation: `1. Disable LLMNR via Group Policy: Computer Config > Admin Templates > Network > DNS Client > Turn off Multicast Name Resolution.
2. Investigate ${responder.ip} — determine if it is a legitimate server or an attacker.
3. If usingResponder/Inveigh tools are found on ${responder.ip}, it is actively poisoning.
4. Ensure DNS properly resolves all internal names so LLMNR fallback is never needed.
5. Enable LLMNR auditing via Event ID 6004 (LLMNR query failures).`,
        evidence: `Responder: ${responder.ip}, Responses: ${responder.count}, Never sent queries`,
        affectedIp: responder.ip,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  // Flag WPAD or .local name queries — classic attack targets
  for (const [name, data] of queryNames) {
    if ((name.includes("wpad") || name.endsWith(".local")) && data.count >= 3) {
      findings.push({
        id: nextId(),
        title: `LLMNR Queries for High-Risk Name: ${name}`,
        severity: Severity.Medium,
        description: `${data.count} LLMNR queries for "${name}" detected from ${data.srcs.size} host(s). WPAD and .local names are prime targets for LLMNR poisoning attacks. WPAD poisoning allows an attacker to configure a malicious proxy, while .local queries indicate DNS misconfiguration forcing LLMNR fallback.`,
        recommendation: `1. Create a DNS A record for "${name}" to prevent LLMNR fallback.
2. For WPAD: ensure a valid WPAD DNS entry exists and disable WPAD if not used.
3. Disable LLMNR via Group Policy across all hosts.
4. Check proxy settings on affected clients for unauthorized proxy configuration.`,
        evidence: `Queried name: ${name}, Queries: ${data.count}, Sources: ${[...data.srcs].join(", ")}`,
        affectedIp: [...data.srcs][0] || "unknown",
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ========================================================================
 * TFTP (Trivial File Transfer Protocol) — UDP port 69
 * ======================================================================== */

/**
 * Detect TFTP traffic — it transmits files with no authentication or encryption.
 * TFTP is commonly used for firmware updates, PBX configs, and PXE boot.
 * Any sensitive file transferred via TFTP is fully exposed on the network.
 */
export function detectTFTPCleartext(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const tftpFlows = flows.filter(
    (f) => f.appProtocol === Protocol.TFTP && f.packetCount >= 2
  );

  if (tftpFlows.length === 0) return findings;

  const tftpEndpoints = new Map<string, { count: number; peers: Set<string> }>();
  for (const flow of tftpFlows) {
    // Server side (port 69 or responding)
    const server = flow.dstPort === 69 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 69 ? flow.srcIp : flow.dstIp;
    const entry = tftpEndpoints.get(server);
    if (entry) {
      entry.count++;
      entry.peers.add(client);
    } else {
      tftpEndpoints.set(server, { count: 1, peers: new Set([client]) });
    }
  }

  for (const [server, data] of tftpEndpoints) {
    findings.push({
      id: nextId(),
      title: "TFTP Cleartext File Transfer Detected",
      severity: Severity.High,
      description: `TFTP traffic detected involving server ${server} with ${data.count} transfer(s) from ${data.peers.size} client(s). TFTP provides no authentication, no encryption, and no integrity checking. Any data transferred — firmware images, configuration files, boot images — is fully exposed to anyone on the network path. TFTP is a common target in ICS/SCADA and VoIP environments.`,
      recommendation: `1. Replace TFTP with SFTP, SCP, or HTTPS where possible.
2. If TFTP is required (PXE boot, ICS firmware), isolate it to a dedicated VLAN.
3. Never transfer credentials, certificates, or sensitive configs via TFTP.
4. Monitor TFTP servers for unauthorized file access or exfiltration.
5. For VoIP: use encrypted provisioning (HTTPS/TFTP over IPsec).`,
      evidence: `TFTP server: ${server}, Transfers: ${data.count}, Clients: ${data.peers.size}`,
      affectedIp: server,
      category: FindingCategory.FileShare,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/* ========================================================================
 * RADIUS (Remote Authentication Dial-In User Service) — UDP 1812/1813
 * ======================================================================== */

/**
 * Detect RADIUS traffic with potential weak shared secrets.
 * RADIUS authenticates using a shared secret (MD5-based for RADIUS/EAP),
 * which is vulnerable to offline brute-force. Many deployments use weak
 * or default secrets. We flag any RADIUS traffic as a review point.
 */
export function detectRADIUSWeakSecret(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const radiusServers = new Map<string, { authCount: number; acctCount: number; clients: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.RADIUS) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const dstIp = pkt.ip.dstIp;
    const dstPort = "dstPort" in (pkt.transport || {}) ? (pkt.transport as { dstPort: number }).dstPort : 0;

    // Authentication (1812) vs Accounting (1813)
    const isAuth = dstPort === 1812 || (pkt.transport as { srcPort: number })?.srcPort === 1812;

    const serverIp = isAuth || dstPort === 1813 ? dstIp : srcIp;
    const clientIp = isAuth || dstPort === 1813 ? srcIp : dstIp;

    const entry = radiusServers.get(serverIp);
    if (entry) {
      if (isAuth) entry.authCount++;
      else entry.acctCount++;
      entry.clients.add(clientIp);
    } else {
      radiusServers.set(serverIp, {
        authCount: isAuth ? 1 : 0,
        acctCount: isAuth ? 0 : 1,
        clients: new Set([clientIp]),
      });
    }
  }

  for (const [server, data] of radiusServers) {
    if (data.authCount < 2 && data.acctCount < 2) continue;

    findings.push({
      id: nextId(),
      title: "RADIUS Authentication Traffic Detected (Review Shared Secret Strength)",
      severity: Severity.Medium,
      description: `RADIUS server ${server} processed ${data.authCount} authentication and ${data.acctCount} accounting packets from ${data.clients.size} client(s). RADIUS uses a shared secret for message integrity (MD5-HMAC) and PAP/CHAP password obfuscation. Weak shared secrets can be brute-forced offline from captured RADIUS packets, allowing an attacker to authenticate as any user or inject forged accounting records. RADIUS over the internet without RadSec (TLS) is especially dangerous.`,
      recommendation: `1. Ensure RADIUS shared secrets are at least 16 characters of high entropy.
2. Use unique shared secrets per RADIUS client — never reuse across NAS devices.
3. Upgrade to RadSec (RADIUS over TLS, RFC 6614) to protect the shared secret exchange.
4. Use EAP-TLS or EAP-TTLS instead of PAP/CHAP for stronger authentication.
5. If RADIUS traffic crosses untrusted networks, tunnel via IPsec or WireGuard.
6. Audit RADIUS shared secrets against common/default wordlists.`,
      evidence: `RADIUS server: ${server}, Auth packets: ${data.authCount}, Acct packets: ${data.acctCount}, Clients: ${data.clients.size}`,
      affectedIp: server,
      category: FindingCategory.Auth,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/* ========================================================================
 * CoAP (Constrained Application Protocol) — UDP 5683/5684
 * ======================================================================== */

/**
 * Detect unsecured CoAP traffic (no DTLS).
 * CoAP on port 5683 is cleartext — IoT devices often expose sensors, actuators,
 * and resource directories without any authentication or encryption.
 * CoAP can also be abused for DDoS amplification.
 */
export function detectCoAPExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const coapDevices = new Map<string, { count: number; methods: Set<string>; hasDTLS: boolean }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.CoAP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const port = "srcPort" in (pkt.transport || {}) ? (pkt.transport as { srcPort: number; dstPort: number }).srcPort : 0;
    const isDTLS = port === 5684;
    const summary = pkt.appPayloadSummary || pkt.info || "";

    const entry = coapDevices.get(srcIp);
    if (entry) {
      entry.count++;
      if (isDTLS) entry.hasDTLS = true;
      // Extract method from summary (e.g. "CoAP GET /sensors/temp")
      const methodMatch = summary.match(/coap\s+(get|post|put|delete|fetch|ipatch)/i);
      if (methodMatch) entry.methods.add(methodMatch[1].toUpperCase());
    } else {
      coapDevices.set(srcIp, {
        count: 1,
        methods: new Set(),
        hasDTLS: isDTLS,
      });
      const methodMatch = summary.match(/coap\s+(get|post|put|delete|fetch|ipatch)/i);
      if (methodMatch) {
        coapDevices.get(srcIp)!.methods.add(methodMatch[1].toUpperCase());
      }
    }
  }

  for (const [ip, data] of coapDevices) {
    if (data.count < 2) continue;
    if (data.hasDTLS) continue; // secured, skip

    const methods = data.methods.size > 0 ? [...data.methods].join(", ") : "unknown";
    findings.push({
      id: nextId(),
      title: "Unsecured CoAP Traffic (No DTLS)",
      severity: Severity.Medium,
      description: `CoAP traffic from ${ip} detected on cleartext port 5683 (${data.count} packets, methods: ${methods}). CoAP is designed for constrained IoT devices and often lacks authentication. Without DTLS, any network observer can read sensor data, and any attacker can send commands to actuators. CoAP also has amplification potential (~30x) for DDoS attacks when responses are larger than requests.`,
      recommendation: `1. Enable DTLS (CoAP over port 5684) with pre-shared keys or certificates.
2. If DTLS is not feasible, isolate CoAP devices on a dedicated IoT VLAN.
3. Implement CoAP observe and block requests from unauthorized IPs.
4. Disable CoAP on devices that do not require it.
5. Filter CoAP (UDP/5683) at network boundaries to prevent amplification abuse.
6. Use CoAP resource directory access control if available.`,
      evidence: `Device: ${ip}, Packets: ${data.count}, Methods: ${methods}, DTLS: no`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/* ========================================================================
 * SIP (Session Initiation Protocol) — UDP 5060/5061
 * ======================================================================== */

/**
 * Detect cleartext SIP traffic and potential VoIP fraud indicators.
 * SIP on port 5060 sends all signaling (including credentials) in cleartext.
 * SIPS (5061) uses TLS. We flag cleartext SIP and detect patterns indicating
 * toll fraud, registration hijacking, or enumeration.
 */
export function detectSIPCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const sipEndpoints = new Map<string, {
    count: number;
    hasTLS: boolean;
    methods: Set<string>;
    failedAuth: number;
    registerFrom: Set<string>;
  }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SIP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const port = "srcPort" in (pkt.transport || {}) ? (pkt.transport as { srcPort: number; dstPort: number }).srcPort : 0;
    const hasTLS = port === 5061;
    const summary = pkt.appPayloadSummary || pkt.info || "";

    const entry = sipEndpoints.get(srcIp);
    if (entry) {
      entry.count++;
      if (hasTLS) entry.hasTLS = true;
      const methodMatch = summary.match(/SIP\s+(REGISTER|INVITE|SUBSCRIBE|NOTIFY|MESSAGE|OPTIONS|BYE|CANCEL|ACK|INFO|PRACK|UPDATE|REFER)\b/i);
      if (methodMatch) entry.methods.add(methodMatch[1].toUpperCase());
      if (summary.includes("401") || summary.includes("403") || summary.includes("407")) {
        entry.failedAuth++;
      }
      if (summary.toUpperCase().includes("REGISTER")) {
        entry.registerFrom.add(srcIp);
      }
    } else {
      const methods = new Set<string>();
      const methodMatch = summary.match(/SIP\s+(REGISTER|INVITE|SUBSCRIBE|NOTIFY|MESSAGE|OPTIONS|BYE|CANCEL|ACK|INFO|PRACK|UPDATE|REFER)\b/i);
      if (methodMatch) methods.add(methodMatch[1].toUpperCase());

      sipEndpoints.set(srcIp, {
        count: 1,
        hasTLS,
        methods,
        failedAuth: (summary.includes("401") || summary.includes("403") || summary.includes("407")) ? 1 : 0,
        registerFrom: new Set([srcIp]),
      });
    }
  }

  // Flag cleartext SIP endpoints
  for (const [ip, data] of sipEndpoints) {
    if (data.count < 2) continue;

    if (!data.hasTLS) {
      const methods = data.methods.size > 0 ? [...data.methods].join(", ") : "unknown";
      findings.push({
        id: nextId(),
        title: "Cleartext SIP Signaling (No TLS/SIPS)",
        severity: Severity.High,
        description: `SIP traffic from ${ip} on cleartext port 5060 (${data.count} packets, methods: ${methods}). SIP credentials, call setup, and session descriptions are transmitted in cleartext. An attacker on the network can capture SIP digest authentication, make unauthorized calls (toll fraud), eavesdrop on call metadata, or hijack registrations. SIP is one of the most exploited protocols in VoIP environments.`,
        recommendation: `1. Enable SIPS (SIP over TLS on port 5061) for all SIP signaling.
2. Use SRTP (Secure RTP) for media encryption.
3. Implement SIP firewall rules to restrict SIP to authorized peers only.
4. Require strong SIP digest authentication passwords.
5. Monitor for unusual call patterns (international calls, off-hours activity).
6. Consider SIP over VPN for remote extensions.`,
        evidence: `Endpoint: ${ip}, Packets: ${data.count}, Methods: ${methods}, TLS: no`,
        affectedIp: ip,
        category: FindingCategory.RemoteAccess,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }

    // Flag high auth failure counts (brute-force or toll fraud attempts)
    if (data.failedAuth >= 5) {
      findings.push({
        id: nextId(),
        title: "SIP Authentication Failures (Potential Brute-Force or Toll Fraud)",
        severity: Severity.High,
        description: `Host ${ip} had ${data.failedAuth} SIP authentication failures (401/403/407 responses). Repeated SIP auth failures may indicate brute-force attacks against SIP accounts, toll fraud attempts, or registration hijacking. Compromised SIP credentials are used to make expensive international calls at the organization's expense.`,
        recommendation: `1. Check SIP server logs for the targeted accounts/extension numbers.
2. Lock accounts with excessive auth failures and reset passwords.
3. Implement rate-limiting on SIP authentication attempts.
4. Enable fail2ban or equivalent SIP intrusion detection.
5. Block international dialing for extensions that don't require it.
6. Review call detail records (CDRs) for unauthorized calls during the failure window.`,
        evidence: `Endpoint: ${ip}, Auth failures: ${data.failedAuth}`,
        affectedIp: ip,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ========================================================================
 * DHCPv6 — UDP 546/547
 * ======================================================================== */

/**
 * Detect rogue DHCPv6 and SLAAC-based attacks.
 * In IPv6 networks, a rogue DHCPv6 server can distribute malicious DNS
 * server addresses, redirecting traffic. Even without DHCPv6, SLAAC
 * Router Advertisements (RAs) can assign malicious DNS resolvers.
 * We flag unexpected DHCPv6 servers and reconfigure messages.
 */
export function detectRogueDHCPv6(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const dhcpv6Servers = new Map<string, {
    advertises: number;
    replies: number;
    reconfigure: number;
    clients: Set<string>;
  }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCPv6) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();

    // DHCPv6 server messages: Advertise (2), Reply (4), Reconfigure (10)
    const isAdvertise = summary.includes("advertise") || summary.includes("type 2");
    const isReply = summary.includes("reply") || summary.includes("type 4") || summary.includes("ack");
    const isReconfigure = summary.includes("reconfigure") || summary.includes("type 10");
    const isServerMsg = isAdvertise || isReply || isReconfigure;

    if (!isServerMsg) continue;

    const entry = dhcpv6Servers.get(srcIp);
    if (entry) {
      if (isAdvertise) entry.advertises++;
      if (isReply) entry.replies++;
      if (isReconfigure) entry.reconfigure++;
      const dstIp = pkt.ip.dstIp;
      if (dstIp && dstIp !== "ff02::1:2" && dstIp !== "ff02::1") {
        entry.clients.add(dstIp);
      }
    } else {
      dhcpv6Servers.set(srcIp, {
        advertises: isAdvertise ? 1 : 0,
        replies: isReply ? 1 : 0,
        reconfigure: isReconfigure ? 1 : 0,
        clients: new Set(),
      });
    }
  }

  for (const [serverIp, data] of dhcpv6Servers) {
    const totalServerMsgs = data.advertises + data.replies + data.reconfigure;
    if (totalServerMsgs < 2) continue;

    // Flag any DHCPv6 server — enterprises typically have 1-2 authorized servers
    findings.push({
      id: nextId(),
      title: "DHCPv6 Server Detected (Verify Authorization)",
      severity: Severity.Medium,
      description: `DHCPv6 server at ${serverIp} sent ${data.advertises} Advertise, ${data.replies} Reply, and ${data.reconfigure} Reconfigure messages. A rogue DHCPv6 server can assign malicious DNS resolvers, default gateways, or NTP servers, enabling traffic interception, DNS hijacking, or time manipulation. In IPv6, DHCPv6 is often combined with SLAAC Router Advertisements to fully control client network configuration.`,
      recommendation: `1. Verify that ${serverIp} is an authorized DHCPv6 server for this network.
2. If unauthorized, block it immediately and investigate the host.
3. Enable DHCPv6 Guard (RA Guard) on network switches to filter rogue DHCPv6/RA messages.
4. Configure IPv6 Router Advertisement authentication (RA Guard, SEND protocol).
5. Monitor for DHCPv6 Reconfigure messages — they can force clients to adopt new settings.
6. Use IPv6 First Hop Security (FHSS) features on managed switches.`,
      evidence: `Server: ${serverIp}, Advertise: ${data.advertises}, Reply: ${data.replies}, Reconfigure: ${data.reconfigure}`,
      affectedIp: serverIp,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });

    // Reconfigure messages are especially dangerous
    if (data.reconfigure >= 1) {
      findings.push({
        id: nextId(),
        title: "DHCPv6 Reconfigure Message Detected",
        severity: Severity.High,
        description: `DHCPv6 server ${serverIp} sent ${data.reconfigure} Reconfigure message(s). The Reconfigure message forces clients to re-request configuration, potentially accepting new DNS servers or other settings from a rogue server. An attacker can use this to push malicious DNS resolvers, redirecting traffic to phishing or C2 servers.`,
        recommendation: `1. Immediately verify the legitimacy of the Reconfigure message from ${serverIp}.
2. If not expected, treat this as an active attack and isolate ${serverIp}.
3. Disable DHCPv6 Reconfigure acceptance on clients if not needed.
4. Implement DHCPv6 Guard on all access switches.
5. Check client DNS resolver settings for unauthorized changes.`,
        evidence: `Server: ${serverIp}, Reconfigure messages: ${data.reconfigure}`,
        affectedIp: serverIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect DHCPv6 Solicit floods (potential DoS against DHCPv6 infrastructure).
 */
export function detectDHCPv6Flood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const solicitSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCPv6) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    if (summary.includes("solicit") || summary.includes("type 1")) {
      const srcIp = pkt.ip.srcIp;
      solicitSources.set(srcIp, (solicitSources.get(srcIp) || 0) + 1);
    }
  }

  for (const [srcIp, count] of solicitSources) {
    if (count >= 10) {
      findings.push({
        id: nextId(),
        title: "DHCPv6 Solicit Flood Detected",
        severity: Severity.Medium,
        description: `Source ${srcIp} sent ${count} DHCPv6 Solicit messages. A high volume of Solicit requests can exhaust DHCPv6 server address pools, cause denial of service for legitimate IPv6 clients, or indicate a misconfigured client in a rapid Solicit-Advertise loop.`,
        recommendation: `1. Investigate ${srcIp} — determine if it is a misconfigured client or an attacker.
2. Rate-limit DHCPv6 Solicit messages on the server.
3. Check the DHCPv6 server address pool utilization.
4. Enable DHCPv6 snooping with rate limiting on access switches.
5. If ${srcIp} is a legitimate client, check its DHCPv6 client daemon for bugs.`,
        evidence: `Source: ${srcIp}, Solicit count: ${count}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ========================================================================
 * WireGuard — UDP 51820
 * ======================================================================== */

/**
 * Detect WireGuard handshake scanning / fingerprinting.
 * Repeated Handshake Initiation messages without a corresponding
 * Handshake Response indicate either: a misconfigured peer, a peer
 * trying to connect to a non-WireGuard endpoint, or active scanning
 * to fingerprint WireGuard servers. WireGuard silently drops invalid
 * handshakes, but the scan itself is observable.
 */
export function detectWireGuardHandshakeScan(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const initiators = new Map<string, { count: number; responders: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.WireGuard) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const view = new Uint8Array(pkt.appPayload);
    const msgType = view[0];

    // Type 1 = Handshake Initiation
    if (msgType === 1) {
      const srcIp = pkt.ip.srcIp;
      const dstIp = pkt.ip.dstIp;
      const entry = initiators.get(srcIp);
      if (entry) {
        entry.count++;
        entry.responders.add(dstIp);
      } else {
        initiators.set(srcIp, { count: 1, responders: new Set([dstIp]) });
      }
    }
  }

  for (const [srcIp, data] of initiators) {
    if (data.count >= 10 || data.responders.size >= 5) {
      findings.push({
        id: nextId(),
        title: "WireGuard Handshake Scanning Detected",
        severity: Severity.Medium,
        description: `Source ${srcIp} sent ${data.count} WireGuard Handshake Initiation messages to ${data.responders.size} different peer(s). High-volume handshake initiations — especially to multiple destinations — may indicate WireGuard server scanning/fingerprinting. While WireGuard silently drops invalid handshakes (no response = no confirmation), the scan pattern itself reveals reconnaissance activity targeting VPN infrastructure.`,
        recommendation: `1. Verify that ${srcIp} is an authorized WireGuard client.
2. If unauthorized, block UDP/51820 from ${srcIp} at the firewall.
3. Consider changing the WireGuard listen port from the default 51820 to a non-standard port.
4. Implement firewall rate-limiting on WireGuard handshake packets.
5. Check WireGuard peer configuration on ${srcIp} for incorrect endpoint addresses.
6. If using a WireGuard management platform, check for misconfigured peer deployments.`,
        evidence: `Source: ${srcIp}, Handshake initiations: ${data.count}, Target peers: ${data.responders.size}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect WireGuard exposure on the default port (51820).
 * Running WireGuard on the default port makes it discoverable by scanners.
 * While the protocol is cryptographically secure, knowing a WireGuard
 * endpoint exists allows targeted attacks against the handshake.
 */
export function detectWireGuardDefaultPort(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const wgEndpoints = new Map<string, { count: number; peers: Set<string> }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.WireGuard) continue;
    if (flow.packetCount < 3) continue;

    const server = flow.dstPort === 51820 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 51820 ? flow.srcIp : flow.dstIp;

    const entry = wgEndpoints.get(server);
    if (entry) {
      entry.count++;
      entry.peers.add(client);
    } else {
      wgEndpoints.set(server, { count: 1, peers: new Set([client]) });
    }
  }

  for (const [server, data] of wgEndpoints) {
    findings.push({
      id: nextId(),
      title: "WireGuard VPN on Default Port 51820",
      severity: Severity.Low,
      description: `WireGuard server ${server} is running on the default port 51820 with ${data.peers.size} connected peer(s). The default port is routinely scanned by automated tools. While WireGuard is cryptographically secure and silently drops unauthorized handshakes, running on a non-standard port reduces exposure to targeted scanning and fingerprinting attempts.`,
      recommendation: `1. Consider changing the WireGuard listen port to a non-standard port.
2. Restrict UDP/51820 access at the firewall to only authorized peer IPs.
3. Use a WireGuard overlay manager (e.g. Firezone, Netmaker) for access control.
4. Monitor for handshake scanning patterns from unknown IPs.
5. Ensure WireGuard private keys are stored securely and rotated periodically.`,
      evidence: `Server: ${server}, Flows: ${data.count}, Peers: ${data.peers.size}, Port: 51820`,
      affectedIp: server,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect WireGuard handshake failures (initiations without responses).
 * When a WireGuard initiator sends Handshake Initiation but never
 * receives a Handshake Response, it indicates the peer is either:
 * offline, has an incorrect public key, is behind a restrictive firewall,
 * or the endpoint is not a WireGuard server at all.
 */
export function detectWireGuardFailedHandshakes(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const handshakePairs = new Map<string, { initiations: number; responses: number; srcIp: string; dstIp: string }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.WireGuard) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const view = new Uint8Array(pkt.appPayload);
    const msgType = view[0];

    if (msgType !== 1 && msgType !== 2) continue;

    const srcIp = pkt.ip.srcIp;
    const dstIp = pkt.ip.dstIp;

    if (msgType === 1) {
      const key = `${srcIp}->${dstIp}`;
      const pair = handshakePairs.get(key);
      if (pair) {
        pair.initiations++;
      } else {
        handshakePairs.set(key, { initiations: 1, responses: 0, srcIp, dstIp });
      }
    } else if (msgType === 2) {
      const key = `${dstIp}->${srcIp}`;
      const pair = handshakePairs.get(key);
      if (pair) {
        pair.responses++;
      }
    }
  }

  for (const [, pair] of handshakePairs) {
    if (pair.initiations >= 5 && pair.responses === 0) {
      findings.push({
        id: nextId(),
        title: "WireGuard Handshake Failures (No Response from Peer)",
        severity: Severity.Medium,
        description: `${pair.srcIp} sent ${pair.initiations} WireGuard Handshake Initiation messages to ${pair.dstIp} but received no Handshake Response. This indicates the peer at ${pair.dstIp} is either not running WireGuard, has a different public key configured, is blocking UDP/51820, or the endpoint address is incorrect. Persistent failed handshakes may also indicate a firewall dropping WireGuard traffic or a configuration mismatch.`,
        recommendation: `1. Verify the WireGuard peer configuration on ${pair.srcIp} — check the endpoint address and peer public key.
2. Confirm ${pair.dstIp} is running WireGuard and listening on the expected port.
3. Check firewall rules on both ends — WireGuard requires bidirectional UDP.
4. Verify that NAT traversal is working if either peer is behind NAT (persistent keepalive).
5. Check for MTU issues that may cause handshake packets to be dropped.
6. Use 'wg show' on both peers to compare session state.`,
        evidence: `Initiator: ${pair.srcIp}, Target: ${pair.dstIp}, Initiations: ${pair.initiations}, Responses: 0`,
        affectedIp: pair.srcIp,
        category: FindingCategory.Network,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
