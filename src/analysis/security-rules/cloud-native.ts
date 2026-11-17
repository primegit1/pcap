import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * etcd — Kubernetes Secret Store (TCP 2379/2380)
 * ======================================================================== */

/**
 * Detect unencrypted etcd traffic — etcd stores all Kubernetes secrets,
 * service account tokens, ConfigMaps, and cluster state. Unauthenticated
 * or unencrypted access is a Critical finding.
 */
export function detectEtcdExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const etcdServers = new Map<string, { count: number; port: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Etcd) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = pkt.ip.dstIp;
    const entry = etcdServers.get(key) || { count: 0, port: pkt.transport.dstPort };
    entry.count++;
    etcdServers.set(key, entry);
  }

  for (const [ip, data] of etcdServers) {
    findings.push({
      id: nextId(),
      title: "etcd Traffic Detected — Kubernetes Secret Store Exposed",
      severity: Severity.Critical,
      description: `etcd traffic detected to ${ip}:${data.port} (${data.count} packets). etcd is the Kubernetes control-plane database that stores ALL cluster secrets including TLS certificates, service account tokens, API keys, and application secrets. Unauthenticated or cleartext access to etcd gives complete cluster compromise — an attacker can read all secrets, create admin service accounts, and take over the entire Kubernetes cluster.`,
      recommendation: `1. Enable mutual TLS (mTLS) authentication on etcd immediately.\n2. Restrict etcd access to the Kubernetes API server only — block port 2379/2380 at the firewall.\n3. Enable etcd encryption-at-rest for all secret types.\n4. Rotate ALL Kubernetes secrets and service account tokens after any etcd exposure.\n5. Audit etcd audit logs for unauthorized read access.\n6. Run etcd on an isolated management network, never on the application network.`,
      evidence: `etcd server: ${ip}:${data.port}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Auth,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * Kafka — Message Broker (TCP 9092/9093)
 * ======================================================================== */

/**
 * Detect unencrypted Kafka broker traffic.
 * Kafka on port 9092 transmits all messages in plaintext.
 * This can expose sensitive business data, PII, and event streams.
 */
export function detectKafkaExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const kafkaBrokers = new Map<string, { count: number; port: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Kafka) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = pkt.ip.dstIp;
    const entry = kafkaBrokers.get(key) || { count: 0, port: pkt.transport.dstPort };
    entry.count++;
    kafkaBrokers.set(key, entry);
  }

  for (const [ip, data] of kafkaBrokers) {
    const isEncryptedPort = data.port === 9093;
    findings.push({
      id: nextId(),
      title: isEncryptedPort
        ? "Kafka SSL/TLS Port Detected (9093)"
        : "Kafka Cleartext Broker Detected — Sensitive Data Exposed",
      severity: isEncryptedPort ? Severity.Info : Severity.High,
      description: isEncryptedPort
        ? `Kafka SSL traffic detected to ${ip}:9093. This is the encrypted Kafka listener port. Verify that all producers and consumers are using this port rather than the plaintext 9092 port.`
        : `Kafka broker traffic detected to ${ip}:${data.port} (${data.count} packets) on the plaintext port. All Kafka messages — which may contain PII, financial transactions, healthcare records, or internal business events — are transmitted in cleartext. Any host on the network segment can subscribe to topics and read all messages without authentication.`,
      recommendation: `1. Configure all Kafka listeners to require SSL/TLS (listener.security.protocol.map=PLAINTEXT:SSL).\n2. Enable SASL authentication (SASL_SSL) on all Kafka brokers.\n3. Migrate all producers and consumers to port 9093 (SSL).\n4. Disable the plaintext listener (port 9092) on all brokers.\n5. Implement topic-level ACLs to restrict access per application.\n6. Never expose Kafka brokers directly to the internet.`,
      evidence: `Kafka broker: ${ip}:${data.port}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * ZooKeeper — Cluster Coordination (TCP 2181)
 * ======================================================================== */

/**
 * Detect ZooKeeper traffic — ZooKeeper has no built-in authentication by default
 * and exposes cluster configuration, leader election data, and coordination state.
 */
export function detectZooKeeperExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const zkServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ZooKeeper) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.dstIp;
    zkServers.set(key, (zkServers.get(key) || 0) + 1);
  }

  for (const [ip, count] of zkServers) {
    findings.push({
      id: nextId(),
      title: "ZooKeeper Traffic Detected — Unauthenticated Cluster Coordination",
      severity: Severity.High,
      description: `ZooKeeper traffic detected to ${ip} (${count} packets). ZooKeeper by default has no authentication — any client that can reach port 2181 can read all znodes, modify cluster configuration, and disrupt leader election. ZooKeeper is typically used to coordinate Kafka, Hadoop, HBase, and other distributed systems. Unauthorized access can cause cluster-wide outages or allow an attacker to redirect cluster traffic.`,
      recommendation: `1. Enable ZooKeeper SASL authentication (Kerberos or DIGEST-MD5).\n2. Configure ACLs on all znodes using the SASL scheme.\n3. Restrict network access to ZooKeeper (port 2181) to authorized cluster nodes only.\n4. Enable TLS encryption on ZooKeeper client connections (ZooKeeper 3.5+).\n5. Never expose ZooKeeper to the internet or untrusted network segments.`,
      evidence: `ZooKeeper server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Auth,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * Consul — Service Mesh / KV Store (TCP 8500 / UDP 8600)
 * ======================================================================== */

/**
 * Detect Consul traffic — Consul's HTTP API and DNS interface can expose
 * service configuration, health check results, and KV store data without ACLs.
 */
export function detectConsulExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const consulServers = new Map<string, { count: number; port: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Consul) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = pkt.ip.dstIp;
    const entry = consulServers.get(key) || { count: 0, port: pkt.transport.dstPort };
    entry.count++;
    consulServers.set(key, entry);
  }

  for (const [ip, data] of consulServers) {
    findings.push({
      id: nextId(),
      title: "Consul Service Mesh Traffic Detected — Verify ACLs",
      severity: Severity.Medium,
      description: `Consul traffic detected to ${ip}:${data.port} (${data.count} packets). Without ACL tokens enabled, Consul's HTTP API (port 8500) exposes the full service registry, health check states, KV store contents, and node metadata to any client. This can leak internal service topology, credentials stored in the KV store, and enable service de-registration attacks.`,
      recommendation: `1. Enable Consul ACL system (acl.enabled = true) and set default policy to deny.\n2. Create minimal-privilege ACL tokens for each service.\n3. Enable TLS on the Consul HTTP API and RPC port.\n4. Restrict access to port 8500 (HTTP) and 8600 (DNS) via firewall rules.\n5. Never store raw secrets in the Consul KV store — use Vault integration instead.\n6. Enable Consul audit logging to track all API access.`,
      evidence: `Consul server: ${ip}:${data.port}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Auth,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * IRC — Internet Relay Chat (TCP 6667/6697)
 * ======================================================================== */

/**
 * Detect IRC traffic — IRC is frequently used as a C2 (Command & Control)
 * channel by botnets and malware. Port 6667 is plaintext.
 */
export function detectIRCTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ircServers = new Map<string, { count: number; port: number; hasNick: boolean }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IRC) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    const entry = ircServers.get(key) || { count: 0, port: pkt.transport.dstPort, hasNick: false };
    entry.count++;

    if (pkt.appPayload && pkt.appPayload.byteLength >= 4) {
      const bytes = new Uint8Array(pkt.appPayload);
      const text = Array.from(bytes).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : " ")).join("");
      if (/^(NICK|JOIN|PRIVMSG|MODE|USER)\s+/i.test(text)) {
        entry.hasNick = true;
      }
    }

    ircServers.set(key, entry);
  }

  for (const [addr, data] of ircServers) {
    const ip = addr.split(":")[0];
    const isPlaintext = data.port === 6667;

    findings.push({
      id: nextId(),
      title: isPlaintext
        ? "IRC Traffic on Port 6667 — Potential C2 Channel or Cleartext Chat"
        : "IRC Traffic Detected",
      severity: isPlaintext ? Severity.High : Severity.Medium,
      description: isPlaintext
        ? `IRC traffic detected to ${addr} (${data.count} packets) on the unencrypted port 6667. IRC is a known C2 (Command & Control) communication channel used by botnets (IRCBot, DarkIRC, Perlbot) and many malware families. Even for legitimate use, port 6667 transmits all chat content, channel names, nicknames, and credentials in cleartext.`
        : `IRC traffic detected to ${addr} (${data.count} packets). Verify this is authorized business communication — IRC is not a standard enterprise protocol and may indicate unauthorized software or C2 activity.`,
      recommendation: `1. Block outbound IRC ports (6667, 6697) at the perimeter firewall unless explicitly required.\n2. Investigate whether the source host is infected with IRC-based malware.\n3. Inspect the IRC server destination — check threat intelligence feeds for known C2 servers.\n4. If IRC is required for legitimate use, mandate IRC over TLS (port 6697).\n5. Alert on any IRC NICK/JOIN/PRIVMSG commands as high-priority security events.`,
      evidence: `IRC server: ${addr}, packets: ${data.count}${data.hasNick ? ", IRC commands confirmed" : ""}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * XMPP — Instant Messaging (TCP 5222/5269)
 * ======================================================================== */

/**
 * Detect XMPP traffic — XMPP on port 5222 may transmit messages in cleartext.
 * Also flags potential data exfiltration over XMPP.
 */
export function detectXMPPCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const xmppServers = new Map<string, { count: number; port: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.XMPP) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = pkt.ip.dstIp;
    const entry = xmppServers.get(key) || { count: 0, port: pkt.transport.dstPort };
    entry.count++;
    xmppServers.set(key, entry);
  }

  for (const [ip, data] of xmppServers) {
    const isFederation = data.port === 5269;
    findings.push({
      id: nextId(),
      title: isFederation
        ? "XMPP Federation Traffic Detected (Port 5269)"
        : "XMPP Instant Messaging Traffic Detected — Verify Encryption",
      severity: Severity.Medium,
      description: isFederation
        ? `XMPP server-to-server federation traffic detected to ${ip}:5269 (${data.count} packets). Federation without mandatory TLS allows message interception between XMPP servers. Verify STARTTLS is enforced on both sides.`
        : `XMPP traffic detected to ${ip}:${data.port} (${data.count} packets). XMPP on port 5222 without STARTTLS transmits instant messages, presence information, and roster (contact list) data in cleartext XML. This exposes all chat content and user relationships to network eavesdroppers.`,
      recommendation: `1. Enforce STARTTLS on all XMPP client connections (port 5222).\n2. Disable unencrypted XMPP connections at the server.\n3. For federation (5269), require mutual TLS between servers.\n4. Consider migrating to a modern encrypted messaging protocol (Signal, Matrix/Element).\n5. Block external XMPP traffic at the perimeter if not required for business purposes.`,
      evidence: `XMPP server: ${ip}:${data.port}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * STUN — Session Traversal Utilities for NAT (UDP 3478/5349)
 * ======================================================================== */

/**
 * Detect STUN/TURN traffic — commonly associated with WebRTC.
 * TURN relay credentials can be exposed if not using DTLS.
 */
export function detectSTUNTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const stunServers = new Map<string, { count: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.STUN) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.dstIp;
    const entry = stunServers.get(key) || { count: 0 };
    entry.count++;
    stunServers.set(key, entry);
  }

  for (const [ip, data] of stunServers) {
    findings.push({
      id: nextId(),
      title: "STUN/TURN Traffic Detected — WebRTC NAT Traversal",
      severity: Severity.Info,
      description: `STUN/TURN traffic detected to ${ip} (${data.count} packets). STUN is used for NAT traversal in WebRTC and VoIP applications. If TURN relay credentials are transmitted without DTLS encryption, they can be intercepted. High volumes of STUN traffic may also indicate peer-to-peer applications or covert channel usage.`,
      recommendation: `1. Ensure TURN relay servers require credential authentication (username/password).\n2. Use DTLS-SRTP for all WebRTC media streams.\n3. Implement short-lived TURN credentials that expire quickly.\n4. Monitor for unusual STUN traffic volumes which may indicate P2P file sharing or covert channels.\n5. Restrict TURN relay server access to authorized users only.`,
      evidence: `STUN server: ${ip}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * DCE/RPC — Windows RPC Endpoint Mapper (TCP 135)
 * ======================================================================== */

/**
 * Detect DCE/RPC endpoint mapper traffic — port 135 is used for Windows
 * RPC service location and is frequently targeted for lateral movement.
 */
export function detectDCERPCExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const rpcServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DCERPC) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.dstIp;
    rpcServers.set(key, (rpcServers.get(key) || 0) + 1);
  }

  for (const [ip, count] of rpcServers) {
    findings.push({
      id: nextId(),
      title: "DCE/RPC Endpoint Mapper Traffic Detected",
      severity: Severity.Medium,
      description: `DCE/RPC endpoint mapper traffic detected to ${ip} (${count} packets) on port 135. The RPC endpoint mapper is used by Windows services to negotiate dynamic ports for RPC communication. Attackers use port 135 for reconnaissance (enumerating RPC services), lateral movement via DCOM/WMI, and exploiting RPC vulnerabilities. Many critical Windows exploits use RPC as the initial entry point.`,
      recommendation: `1. Block port 135 at network perimeters — RPC should never be exposed to the internet.\n2. Use Windows Firewall to restrict RPC access to specific management hosts only.\n3. Disable unnecessary RPC services (DCOM Server Process Launcher if not needed).\n4. Monitor RPC endpoint mapper connections for unusual patterns or external sources.\n5. Apply all Windows RPC-related security patches promptly.`,
      evidence: `RPC endpoint mapper: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * GE SRTP — GE PLC Protocol (TCP 18245)
 * ======================================================================== */

/**
 * Detect GE SRTP (Service Request Transport Protocol) traffic.
 * Used by GE PLCs (PACSystems, Series 90). No authentication by default.
 */
export function detectGeSRTPTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const srtpDevices = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.GeSRTP) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.dstIp;
    srtpDevices.set(key, (srtpDevices.get(key) || 0) + 1);
  }

  for (const [ip, count] of srtpDevices) {
    findings.push({
      id: nextId(),
      title: "GE SRTP PLC Protocol Detected — Unauthenticated ICS Traffic",
      severity: Severity.High,
      description: `GE SRTP (Service Request Transport Protocol) traffic detected to ${ip} (${count} packets). SRTP is used by GE PACSystems and Series 90 PLCs for programming, monitoring, and control. The protocol has no built-in authentication or encryption — any attacker that can reach port 18245 can read PLC data, modify program logic, start/stop processes, and potentially cause physical damage to industrial equipment.`,
      recommendation: `1. Isolate GE PLC devices on a dedicated OT network segment with no IT network access.\n2. Implement industrial firewalls/DMZ between IT and OT networks.\n3. Use application-aware firewalls that understand SRTP to whitelist only expected command types.\n4. Enable logging and anomaly detection on all SRTP communications.\n5. Apply GE security recommendations for PACSystems hardening.\n6. Never expose SRTP (port 18245) outside the OT network.`,
      evidence: `GE PLC device: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * Niagara Fox — Building Automation (TCP 1911/4911)
 * ======================================================================== */

/**
 * Detect Niagara Fox protocol traffic — used by Tridium Niagara building
 * automation controllers. Historical vulnerabilities include cleartext auth.
 */
export function detectNiagaraFoxTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const foxDevices = new Map<string, { count: number; port: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.NiagaraFox) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = pkt.ip.dstIp;
    const entry = foxDevices.get(key) || { count: 0, port: pkt.transport.dstPort };
    entry.count++;
    foxDevices.set(key, entry);
  }

  for (const [ip, data] of foxDevices) {
    const isTLS = data.port === 4911;
    findings.push({
      id: nextId(),
      title: isTLS
        ? "Niagara Fox/TLS Building Automation Traffic (Port 4911)"
        : "Niagara Fox Cleartext Building Automation Protocol Detected",
      severity: isTLS ? Severity.Info : Severity.High,
      description: isTLS
        ? `Niagara Fox over TLS (FoxS) detected to ${ip}:4911 (${data.count} packets). This is the encrypted variant. Verify certificate validity and authentication configuration.`
        : `Niagara Fox protocol traffic detected to ${ip}:1911 (${data.count} packets). Niagara Fox is used by Tridium Niagara building automation controllers (HVAC, lighting, access control, energy management). The cleartext Fox protocol (port 1911) has had multiple CVEs including cleartext credential transmission. An attacker can intercept credentials and gain control of building systems.`,
      recommendation: `1. Migrate all Niagara Fox connections to FoxS (TLS on port 4911).\n2. Disable the cleartext Fox protocol (port 1911) on all Niagara controllers.\n3. Apply all Tridium security patches — multiple critical CVEs exist for Niagara.\n4. Isolate building automation controllers on a dedicated BAS network segment.\n5. Enable Niagara's built-in audit logging.\n6. Implement a building automation DMZ with strict firewall rules.`,
      evidence: `Niagara controller: ${ip}:${data.port}, packets: ${data.count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * HART-IP — Process Instrumentation (UDP/TCP 5094)
 * ======================================================================== */

/**
 * Detect HART-IP traffic — Highway Addressable Remote Transducer over IP.
 * Used in process industries for instrument configuration and monitoring.
 */
export function detectHARTIPTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const hartDevices = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HARTIP) continue;
    if (!pkt.ip) continue;

    const key = pkt.ip.dstIp;
    hartDevices.set(key, (hartDevices.get(key) || 0) + 1);
  }

  for (const [ip, count] of hartDevices) {
    findings.push({
      id: nextId(),
      title: "HART-IP Process Instrumentation Protocol Detected",
      severity: Severity.Medium,
      description: `HART-IP traffic detected to ${ip} (${count} packets). HART-IP (Highway Addressable Remote Transducer over IP) is used in process industries to configure and monitor field instruments (sensors, transmitters, actuators) over IP networks. HART-IP has limited security features — unauthorized access can allow reading sensitive process data, modifying instrument configurations, or causing process disruptions in chemical, oil & gas, or utility environments.`,
      recommendation: `1. Restrict HART-IP (port 5094) access to authorized engineering workstations only.\n2. Place HART-IP devices behind an industrial firewall/DMZ.\n3. Enable HART-IP session-level authentication where supported by the device.\n4. Monitor for unexpected HART-IP connections from non-engineering hosts.\n5. Apply firmware updates for all HART-enabled field devices.`,
      evidence: `HART-IP device: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}

/* ========================================================================
 * VXLAN — Overlay Tunnel (UDP 4789)
 * ======================================================================== */

/**
 * Detect VXLAN overlay tunnel traffic — VXLAN encapsulates L2 frames in UDP.
 * Without encryption, all inner traffic (including inner IP/TCP) is visible.
 */
export function detectVXLANTraffic(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const vxlanEndpoints = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.VXLAN) continue;
    if (!pkt.ip) continue;

    const key = `${pkt.ip.srcIp} → ${pkt.ip.dstIp}`;
    vxlanEndpoints.set(key, (vxlanEndpoints.get(key) || 0) + 1);
  }

  for (const [pair, count] of vxlanEndpoints) {
    const srcIp = pair.split(" → ")[0];
    findings.push({
      id: nextId(),
      title: "VXLAN Overlay Tunnel Detected — Inner Traffic Not Analyzed",
      severity: Severity.Medium,
      description: `VXLAN tunnel traffic detected on flow ${pair} (${count} packets). VXLAN encapsulates entire Ethernet frames inside UDP/IP packets. Without decapsulation, the inner L2/L3 traffic (which may include HTTP, database queries, authentication flows) is invisible to all current security rules. If VXLAN is not encrypted (e.g., via IPSec), all inner traffic is in cleartext and can be read by any host on the underlay network.`,
      recommendation: `1. Encrypt VXLAN tunnels using IPSec or WireGuard on the underlay network.\n2. Implement network-level segmentation to restrict who can send/receive VXLAN packets.\n3. Use BGP EVPN control plane for VXLAN to prevent unauthorized tunnel endpoints.\n4. Consider deploying a VXLAN-aware security tool that can decapsulate and inspect inner frames.\n5. Monitor for unexpected VXLAN sources — unauthorized VTEP endpoints indicate network misconfiguration or attack.`,
      evidence: `VXLAN tunnel: ${pair}, packets: ${count}`,
      affectedIp: srcIp,
      category: FindingCategory.Network,
      timestamp: 0,
    });
  }

  return findings;
}
