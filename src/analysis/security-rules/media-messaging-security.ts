import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { FlowRecord, SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========================================================================
 * RTSP (Real-Time Streaming Protocol) — TCP 554/8554
 * ======================================================================== */

/**
 * Detect cleartext RTSP traffic — credentials and camera streams exposed.
 * RTSP on port 554 sends authentication (Digest or Basic) and stream
 * URLs in cleartext. An attacker can capture credentials, enumerate
 * camera feeds, and intercept video/audio streams.
 */
export function detectRTSPCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const rtspEndpoints = new Map<string, { count: number; hasAuth: boolean; methods: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.RTSP) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    const summary = pkt.appPayloadSummary || pkt.info || "";

    const entry = rtspEndpoints.get(srcIp);
    if (entry) {
      entry.count++;
      if (summary.includes("401") || summary.includes("Authorization")) entry.hasAuth = true;
      const methodMatch = summary.match(/^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|ANNOUNCE|RECORD)/i);
      if (methodMatch) entry.methods.add(methodMatch[1].toUpperCase());
    } else {
      const methods = new Set<string>();
      const methodMatch = summary.match(/^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|ANNOUNCE|RECORD)/i);
      if (methodMatch) methods.add(methodMatch[1].toUpperCase());
      rtspEndpoints.set(srcIp, {
        count: 1,
        hasAuth: summary.includes("401") || summary.includes("Authorization"),
        methods,
      });
    }
  }

  for (const [ip, data] of rtspEndpoints) {
    if (data.count < 2) continue;

    const methods = data.methods.size > 0 ? [...data.methods].join(", ") : "unknown";
    findings.push({
      id: nextId(),
      title: "Cleartext RTSP Traffic (Camera/Surveillance Exposure)",
      severity: Severity.High,
      description: `RTSP traffic from ${ip} on cleartext port 554 (${data.count} packets, methods: ${methods}). RTSP streams from IP cameras, NVRs, and video encoders are transmitted without encryption. Credentials (if using Digest or Basic auth), camera URLs, and the video/audio stream itself are fully exposed. An attacker can view surveillance feeds, capture credentials, or manipulate PTZ controls. This is a physical security vulnerability.`,
      recommendation: `1. Enable RTSPS (RTSP over TLS) on all cameras and NVRs.
2. If RTSPS is not supported, tunnel RTSP through a VPN (WireGuard, IPsec).
3. Isolate cameras on a dedicated surveillance VLAN with no internet access.
4. Use strong RTSP credentials — avoid default admin/admin on cameras.
5. Disable ANNOUNCE and RECORD methods unless required.
6. Implement MAC filtering on the camera VLAN.
7. Consider modern alternatives: ONVIF Profile G (TLS), WebRTC, or SRTP.`,
      evidence: `Endpoint: ${ip}, Packets: ${data.count}, Methods: ${methods}, Auth: ${data.hasAuth ? "yes" : "none"}`,
      affectedIp: ip,
      category: FindingCategory.RemoteAccess,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect RTSP DESCRIBE requests without authentication.
 * DESCRIBE reveals the stream URL and media capabilities. Without auth,
 * any client can discover and access the camera feed.
 */
export function detectRTSPNoAuth(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const rtspFlows = flows.filter(
    (f) => f.appProtocol === Protocol.RTSP && f.packetCount >= 3
  );

  if (rtspFlows.length === 0) return findings;

  // Aggregate by server IP (typically the camera/NVR)
  const servers = new Map<string, { flows: number; clients: Set<string> }>();
  for (const flow of rtspFlows) {
    const server = flow.dstPort === 554 || flow.dstPort === 8554 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 554 || flow.dstPort === 8554 ? flow.srcIp : flow.dstIp;
    const entry = servers.get(server);
    if (entry) {
      entry.flows++;
      entry.clients.add(client);
    } else {
      servers.set(server, { flows: 1, clients: new Set([client]) });
    }
  }

  for (const [server, data] of servers) {
    if (data.flows >= 2) {
      findings.push({
        id: nextId(),
        title: "RTSP Camera/NVR Accessible Without Authentication Review",
        severity: Severity.Medium,
        description: `RTSP server ${server} has ${data.flows} active flow(s) from ${data.clients.size} client(s). If this camera or NVR does not require authentication for DESCRIBE/SETUP/PLAY, any network user can access the video feed. Many IP cameras ship with no authentication or default credentials, making them prime targets for surveillance feed interception and botnet recruitment (Mirai-style).`,
        recommendation: `1. Verify that ${server} requires authentication for all RTSP methods.
2. Change default credentials immediately if still in use.
3. Disable anonymous viewing in camera/NVR settings.
4. Restrict RTSP access to authorized client IPs via firewall rules.
5. Check if the device is exposed to the internet and close the port if not needed externally.`,
        evidence: `Server: ${server}, Flows: ${data.flows}, Clients: ${data.clients.size}`,
        affectedIp: server,
        category: FindingCategory.RemoteAccess,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ========================================================================
 * AMQP (Advanced Message Queuing Protocol) — TCP 5672/5671
 * ======================================================================== */

/**
 * Detect cleartext AMQP traffic and default credentials.
 * AMQP on port 5672 (without AMQPS/TLS on 5671) transmits messages,
 * credentials, and queue/exchange definitions in cleartext. RabbitMQ
 * ships with default guest/guest credentials that have full admin access.
 */
export function detectAMQPCleartext(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const amqpEndpoints = new Map<string, { count: number; peers: Set<string>; port: number }>();

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.AMQP) continue;
    if (flow.packetCount < 3) continue;

    const server = flow.dstPort === 5672 || flow.dstPort === 5671 ? flow.dstIp : flow.srcIp;
    const client = flow.dstPort === 5672 || flow.dstPort === 5671 ? flow.srcIp : flow.dstIp;
    const port = flow.dstPort === 5672 || flow.dstPort === 5671 ? flow.dstPort : flow.srcPort;

    const entry = amqpEndpoints.get(server);
    if (entry) {
      entry.count++;
      entry.peers.add(client);
    } else {
      amqpEndpoints.set(server, { count: 1, peers: new Set([client]), port });
    }
  }

  for (const [server, data] of amqpEndpoints) {
    const isTLS = data.port === 5671;
    if (isTLS) continue;

    findings.push({
      id: nextId(),
      title: "Cleartext AMQP Traffic (No TLS)",
      severity: Severity.High,
      description: `AMQP broker ${server} is using cleartext port 5672 with ${data.peers.size} connected client(s). AMQP without TLS (AMQPS) exposes message payloads, credentials, and queue/exchange configuration to network observers. RabbitMQ's default guest/guest account has full administrative access. Message queues often contain sensitive data: credentials, API keys, PII, and financial transactions.`,
      recommendation: `1. Enable AMQPS (AMQP over TLS on port 5671) with valid certificates.
2. Disable the default guest/guest account on RabbitMQ immediately.
3. Create dedicated AMQP users with least-privilege permissions per vhost.
4. Restrict guest access to localhost only (RabbitMQ default since 3.3.x).
5. Use SASL PLAIN over TLS or EXTERNAL (certificate) authentication.
6. Isolate the AMQP broker on a dedicated messaging VLAN.
7. Audit queue contents for sensitive data being transmitted in cleartext.`,
      evidence: `Broker: ${server}, Port: 5672 (cleartext), Clients: ${data.peers.size}, Flows: ${data.count}`,
      affectedIp: server,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
