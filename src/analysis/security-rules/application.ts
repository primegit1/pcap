import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect LDAP anonymous binds — LDAP bind requests with empty credentials.
 * Flags flows where LDAP traffic contains binds without authentication.
 */
export function detectLDAPAnonymousBind(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const ldapServers = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.LDAP) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    ldapServers.add(pkt.ip.dstIp);
  }

  for (const ip of ldapServers) {
    findings.push({
      id: nextId(),
      title: "LDAP Traffic Detected",
      severity: Severity.Low,
      description: `LDAP traffic detected to ${ip}. LDAP transmits credentials and directory data in cleartext unless LDAPS (port 636) or STARTTLS is used. An attacker on the same network segment can intercept LDAP binds and extract usernames, passwords, and directory contents.`,
      recommendation: `1. Migrate all LDAP traffic to LDAPS (port 636) with valid TLS certificates.
2. Disable plain LDAP (port 389) on directory servers.
3. Enable signing and sealing via LDAP channel binding.
4. Monitor for anonymous LDAP binds which can expose directory structure.
5. Ensure domain controllers and directory servers reject LDAP without TLS.`,
      evidence: `LDAP server: ${ip}`,
      affectedIp: ip,
      category: FindingCategory.Auth,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect IMAP cleartext authentication — IMAP LOGIN command sends
 * username and password in plaintext.
 */
export function detectIMAPClearText(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.IMAP) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 10) continue;

    const bytes = new Uint8Array(pkt.appPayload);
    const text = Array.from(bytes)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ""))
      .join("");

    if (text.toUpperCase().includes("LOGIN")) {
      // Extract the login line (first 80 chars after LOGIN)
      const loginIdx = text.toUpperCase().indexOf("LOGIN");
      const snippet = text.slice(loginIdx, loginIdx + 80).trim();
      findings.push({
        id: nextId(),
        title: "IMAP Cleartext Authentication",
        severity: Severity.High,
        description: `IMAP LOGIN command detected in cleartext from ${pkt.ip.srcIp} to ${pkt.ip.dstIp}. IMAP transmits usernames and passwords as plaintext when STARTTLS or IMAPS is not used. This exposes email credentials to anyone with packet capture access to the network path.`,
        recommendation: `1. Immediately disable plaintext authentication on the IMAP server.
2. Use IMAPS (port 993) with TLS encryption for all email access.
3. Rotate the captured credentials as they are now compromised.
4. Enforce TLS-only connections via server configuration (require STARTTLS).
5. Audit all email clients to ensure they use encrypted connections.`,
        evidence: `Payload: ${snippet}`,
        affectedIp: pkt.ip.dstIp,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect mDNS traffic from external/non-link-local sources.
 * mDNS should only operate on the local link (224.0.0.251 / ff02::fb).
 * Traffic from other sources may indicate misconfiguration or reflection.
 */
export function detectMDNSReflection(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const externalSources = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.mDNS) continue;
    if (!pkt.ip) continue;

    const srcIp = pkt.ip.srcIp;
    // Link-local addresses start with 169.254.x.x or fe80::
    // mDNS should only originate from link-local
    if (
      !srcIp.startsWith("169.254.") &&
      !srcIp.startsWith("fe80:") &&
      srcIp !== "127.0.0.1" &&
      !srcIp.startsWith("::1")
    ) {
      externalSources.add(srcIp);
    }
  }

  for (const ip of externalSources) {
    findings.push({
      id: nextId(),
      title: "mDNS Traffic from Non-Link-Local Source",
      severity: Severity.Medium,
      description: `mDNS traffic detected from ${ip}, which is not a link-local address. mDNS (multicast DNS) is designed for zero-configuration networking on local subnets and should only originate from link-local addresses (169.254.x.x or fe80::). Traffic from other sources suggests multicast traffic crossing network boundaries, which can indicate mDNS reflection attacks or network misconfiguration.`,
      recommendation: `1. Investigigate the source ${ip} — determine how it is generating mDNS traffic.
2. Configure network switches to block mDNS at network boundaries (IGMP snooping, MLD).
3. Ensure multicast traffic does not traverse VLANs or subnets.
4. Review network segmentation — mDNS should never cross security boundaries.
5. Consider disabling mDNS on systems that do not require zero-config networking.`,
      evidence: `Source: ${ip}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect sensitive data patterns in Syslog traffic.
 */
export function detectSyslogSensitiveData(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Syslog) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 10) continue;

    const bytes = new Uint8Array(pkt.appPayload);
    const text = Array.from(bytes)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ""))
      .join("");

    // Check for potentially sensitive patterns
    const sensitivePatterns: [RegExp, string][] = [
      [/password[=: ]\S+/i, "possible password in syslog"],
      [/passwd[=: ]\S+/i, "possible password in syslog"],
      [/secret[=: ]\S+/i, "possible secret in syslog"],
      [/token[=: ]\S+/i, "possible token in syslog"],
      [/api[_-]?key[=: ]\S+/i, "possible API key in syslog"],
    ];

    for (const [pattern, label] of sensitivePatterns) {
      const match = text.match(pattern);
      if (match) {
        findings.push({
          id: nextId(),
          title: "Potential Sensitive Data in Syslog",
          severity: Severity.Medium,
          description: `Syslog message from ${pkt.ip.srcIp} to ${pkt.ip.dstIp} contains ${label}. Syslog is typically transmitted in cleartext over UDP port 514, meaning any sensitive data (passwords, tokens, API keys) sent via syslog is visible to anyone on the network path.`,
          recommendation: `1. Remove passwords, secrets, and API keys from all syslog messages.
2. Consider using RELP (Reliable Event Logging Protocol) over TLS for secure log transport.
3. Implement log filtering on the sending system to redact sensitive patterns.
4. Use encrypted syslog (TLS/SSL — RFC 5425) instead of plain UDP syslog.
5. Rotate any credentials that were captured in syslog messages.`,
          evidence: `Matched: ${match[0].slice(0, 80)}`,
          affectedIp: pkt.ip.dstIp,
          category: FindingCategory.Auth,
          timestamp: 0, // replaced with capture time by runAllRules
        });
        break; // One finding per packet
      }
    }
  }

  return findings;
}

/* ──────────── Redis, MongoDB, Docker, MQTT, Memcached Rules ──────────── */

/**
 * Detect Redis servers with no authentication exposed on the network.
 * Redis has no password by default and is one of the most exploited services.
 */
export function detectRedisExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const redisServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Redis) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    redisServers.set(key, (redisServers.get(key) || 0) + 1);
  }

  for (const [addr, count] of redisServers) {
    const ip = addr.split(":")[0];
    findings.push({
      id: nextId(),
      title: "Redis Service Detected — Potential No-Auth Exposure",
      severity: Severity.High,
      description: `Redis traffic detected to ${addr} (${count} packets). Redis has no authentication enabled by default and is one of the most frequently exploited database services. Attackers can read/write all data, modify configuration to write SSH keys or crontabs for RCE, and exfiltrate data with a single command.`,
      recommendation: `1. Immediately enable Redis AUTH with a strong password (requirepass directive).
2. Bind Redis to localhost (127.0.0.1) only unless remote access is absolutely required.
3. Place Redis behind a firewall — never expose it directly to the internet.
4. Rename or disable dangerous commands (FLUSHALL, CONFIG, DEBUG, SHUTDOWN).
5. Use Redis ACLs (Redis 6+) for fine-grained user permissions.
6. Enable TLS if remote access is unavoidable.`,
      evidence: `Server: ${addr}, ${count} packets observed`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect MongoDB traffic — commonly targeted in ransomware campaigns
 * where unsecured MongoDB instances are accessed, encrypted, and held for ransom.
 */
export function detectMongoDBExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const mongoServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.MongoDB) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    mongoServers.set(key, (mongoServers.get(key) || 0) + 1);
  }

  for (const [addr, count] of mongoServers) {
    const ip = addr.split(":")[0];
    findings.push({
      id: nextId(),
      title: "MongoDB Traffic Detected — Verify Security",
      severity: Severity.High,
      description: `MongoDB traffic detected to ${addr} (${count} packets). MongoDB has been the target of widespread ransomware campaigns where attackers scan for open databases, download and encrypt data, then demand payment. Unsecured MongoDB instances on port 27017 are discovered and compromised within hours of being exposed to the internet.`,
      recommendation: `1. Enable MongoDB authentication (SCRAM-SHA-256) with strong credentials.
2. Bind to localhost unless remote access is explicitly required.
3. Never expose MongoDB directly to the internet — always use a VPN or SSH tunnel.
4. Enable MongoDB audit logging to track queries and access.
5. Implement network segmentation to isolate database servers.
6. Ensure regular authenticated backups are maintained.`,
      evidence: `Server: ${addr}, ${count} packets observed`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Docker API exposure — unauthenticated Docker API access
 * grants full container and host control to attackers.
 */
export function detectDockerAPIExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const dockerEndpoints = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Docker) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    dockerEndpoints.set(key, (dockerEndpoints.get(key) || 0) + 1);
  }

  for (const [addr, count] of dockerEndpoints) {
    const ip = addr.split(":")[0];
    findings.push({
      id: nextId(),
      title: "Docker API Exposed — Potential Container Takeover Risk",
      severity: Severity.Critical,
      description: `Docker Engine API traffic detected to ${addr} (${count} packets). An exposed Docker API allows remote control of the Docker daemon. An attacker can start, stop, or modify containers, execute commands in running containers, pull malicious images, and potentially escape to the host. This is a well-known attack vector used by cryptominers and botnets for mass exploitation.`,
      recommendation: `1. IMMEDIATELY bind Docker API to localhost only — never expose port 2375/2376.
2. Use TLS authentication with client certificates for the Docker daemon.
3. If remote Docker management is needed, use SSH tunneling or a VPN.
4. Audit all running containers for unauthorized images.
5. Rotate all credentials on the affected host — assume compromise.
6. Review container logs and network traffic for signs of lateral movement.`,
      evidence: `Endpoint: ${addr}, ${count} packets observed`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Memcached traffic — used in massive DDoS amplification attacks
 * (up to 51,000x amplification factor).
 */
export function detectMemcachedExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const memcachedServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Memcached) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    memcachedServers.set(key, (memcachedServers.get(key) || 0) + 1);
  }

  for (const [addr, count] of memcachedServers) {
    const ip = addr.split(":")[0];
    findings.push({
      id: nextId(),
      title: "Memcached Service Detected — DDoS Amplification Risk",
      severity: Severity.High,
      description: `Memcached traffic detected to ${addr} (${count} packets). Memcached is frequently exploited in massive DDoS amplification attacks because it responds to UDP queries with a 51,000x amplification factor. A single small query can generate an enormous response. Exposed Memcached servers are actively scanned and harvested by DDoS-for-hire botnets.`,
      recommendation: `1. Bind Memcached to localhost (127.0.0.1) — never expose to the internet.
2. Disable UDP support if not needed (--enable-udp=no).
3. Implement firewall rules to restrict Memcached access to authorized hosts only.
4. Require SASL authentication for all Memcached connections.
5. Monitor Memcached network traffic for unusual query patterns or burst amplification.
6. Consider replacing Memcached with Redis if UDP is not required.`,
      evidence: `Server: ${addr}, ${count} packets observed`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect MQTT traffic — IoT messaging protocol often deployed without
 * authentication or encryption, exposing sensor data and device control.
 */
export function detectMQTTExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const mqttBrokers = new Map<string, { count: number; connects: number; publishes: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.MQTT) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("dstPort" in pkt.transport)) continue;

    const key = `${pkt.ip.dstIp}:${pkt.transport.dstPort}`;
    const entry = mqttBrokers.get(key) || { count: 0, connects: 0, publishes: 0 };
    entry.count++;

    // Check if payload indicates CONNECT or PUBLISH
    if (pkt.appPayload && pkt.appPayload.byteLength >= 2) {
      const msgType = (new Uint8Array(pkt.appPayload)[0] >> 4) & 0x0f;
      if (msgType === 1) entry.connects++;
      if (msgType === 3) entry.publishes++;
    }

    mqttBrokers.set(key, entry);
  }

  for (const [addr, data] of mqttBrokers) {
    const ip = addr.split(":")[0];
    const extra = [];
    if (data.connects > 0) extra.push(`${data.connects} CONNECT`);
    if (data.publishes > 0) extra.push(`${data.publishes} PUBLISH`);
    const details = extra.length > 0 ? ` (${extra.join(", ")})` : "";

    findings.push({
      id: nextId(),
      title: "MQTT Broker Detected — Verify Authentication",
      severity: Severity.Medium,
      description: `MQTT traffic detected to ${addr}${details}. MQTT is widely used in IoT deployments but is often configured without authentication, allowing anyone to subscribe to sensor topics or publish control commands. Unauthorized access can expose sensitive telemetry data or enable remote control of connected devices (SCADA, HVAC, door locks, sensors).`,
      recommendation: `1. Enable TLS encryption on all MQTT connections (port 8883).
2. Require username/password authentication on the broker.
3. Implement topic-based ACLs — restrict which clients can publish/subscribe to which topics.
4. Never expose MQTT brokers directly to the internet — use a gateway or VPN.
5. Audit all connected clients and revoke unused credentials.
6. Monitor publish rates to detect anomalous device behavior.`,
      evidence: `Broker: ${addr}, ${data.count} packets${details}`,
      affectedIp: ip,
      category: FindingCategory.Network,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
