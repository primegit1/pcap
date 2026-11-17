import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect SMTP traffic — flags cleartext email transmission and
 * potential open relay configuration.
 */
export function detectSMTPCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const smtpServers = new Map<string, { count: number; hasAuth: boolean; hasStartTLS: boolean }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SMTP) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const text = decodeASCII(pkt.appPayload);
    const serverIp = pkt.ip.dstIp;

    const existing = smtpServers.get(serverIp) || { count: 0, hasAuth: false, hasStartTLS: false };
    existing.count++;

    // Check for AUTH command (client attempting authentication)
    if (/^AUTH\s+/i.test(text)) {
      existing.hasAuth = true;
    }

    // Check for STARTTLS command (client requesting TLS upgrade)
    if (/^STARTTLS/i.test(text)) {
      existing.hasStartTLS = true;
    }

    // Detect SMTP AUTH LOGIN/PLAIN — cleartext credential transmission
    if (/^AUTH\s+(LOGIN|PLAIN)/i.test(text)) {
      findings.push({
        id: nextId(),
        title: "SMTP Cleartext Authentication Detected",
        severity: Severity.High,
        description: `SMTP AUTH LOGIN/PLAIN detected from ${pkt.ip.srcIp} to ${pkt.ip.dstIp}. These authentication mechanisms transmit credentials in base64 encoding (which is NOT encryption). Anyone with packet capture access can trivially decode the username and password.`,
        recommendation: `1. Ensure SMTP connections use TLS encryption (SMTPS port 465 or STARTTLS on port 587).
2. Disable AUTH LOGIN and AUTH PLAIN without TLS on the SMTP server.
3. Rotate the exposed credentials immediately.
4. Configure the mail server to require STARTTLS before accepting AUTH commands.
5. Audit mail server logs for unauthorized relay attempts.`,
        evidence: `AUTH command: ${text.slice(0, 60).trim()}`,
        affectedIp: pkt.ip.dstIp,
        category: FindingCategory.Email,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }

    smtpServers.set(serverIp, existing);
  }

  // Flag SMTP servers that lack STARTTLS
  for (const [ip, data] of smtpServers) {
    if (!data.hasStartTLS) {
      findings.push({
        id: nextId(),
        title: "SMTP Without STARTTLS — Cleartext Email Transmission",
        severity: Severity.Medium,
        description: `SMTP traffic to ${ip} (${data.count} packets) with no STARTTLS upgrade detected. Without TLS encryption, all email content, headers, and credentials are transmitted in cleartext. This exposes sensitive communications and authentication data to network-level eavesdropping.`,
        recommendation: `1. Enable STARTTLS on the SMTP server.
2. Configure the server to prefer TLS connections (port 587 with mandatory STARTTLS or port 465 SMTPS).
3. Set a policy to reject connections that don't upgrade to TLS.
4. Ensure valid TLS certificates are installed on the mail server.
5. Monitor for email credential exposure in network captures.`,
        evidence: `Server: ${ip}, packets: ${data.count}, STARTTLS: not detected`,
        affectedIp: ip,
        category: FindingCategory.Email,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect potential SMTP open relay — external clients sending MAIL FROM/RCPT TO
 * commands to non-local domains through this server.
 */
export function detectSMTPOpenRelay(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const relayAttempts = new Map<string, { domains: Set<string>; srcIp: string }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SMTP) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const text = decodeASCII(pkt.appPayload);

    // Track RCPT TO commands to identify relay attempts
    const rcptMatch = text.match(/^RCPT\s+TO:\s*<([^>]*)>/i);
    if (rcptMatch && pkt.ip) {
      const serverIp = pkt.ip.dstIp;
      const recipient = rcptMatch[1];
      const domain = recipient.includes("@") ? recipient.split("@")[1] : "local";

      const existing = relayAttempts.get(serverIp) || { domains: new Set<string>(), srcIp: pkt.ip.srcIp };
      existing.domains.add(domain);
      relayAttempts.set(serverIp, existing);
    }
  }

  // Flag servers receiving mail for many different domains (potential open relay)
  for (const [serverIp, data] of relayAttempts) {
    if (data.domains.size >= 3) {
      findings.push({
        id: nextId(),
        title: "Possible SMTP Open Relay Detected",
        severity: Severity.High,
        description: `SMTP server ${serverIp} received RCPT TO commands for ${data.domains.size} different domains from ${data.srcIp}. An open relay accepts and forwards email for any domain without authentication, making it a target for spammers and phishers. Open relays are quickly blacklisted, disrupting legitimate email delivery.`,
        recommendation: `1. Configure the SMTP server to require authentication before accepting mail.
2. Restrict relay permissions to authenticated users and local domains only.
3. Check DNSBL (DNS-based Blackhole List) status — the server may already be blacklisted.
4. Implement rate limiting on outbound email.
5. Enable SPF, DKIM, and DMARC to prevent email spoofing.`,
        evidence: `Server: ${serverIp}, recipient domains: ${Array.from(data.domains).slice(0, 10).join(", ")}`,
        affectedIp: serverIp,
        category: FindingCategory.Email,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

function decodeASCII(payload: ArrayBuffer): string {
  const bytes = new Uint8Array(payload);
  return Array.from(bytes)
    .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : " "))
    .join("");
}
