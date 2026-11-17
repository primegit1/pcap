import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect Kerberos AS-REP roasting — pre-authentication disabled.
 * When an account has "Do not require Kerberos preauthentication" enabled,
 * the KDC returns an AS-REP containing encrypted password-derived data
 * without requiring a timestamp. Attackers can offline-crack this to
 * recover the account password.
 */
export function detectKerberosASREPRoasting(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const asRepSources = new Map<string, { count: number; targets: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Kerberos) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // AS-REP is the KDC response; without pre-auth, it's sent immediately after AS-REQ
    if (summary.includes("as-rep") || (summary.includes("kdc") && summary.includes("reply"))) {
      const srcIp = pkt.ip.srcIp;
      const dstIp = pkt.ip.dstIp;
      const entry = asRepSources.get(srcIp);
      if (entry) {
        entry.count++;
        entry.targets.add(dstIp);
      } else {
        asRepSources.set(srcIp, { count: 1, targets: new Set([dstIp]) });
      }
    }
  }

  for (const [kdcIp, data] of asRepSources) {
    findings.push({
      id: nextId(),
      title: "Kerberos AS-REP Responses Detected (Check Pre-Authentication)",
      severity: Severity.High,
      description: `KDC ${kdcIp} sent ${data.count} AS-REP response(s) to ${data.targets.size} client(s). If any of these accounts have pre-authentication disabled, the AS-REP contains encrypted password data that can be offline-cracked (AS-REP roasting). This is a common Active Directory attack — tools like Rubeus and Impacket automatically enumerate accounts with pre-auth disabled and extract crackable hashes.`,
      recommendation: `1. Audit Active Directory for accounts with "Do not require Kerberos preauthentication" enabled.
2. Enable pre-authentication for all accounts except where strictly required (e.g., legacy services).
3. Ensure service accounts use long, complex passwords (25+ chars) to resist offline cracking.
4. Monitor Event ID 4768 with pre-auth type 0 for AS-REQ without pre-auth.
5. Use Protected Users group for high-privilege accounts.
6. Deploy credential guard on endpoints to prevent credential theft.`,
      evidence: `KDC: ${kdcIp}, AS-REP count: ${data.count}, Clients: ${data.targets.size}`,
      affectedIp: kdcIp,
      category: FindingCategory.Auth,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Kerberos weak encryption (RC4 / DES).
 * Kerberos can negotiate weaker encryption types (RC4-HMAC, DES-CBC)
 * which are vulnerable to offline cracking. Modern environments should
 * enforce AES256-CTS-HMAC-SHA1-96 or newer.
 */
export function detectKerberosWeakEncryption(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const weakEtpSources = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Kerberos) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // RC4 (etype 23), DES-CBC-CRC (1), DES-CBC-MD5 (2), RC4-HMAC-EXP (24)
    if (summary.includes("rc4") || summary.includes("des") || summary.includes("etype 23") ||
        summary.includes("etype 1") || summary.includes("etype 2") || summary.includes("etype 24")) {
      const srcIp = pkt.ip.srcIp;
      weakEtpSources.set(srcIp, (weakEtpSources.get(srcIp) || 0) + 1);
    }
  }

  for (const [srcIp, count] of weakEtpSources) {
    findings.push({
      id: nextId(),
      title: "Kerberos Weak Encryption Type (RC4/DES) in Use",
      severity: Severity.High,
      description: `Kerberos traffic from ${srcIp} is using weak encryption types (RC4-HMAC or DES). RC4-HMAC (etype 23) is deprecated and vulnerable to offline brute-force attacks — Kerberoasting relies on extracting RC4-encrypted service tickets. DES encryption (etype 1/2) is trivially broken. Active Directory defaults to RC4 for service accounts unless AES is explicitly configured.`,
      recommendation: `1. Configure all accounts to support AES256 (etype 18) only.
2. Set "This account supports Kerberos AES 256 bit encryption" on all service accounts.
3. Enforce encryption type restrictions via Group Policy: Kerberos/Supported Encryption Types.
4. Remove RC4-HMAC from supported encryption types domain-wide.
5. Audit service accounts still using RC4: Get-ADUser -Filter {msDS-SupportedEncryptionTypes -band 0x4}.
6. Rotate passwords for any accounts that were using RC4 — they may have been cracked.`,
      evidence: `Source: ${srcIp}, Weak encryption packets: ${count}`,
      affectedIp: srcIp,
      category: FindingCategory.Auth,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Kerberos TGS-REQ for service tickets (Kerberoasting indicator).
 * Attackers request service tickets (TGS) for SPNs to extract encrypted
 * password hashes for offline cracking. High volumes of TGS requests
 * across many different SPNs from a single source is suspicious.
 */
export function detectKerberoasting(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const tgsRequesters = new Map<string, { count: number; targets: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Kerberos) continue;
    if (!pkt.ip) continue;

    const summary = (pkt.appPayloadSummary || pkt.info || "").toLowerCase();
    // TGS-REQ is a service ticket request
    if (summary.includes("tgs-req") || (summary.includes("kdc") && summary.includes("request") && !summary.includes("as-req"))) {
      const srcIp = pkt.ip.srcIp;
      const dstIp = pkt.ip.dstIp;
      const entry = tgsRequesters.get(srcIp);
      if (entry) {
        entry.count++;
        entry.targets.add(dstIp);
      } else {
        tgsRequesters.set(srcIp, { count: 1, targets: new Set([dstIp]) });
      }
    }
  }

  for (const [srcIp, data] of tgsRequesters) {
    // High TGS request volume from a single host is suspicious
    if (data.count >= 20) {
      findings.push({
        id: nextId(),
        title: "High Volume of Kerberos TGS Requests (Potential Kerberoasting)",
        severity: Severity.High,
        description: `Host ${srcIp} made ${data.count} TGS-REQ service ticket requests to KDC(s). A high volume of service ticket requests — especially across many different SPNs — is a strong indicator of Kerberoasting, where an attacker extracts RC4-encrypted service ticket hashes for offline password cracking. Combined with weak encryption (RC4), this is one of the most effective Active Directory attack techniques.`,
        recommendation: `1. Check Event ID 4769 logs for the requesting account and targeted SPNs.
2. If many different SPNs are being requested from ${srcIp}, investigate the host immediately.
3. Ensure all service accounts use AES256 encryption and have 25+ character passwords.
4. Use Managed Service Accounts (gMSA) instead of traditional service accounts.
5. Monitor for TGS requests with encryption type RC4 (etype 23) — these are the crackable ones.
6. Deploy deception SPNs (honey accounts) to detect Kerberoasting attempts.`,
        evidence: `Source: ${srcIp}, TGS requests: ${data.count}, KDCs: ${data.targets.size}`,
        affectedIp: srcIp,
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
