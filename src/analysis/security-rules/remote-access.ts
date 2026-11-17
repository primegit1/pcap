import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";
import { decodeAscii } from "../ascii";

/**
 * Detect SSH protocol version exchange and weak configurations.
 * SSH servers advertising very old versions may have known vulnerabilities.
 */
export function detectSSHWeakConfig(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const sshServers = new Map<string, string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SSH) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const text = decodeASCII(pkt.appPayload);
    if (!text) continue;

    // SSH version exchange: "SSH-2.0-OpenSSH_7.4" or similar
    if (text.startsWith("SSH-")) {
      const versionMatch = text.match(/^SSH-(\d+\.\d+)-([^\r\n]+)/);
      if (versionMatch) {
        const protoVersion = versionMatch[1];
        const software = versionMatch[2];
        const key = pkt.ip.srcIp;
        if (!sshServers.has(key)) {
          sshServers.set(key, `${protoVersion}-${software}`);
        }

        // Flag SSH protocol version < 2.0
        if (parseFloat(protoVersion) < 2.0) {
          findings.push({
            id: nextId(),
            title: "SSH Protocol Version 1 Detected — Insecure",
            severity: Severity.Critical,
            description: `SSH protocol version ${protoVersion} detected from ${pkt.ip.srcIp} (${software}). SSH-1 is cryptographically broken and vulnerable to man-in-the-middle attacks (insertion, interception, CRC32 compensation). It must not be used in any environment.`,
            recommendation: `1. Immediately disable SSH-1 on ${pkt.ip.srcIp}.
2. Force SSH-2 in sshd_config: Protocol 2 (or remove Protocol 1).
3. Regenerate any SSH-1 host keys.
4. Audit all SSH clients to ensure they use SSH-2 only.
5. If a legacy device only supports SSH-1, replace it or place behind a VPN.`,
            evidence: `SSH banner: ${text.slice(0, 80)}`,
            affectedIp: pkt.ip.srcIp,
            category: FindingCategory.SSH,
            timestamp: 0, // replaced with capture time by runAllRules
          });
        }
      }
    }
  }

  // Report all SSH servers detected (info level)
  for (const [ip, version] of sshServers) {
    findings.push({
      id: nextId(),
      title: "SSH Server Detected",
      severity: Severity.Info,
      description: `SSH server at ${ip} running ${version}. SSH provides encrypted remote access but should be audited for configuration weaknesses (key exchange algorithms, MACs, ciphers).`,
      recommendation: `1. Verify SSH is restricted to authorized users and IP ranges.
2. Disable password authentication — use key-based auth only.
3. Review supported key exchange, cipher, and MAC algorithms for weak entries.
4. Enable fail2ban or similar brute-force protection.
5. Keep the SSH server software up to date.`,
      evidence: `SSH version: ${version}`,
      affectedIp: ip,
      category: FindingCategory.SSH,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Telnet traffic — always insecure (cleartext credentials, no encryption).
 */
export function detectTelnetCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const telnetServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Telnet) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    telnetServers.set(serverIp, (telnetServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of telnetServers) {
    findings.push({
      id: nextId(),
      title: "Telnet Cleartext Protocol Detected",
      severity: Severity.Critical,
      description: `Telnet traffic detected to ${ip} (${count} packets). Telnet transmits all data — including login credentials — in cleartext with no encryption. Anyone on the network path can capture usernames, passwords, and session data. Telnet is one of the most exploited protocols in network intrusion scenarios.`,
      recommendation: `1. Replace Telnet with SSH immediately on all devices.
2. Disable the Telnet service on ${ip} if SSH is available.
3. Rotate all credentials that were transmitted over Telnet — assume compromised.
4. For network devices (switches, routers), use SSH or console access only.
5. Implement network segmentation to isolate any devices that still require Telnet.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.RemoteAccess,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect FTP cleartext credentials — FTP USER and PASS commands in plaintext.
 */
export function detectFTPCleartext(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.FTP) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 5) continue;

    const text = decodeASCII(pkt.appPayload);
    if (!text) continue;

    // Detect FTP USER command
    if (/^USER\s+/i.test(text)) {
      const username = text.slice(5, 50).trim();
      findings.push({
        id: nextId(),
        title: "FTP Cleartext Username Detected",
        severity: Severity.High,
        description: `FTP USER command detected from ${pkt.ip.srcIp} to ${pkt.ip.dstIp}. FTP transmits credentials in cleartext, exposing usernames and passwords to anyone with packet capture access. The username "${username}" is now compromised.`,
        recommendation: `1. Migrate from FTP to SFTP or FTPS immediately.
2. Disable plain FTP on the server.
3. Rotate the FTP credentials — they are compromised.
4. Use SSH-based file transfer (SFTP) or FTP over TLS (FTPS).
5. If FTP is required for legacy reasons, restrict access to trusted IP ranges only.`,
        evidence: `USER command: ${text.slice(0, 60).trim()}`,
        affectedIp: pkt.ip.dstIp,
        category: FindingCategory.FileShare,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }

    // Detect FTP PASS command
    if (/^PASS\s+/i.test(text)) {
      findings.push({
        id: nextId(),
        title: "FTP Cleartext Password Detected",
        severity: Severity.Critical,
        description: `FTP PASS command detected from ${pkt.ip.srcIp} to ${pkt.ip.dstIp}. The password was transmitted in cleartext over the network. This credential is now fully compromised and must be rotated immediately.`,
        recommendation: `1. IMMEDIATELY change the FTP password on ${pkt.ip.dstIp}.
2. Migrate from FTP to SFTP or FTPS.
3. Audit the FTP server for unauthorized access using these credentials.
4. Enable FTPS (FTP over TLS) or SFTP for all file transfers.
5. Implement IP-based access controls on the FTP server.`,
        evidence: `PASS command detected (credentials exposed)`,
        affectedIp: pkt.ip.dstIp,
        category: FindingCategory.FileShare,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }

    // Detect anonymous FTP login
    if (/^USER\s+anonymous/i.test(text)) {
      findings.push({
        id: nextId(),
        title: "FTP Anonymous Login Detected",
        severity: Severity.Medium,
        description: `Anonymous FTP login detected from ${pkt.ip.srcIp} to ${pkt.ip.dstIp}. Anonymous FTP access can expose sensitive files and may allow write access if misconfigured. It is frequently targeted by attackers for data theft and as a pivot point.`,
        recommendation: `1. Disable anonymous FTP access unless specifically required.
2. If anonymous access is needed, ensure it is read-only and chrooted.
3. Audit the anonymous FTP directory for sensitive data.
4. Log and monitor anonymous FTP sessions.
5. Consider using HTTP-based file sharing instead of anonymous FTP.`,
        evidence: `Anonymous login from ${pkt.ip.srcIp}`,
        affectedIp: pkt.ip.dstIp,
        category: FindingCategory.FileShare,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect RDP weak encryption / no NLA.
 * Flags any RDP traffic that isn't using TLS or CredSSP (NLA).
 */
export function detectRDPWeakEncryption(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const rdpServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.RDP) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    rdpServers.set(serverIp, (rdpServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of rdpServers) {
    findings.push({
      id: nextId(),
      title: "RDP Traffic Detected — Verify Encryption & NLA",
      severity: Severity.Medium,
      description: `RDP traffic detected to ${ip} (${count} packets). RDP without Network Level Authentication (NLA) and TLS encryption is vulnerable to credential interception and BlueKeep-style attacks. Legacy RDP encryption (RC4) is considered weak and vulnerable to man-in-the-middle attacks.`,
      recommendation: `1. Enable Network Level Authentication (NLA) on the RDP server.
2. Force TLS encryption for all RDP connections.
3. Disable legacy RDP security (RC4 encryption).
4. Place RDP behind a VPN — never expose port 3389 directly to the internet.
5. Apply all security patches (especially CVE-2019-0708 / BlueKeep).
6. Use strong password policies and consider MFA for RDP access.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.RemoteAccess,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect VNC traffic — often deployed without authentication or with weak
 * challenge-response authentication.
 */
export function detectVNCWeakAuth(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const vncServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.VNC) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    vncServers.set(serverIp, (vncServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of vncServers) {
    findings.push({
      id: nextId(),
      title: "VNC Traffic Detected — Verify Authentication",
      severity: Severity.High,
      description: `VNC traffic detected to ${ip} (${count} packets). VNC typically uses weak DES-based challenge-response authentication or no authentication at all. VNC transmits screen data and keystrokes without encryption, allowing credential theft and screen eavesdropping. It is a common target for brute-force attacks.`,
      recommendation: `1. Tunnel VNC through SSH or a VPN for encryption.
2. Use VNC implementations that support TLS (e.g., TigerVNC, RealVNC with encryption).
3. Set a strong VNC password (many implementations limit to 8 characters).
4. Restrict VNC access to trusted IP addresses.
5. Consider replacing VNC with RDP+NLA or SSH X11 forwarding.
6. Monitor for brute-force attempts against VNC authentication.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.RemoteAccess,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Decode ArrayBuffer to ASCII string, replacing non-printable chars.
 */
function decodeASCII(payload: ArrayBuffer): string {
  return decodeAscii(payload, false);
}
