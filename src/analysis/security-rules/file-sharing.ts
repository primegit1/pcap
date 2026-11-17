import { Protocol } from "../../types/packets";
import type { Packet } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect SMBv1 traffic by inspecting the SMB protocol magic bytes.
 * SMBv1 uses 0xFF 0x53 0x4D 0x42 ("\xFFSMB") as its protocol identifier.
 * SMBv2+ uses 0xFE 0x53 0x4D 0x42 ("\xFESMB").
 * SMBv1 is vulnerable to EternalBlue (MS17-010) and must be disabled.
 */
export function detectSMBv1(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const smb1Servers = new Map<string, number>();
  const smb2Servers = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SMB) continue;
    if (!pkt.ip) continue;

    if (!pkt.appPayload || pkt.appPayload.byteLength < 4) continue;

    const view = new Uint8Array(pkt.appPayload);
    const serverIp = pkt.ip.dstIp;

    // SMBv1: 0xFF 0x53 0x4D 0x42 ("\xffSMB")
    if (view[0] === 0xff && view[1] === 0x53 && view[2] === 0x4d && view[3] === 0x42) {
      smb1Servers.set(serverIp, (smb1Servers.get(serverIp) || 0) + 1);
    }
    // SMBv2+: 0xFE 0x53 0x4D 0x42 ("\xfeSMB")
    else if (view[0] === 0xfe && view[1] === 0x53 && view[2] === 0x4d && view[3] === 0x42) {
      smb2Servers.add(serverIp);
    }
  }

  // Report confirmed SMBv1 traffic
  for (const [ip, count] of smb1Servers) {
    findings.push({
      id: nextId(),
      title: "SMBv1 Traffic Detected — EternalBlue Vulnerable Protocol",
      severity: Severity.High,
      description: `SMBv1 traffic confirmed to ${ip} (${count} packets). The SMB protocol magic bytes (\\xFFSMB) identify this as SMBv1, which is vulnerable to the EternalBlue exploit (MS17-010 / CVE-2017-0144) used in the WannaCry and NotPetya ransomware attacks. SMBv1 also lacks encryption and has weaker authentication than SMBv2/v3. All modern systems should have SMBv1 disabled.`,
      recommendation: `1. Disable SMBv1 on all systems immediately.
2. On Windows: Set "SMB 1.0/CIFS Client" and "SMB 1.0/CIFS Server" to Disabled.
3. On Samba: Set "min protocol = SMB2" in smb.conf.
4. Apply MS17-010 security patch on all Windows systems.
5. Verify SMBv3 encryption is enabled where supported.
6. Block SMB ports (139, 445) at the network perimeter.`,
      evidence: `SMBv1 confirmed (\\xFFSMB magic) to server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.FileShare,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  // Report SMB servers where version could not be determined (no payload available)
  // but skip any already identified as SMBv2+
  const allSmbServers = new Map<string, number>();
  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SMB || !pkt.ip) continue;
    const ip = pkt.ip.dstIp;
    if (smb1Servers.has(ip) || smb2Servers.has(ip)) continue;
    allSmbServers.set(ip, (allSmbServers.get(ip) || 0) + 1);
  }

  for (const [ip, count] of allSmbServers) {
    findings.push({
      id: nextId(),
      title: "SMB Traffic Detected — Version Unknown",
      severity: Severity.Medium,
      description: `SMB traffic detected to ${ip} (${count} packets) but the SMB version could not be determined from the captured payload. If this is SMBv1, it is vulnerable to the EternalBlue exploit (MS17-010). Verify that SMBv1 is disabled and only SMBv2+ is in use.`,
      recommendation: `1. Verify SMBv1 is disabled on ${ip} — check server configuration.
2. On Windows: run "Get-SmbServerConfiguration" to check minimum SMB version.
3. On Samba: verify "min protocol = SMB2" in smb.conf.
4. Apply MS17-010 security patch on all Windows systems.
5. Block SMB ports (139, 445) at the network perimeter.`,
      evidence: `Server: ${ip}, packets: ${count}, version: could not determine from payload`,
      affectedIp: ip,
      category: FindingCategory.FileShare,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Kubernetes API server exposure — unauthenticated access to the
 * K8s API grants full cluster control.
 */
export function detectKubernetesExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const k8sEndpoints = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Kubernetes) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    k8sEndpoints.set(serverIp, (k8sEndpoints.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of k8sEndpoints) {
    findings.push({
      id: nextId(),
      title: "Kubernetes API Traffic Detected — Verify Authentication",
      severity: Severity.Critical,
      description: `Kubernetes API traffic detected to ${ip} (${count} packets). An unauthenticated Kubernetes API server allows full cluster takeover — attackers can read secrets, deploy malicious pods, access all cluster data, and pivot to the host node. The K8s API on port 6443 is a high-value target in cloud attacks.`,
      recommendation: `1. Ensure RBAC is enabled and properly configured on the cluster.
2. Disable anonymous authentication (--anonymous-auth=false).
3. Use TLS client certificates or OIDC tokens for API authentication.
4. Never expose the Kubernetes API directly to the internet — use a VPN or bastion host.
5. Audit all service accounts and their permissions.
6. Enable Kubernetes audit logging for all API requests.`,
      evidence: `Endpoint: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Container,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
