import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Parse a single ASN.1/BER TLV (Tag-Length-Value) from a buffer.
 * Minimal inline version for the security rule (avoids cross-module dependency).
 */
function parseBER(
  buf: Uint8Array,
  offset: number
): { tag: number; length: number; value: Uint8Array; consumed: number } | null {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  let pos = offset + 1;
  if (pos >= buf.length) return null;
  let len = buf[pos];
  pos++;
  if (len > 0x7f) {
    const numOctets = len & 0x7f;
    if (numOctets === 0 || numOctets > 4) return null;
    len = 0;
    for (let i = 0; i < numOctets; i++) {
      if (pos >= buf.length) return null;
      len = (len << 8) | buf[pos];
      pos++;
    }
  }
  if (pos + len > buf.length) return null;
  const value = buf.slice(pos, pos + len);
  return { tag, length: len, value, consumed: pos + len - offset };
}

/**
 * Try to extract the SNMP community string from a packet payload.
 */
function extractCommunity(payload: ArrayBuffer): string | null {
  if (payload.byteLength < 6) return null;
  const view = new Uint8Array(payload);

  const seq = parseBER(view, 0);
  if (!seq || seq.tag !== 0x30) return null;

  const ver = parseBER(seq.value, 0);
  if (!ver || ver.tag !== 0x02) return null;
  const version = ver.value[0] ?? 0;
  if (version >= 3) return null; // v3 is encrypted

  const pos = ver.consumed;
  const comm = parseBER(seq.value, pos);
  if (!comm || comm.tag !== 0x04) return null;

  return String.fromCharCode(...comm.value);
}

/**
 * Detect SNMPv1/v2c packets using default/weak community strings.
 * Default "public" and "private" are well-known credentials that
 * should never be used in production.
 */
export function detectWeakSNMPCommunity(
  packets: Packet[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const weakCommunities = ["public", "private", "snmp", "manager", "admin"];

  // Track which IPs are using weak communities (deduplicate)
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.SNMP) continue;
    if (!pkt.appPayload) continue;

    const community = extractCommunity(pkt.appPayload);
    if (!community) continue;

    const key = `${pkt.ip?.srcIp ?? "?"}:${community}`;
    if (reported.has(key)) continue;
    reported.add(key);

    if (weakCommunities.includes(community.toLowerCase())) {
      findings.push({
        id: nextId(),
        title: "Weak SNMP Community String",
        severity: community.toLowerCase() === "public" ? Severity.High : Severity.Medium,
        description: `Device ${pkt.ip?.srcIp ?? "unknown"} is using SNMP with the default community string "${community}". SNMPv1/v2c transmits community strings in cleartext and provides no encryption or authentication. A weak community string exposes device configuration, performance metrics, and network topology to anyone with network access to UDP port 161.`,
        recommendation: `1. Change the SNMP community string from "${community}" to a strong, unique value immediately.
2. Migrate from SNMPv1/v2c to SNMPv3, which provides encryption and authentication.
3. Restrict SNMP access by IP address using access control lists (ACLs).
4. If SNMPv3 is not immediately possible, at minimum use a non-default community string.
5. Audit all network devices for default SNMP credentials.`,
        evidence: `SNMP community string: "${community}"`,
        affectedIp: pkt.ip?.srcIp ?? "unknown",
        category: FindingCategory.Auth,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}