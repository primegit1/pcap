import { Protocol } from "../../types/packets";
import type { SecurityFinding, FlowRecord } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import type { Packet } from "../../types/packets";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect TLS/HTTPS connections and flag weak versions.
 * For MVP, we flag HTTPS connections (which implies TLS usage).
 * Full TLS version detection requires deep packet inspection of the
 * TLS ClientHello/ServerHello.
 */
export function detectWeakTLS(
  flows: FlowRecord[]
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const flow of flows) {
    if (flow.appProtocol !== Protocol.HTTPS) continue;

    // For MVP: flag HTTPS on unusual ports as potentially weak
    if (flow.dstPort !== 443) {
      findings.push({
        id: nextId(),
        title: "TLS Service on Non-Standard Port",
        severity: Severity.Low,
        description: `TLS/HTTPS traffic detected on port ${flow.dstPort} (not 443) between ${flow.srcIp} and ${flow.dstIp}. Running TLS services on non-standard ports can be used to bypass security controls or hide services. While sometimes legitimate (e.g., development servers), it warrants verification.`,
        recommendation: `1. Verify the service running on ${flow.dstIp}:${flow.dstPort} is authorized.
2. Ensure any legitimate services on non-standard ports use current TLS versions (1.2+).
3. Review firewall rules to confirm this port should be open.
4. If unauthorized, investigate for potential shadow IT or hidden services.`,
        evidence: `Source: ${flow.srcIp}:${flow.srcPort} → ${flow.dstIp}:${flow.dstPort}`,
        affectedIp: flow.dstIp,
        category: FindingCategory.TLS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/* ───────── JA4 TLS Fingerprinting ───────── */

/**
 * Compute a simplified JA4 fingerprint from a TLS ClientHello payload.
 *
 * JA4 components:
 *   tls_protocol (e.g. "t13" for TLS 1.3, "t12" for TLS 1.2)
 *   sni (e.g. "d" if domain-like SNI, "i" if IP, "0" if absent)
 *   ciphers_hash (2-char hex hash of sorted cipher suite list)
 *   extensions_hash (2-char hex hash of sorted extension list)
 *
 * Full JA4 spec: protocol_sni_count_ciphers_extensions
 * We produce a simplified hash for display and anomaly detection.
 */
export interface JA4Result {
  /** Full JA4 fingerprint string */
  fingerprint: string;
  /** TLS version string, e.g. "TLS 1.3" */
  version: string;
  /** SNI hostname if present */
  sni: string | null;
  /** Whether this is a known-weak version (TLS < 1.2) */
  isWeak: boolean;
  /** Number of cipher suites offered */
  cipherCount: number;
  /** Number of extensions */
  extensionCount: number;
}

/**
 * Parse a TLS ClientHello and extract JA4 fingerprint data.
 * Only processes the first ClientHello handshake message in a payload.
 */
export function parseTLSClientHello(payload: ArrayBuffer): JA4Result | null {
  if (payload.byteLength < 6) return null;
  const view = new Uint8Array(payload);

  // TLS record header: content_type(1) + version(2) + length(2)
  const contentType = view[0];
  if (contentType !== 22) return null; // Not handshake

  const majorVer = view[1];
  const minorVer = view[2];

  // Map TLS version
  let versionLabel: string;
  let protocolTag: string;
  let isWeak = false;
  if (majorVer === 0x03 && minorVer === 0x04) {
    versionLabel = "TLS 1.3";
    protocolTag = "t13";
  } else if (majorVer === 0x03 && minorVer === 0x03) {
    versionLabel = "TLS 1.2";
    protocolTag = "t12";
  } else if (majorVer === 0x03 && minorVer === 0x02) {
    versionLabel = "TLS 1.1";
    protocolTag = "t11";
    isWeak = true;
  } else if (majorVer === 0x03 && minorVer === 0x01) {
    versionLabel = "TLS 1.0";
    protocolTag = "t10";
    isWeak = true;
  } else if (majorVer === 0x03 && minorVer === 0x00) {
    versionLabel = "SSL 3.0";
    protocolTag = "s30";
    isWeak = true;
  } else {
    versionLabel = `TLS ${majorVer}.${minorVer}`;
    protocolTag = `t${majorVer.toString(16)}${minorVer.toString(16)}`;
  }

  // Find handshake: at offset 5 (after record header + handshake header)
  if (payload.byteLength < 44) return null;
  const handshakeType = view[5];
  if (handshakeType !== 1) return null; // Not ClientHello

  // Handshake body length: bytes 6-8 (3 bytes)
  const hsLen = (view[6] << 16) | (view[7] << 8) | view[8];
  if (5 + hsLen > payload.byteLength) return null;

  let pos = 9; // After handshake header

  // Client Version (2 bytes)
  if (pos + 2 > payload.byteLength) return null;
  const clientMajor = view[pos];
  const clientMinor = view[pos + 1];
  pos += 2;

  // If client version is TLS 1.3 (0x0304) or higher client, record says TLS 1.2 (0x0303)
  // for backwards compat — use the higher of client and record versions
  if (clientMajor === 0x03 && clientMinor >= 0x04) {
    versionLabel = "TLS 1.3";
    protocolTag = "t13";
    isWeak = false;
  }

  // Random (32 bytes)
  if (pos + 32 > payload.byteLength) return null;
  pos += 32;

  // Session ID
  if (pos >= payload.byteLength) return null;
  const sessionIdLen = view[pos];
  pos += 1 + sessionIdLen;

  // Cipher Suites
  if (pos + 2 > payload.byteLength) return null;
  const cipherLen = view[pos] << 8 | view[pos + 1];
  pos += 2;
  if (pos + cipherLen > payload.byteLength) return null;

  const cipherCount = cipherLen / 2;
  // Read cipher IDs for hashing
  const cipherIds: number[] = [];
  for (let i = 0; i < cipherLen; i += 2) {
    cipherIds.push((view[pos + i] << 8) | view[pos + i + 1]);
  }
  pos += cipherLen;

  // Compression methods
  if (pos >= payload.byteLength) return null;
  const comprLen = view[pos];
  pos += 1 + comprLen;

  // Extensions
  const exts: number[] = [];
  let extensionCount: number;
  if (pos + 2 <= payload.byteLength) {
    const extLen = (view[pos] << 8) | view[pos + 1];
    pos += 2;
    const extEnd = Math.min(pos + extLen, payload.byteLength);
    extensionCount = 0;

    let sni: string | null = null;

    while (pos + 4 <= extEnd) {
      const extType = (view[pos] << 8) | view[pos + 1];
      const extDataLen = (view[pos + 2] << 8) | view[pos + 3];
      exts.push(extType);
      extensionCount++;

      // SNI extension (0)
      if (extType === 0x0000 && sni === null && pos + 7 + extDataLen <= extEnd) {
        // ServerNameList: length(2) + ServerNameType(1) + length(2) + name
        const listLen = (view[pos + 4] << 8) | view[pos + 5];
        if (listLen > 0 && pos + 6 < extEnd) {
          const nameType = view[pos + 6];
          const nameLen = (view[pos + 7] << 8) | view[pos + 8];
          if (nameType === 0x00 && nameLen > 0 && pos + 9 + nameLen <= extEnd) {
            sni = String.fromCharCode(...Array.from(view.slice(pos + 9, pos + 9 + nameLen)));
          }
        }
      }

      pos += 4 + extDataLen;
    }

    // Build SNI tag
    let sniTag = "0";
    if (sni) {
      sniTag = /^[\d.]+$/.test(sni) ? "i" : "d";
    }

    // Hash cipher suites (simple DJB2 hash, first 12 bits → 3 hex chars)
    const cipherHash = hash12bit(cipherIds);
    // Hash extension types
    const extHash = hash12bit(exts);

    // JA4 fingerprint: protocol + sni + count + ciphers + exts
    const fingerprint = `${protocolTag}${sniTag}${cipherCount.toString(16).slice(0, 2)}${cipherHash}_${extHash}`;

    return {
      fingerprint,
      version: versionLabel,
      sni,
      isWeak,
      cipherCount,
      extensionCount,
    };
  }

  return null;
}

/**
 * DJB2 12-bit hash for JA4 fingerprinting.
 */
function hash12bit(values: number[]): string {
  let hash = 5381;
  for (const v of values) {
    hash = ((hash << 5) + hash + v) & 0xffffffff;
  }
  return (hash & 0xfff).toString(16).padStart(3, "0");
}

/**
 * Detect TSL ClientHellos with weak TLS versions (< 1.2) or unusual fingerprints.
 */
export function detectTLSFingerprints(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const fingerprints = new Map<string, { count: number; version: string; sni: string | null; isWeak: boolean }>();
  const weakIPs = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTPS) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 6) continue;

    const ja4 = parseTLSClientHello(pkt.appPayload);
    if (!ja4) continue;

    const fp = ja4.fingerprint;
    const existing = fingerprints.get(fp);
    if (existing) {
      existing.count++;
    } else {
      fingerprints.set(fp, {
        count: 1,
        version: ja4.version,
        sni: ja4.sni,
        isWeak: ja4.isWeak,
      });
    }

    // Flag weak TLS versions
    if (ja4.isWeak) {
      const key = `${pkt.ip.srcIp} → ${pkt.ip.dstIp}`;
      weakIPs.add(key);
    }
  }

  // Report weak TLS version usage
  for (const ipPair of weakIPs) {
    findings.push({
      id: nextId(),
      title: "Weak TLS Version Detected (TLS < 1.2)",
      severity: Severity.High,
      description: `A TLS ClientHello with a version below TLS 1.2 was observed in connection ${ipPair}. TLS 1.0 and 1.1 are deprecated by IETF (RFC 8996) and contain known vulnerabilities including BEAST, Lucky13, and POODLE. Their use indicates outdated or misconfigured SSL/TLS stacks.`,
      recommendation: `1. Upgrade the TLS library/stack offering weak versions to TLS 1.2+.
2. Disable TLS 1.0 and 1.1 in server configuration.
3. Audit all services using the deprecated TLS client to identify outdated systems.
4. Replace any legacy applications that cannot support TLS 1.2+.
5. Configure servers to require minimum TLS 1.2.`,
      evidence: `Connection: ${ipPair}`,
      affectedIp: ipPair.split(" → ")[1],
      category: FindingCategory.TLS,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  // Report unique fingerprints (for fingerprinting awareness)
  let foundCount = 0;
  for (const [fp, data] of fingerprints) {
    if (data.count === 1 && data.sni && foundCount < 5) {
      foundCount++;
      findings.push({
        id: nextId(),
        title: "Unique TLS Fingerprint — Potential Custom Client",
        severity: Severity.Info,
        description: `A unique TLS ClientHello fingerprint was observed to ${data.sni} (JA4: ${fp}). Single-occurrence fingerprints can indicate custom-built clients, malware beaconing, or specialized tools that differ from standard browser TLS stacks.`,
        recommendation: `1. Investigate the source traffic to ${data.sni} — determine the tool or software generating it.
2. Compare the fingerprint against known JA4 databases of malware and legitimate tools.
3. If the destination is unexpected, block and monitor for C2 beaconing patterns.
4. Maintain a baseline of acceptable TLS fingerprints for your environment.`,
        evidence: `JA4: ${fp}, SNI: ${data.sni}, Version: ${data.version}`,
        affectedIp: data.sni,
        category: FindingCategory.TLS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
