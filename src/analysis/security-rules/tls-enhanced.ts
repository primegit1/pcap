import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { parseTLSClientHello, JA4Result } from "./tls";

import { nextFindingId as nextId } from "../findings";

/**
 * Parsed TLS ServerHello response data
 */
interface TLSServerHelloResult {
  version: string;
  protocolTag: string;
  isWeak: boolean;
  cipherSuite: number;
  cipherName: string;
  selectedCompression: number;
  serverName: string | null;
}

/**
 * Known cipher suite IDs and their security status.
 * Only listing weak/deprecated ones for detection purposes.
 */
const WEAK_CIPHER_SUITES: Map<number, string> = new Map([
  // RC4
  [0x0005, "TLS_RSA_WITH_RC4_128_SHA"],
  [0x0004, "TLS_RSA_WITH_RC4_128_MD5"],
  [0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"],
  [0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"],
  // NULL ciphers
  [0x0001, "TLS_RSA_WITH_NULL_MD5"],
  [0x0002, "TLS_RSA_WITH_NULL_SHA"],
  [0x003B, "TLS_RSA_WITH_NULL_SHA256"],
  [0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"],
  [0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"],
  [0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA"],
  [0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"],
  // Export-grade (FREAK attack)
  [0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
  [0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"],
  [0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
  [0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"],
  // DES
  [0x0009, "TLS_RSA_WITH_DES_CBC_SHA"],
  [0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"],
  // 3DES (SWEET32)
  [0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
  [0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"],
  [0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"],
  [0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"],
]);

/**
 * Map cipher suite ID to a human-readable name.
 */
function getCipherName(id: number): string {
  return WEAK_CIPHER_SUITES.get(id) || `Cipher-0x${id.toString(16).padStart(4, "0")}`;
}

/**
 * Parse a TLS ServerHello from a payload.
 * ServerHello is handshake type 2, within a TLS record.
 */
export function parseTLSServerHello(payload: ArrayBuffer): TLSServerHelloResult | null {
  if (!payload || payload.byteLength < 6) return null;
  const view = new Uint8Array(payload);

  // TLS record header: content_type(1) + version(2) + length(2)
  const contentType = view[0];
  if (contentType !== 22) return null; // Not handshake

  // Skip to handshake message
  if (payload.byteLength < 44) return null;
  const handshakeType = view[5];
  if (handshakeType !== 2) return null; // Not ServerHello

  // Handshake body length
  const hsLen = (view[6] << 16) | (view[7] << 8) | view[8];
  if (5 + hsLen > payload.byteLength) return null;

  let pos = 9;

  // Server Version (2 bytes)
  if (pos + 2 > payload.byteLength) return null;
  const majorVer = view[pos];
  const minorVer = view[pos + 1];
  pos += 2;

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

  // Random (32 bytes)
  if (pos + 32 > payload.byteLength) return null;
  pos += 32;

  // Session ID
  if (pos >= payload.byteLength) return null;
  const sessionIdLen = view[pos];
  pos += 1 + sessionIdLen;

  // Cipher Suite (2 bytes)
  if (pos + 2 > payload.byteLength) return null;
  const cipherSuite = (view[pos] << 8) | view[pos + 1];
  pos += 2;

  // Compression method (1 byte)
  if (pos >= payload.byteLength) return null;
  const compression = view[pos];

  // Check if the selected cipher is weak
  if (WEAK_CIPHER_SUITES.has(cipherSuite)) {
    isWeak = true;
  }

  // Try to parse extensions for SNI (not in ServerHello, but we look for ALPN etc.)
  const serverName: string | null = null;
  // Note: ServerHello doesn't contain SNI extension; it's in ClientHello.
  // We'll leave this null for ServerHello.

  return {
    version: versionLabel,
    protocolTag,
    isWeak,
    cipherSuite,
    cipherName: getCipherName(cipherSuite),
    selectedCompression: compression,
    serverName,
  };
}

/**
 * Detect TLS downgrade attacks — client offers TLS 1.2+ but server
 * negotiates a lower version.
 */
export function detectTLSDowngrade(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track ClientHello versions by source IP + destination
  const clientOffers = new Map<string, JA4Result>();
  const serverResponds = new Map<string, TLSServerHelloResult>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTPS) continue;
    if (!pkt.ip || !pkt.appPayload || pkt.appPayload.byteLength < 6) continue;

    const key = `${pkt.ip.srcIp}→${pkt.ip.dstIp}`;

    // Try ClientHello first
    const clientHello = parseTLSClientHello(pkt.appPayload);
    if (clientHello) {
      clientOffers.set(key, clientHello);
      continue;
    }

    // Try ServerHello
    const serverHello = parseTLSServerHello(pkt.appPayload);
    if (serverHello) {
      serverResponds.set(key, serverHello);
    }
  }

  // Cross-reference: check for downgrades
  for (const [key, serverResp] of serverResponds) {
    // Reverse the key to find the client hello
    const [serverIp, clientPart] = key.split("→");
    const reverseKey = `${clientPart}→${serverIp}`;

    const clientOffer = clientOffers.get(reverseKey);
    if (!clientOffer) continue;

    // Check if server negotiated a lower version than client offered
    if (serverResp.isWeak && !clientOffer.isWeak) {
      findings.push({
        id: nextId(),
        title: "TLS Downgrade Detected — Server Negotiated Weak Version",
        severity: Severity.Critical,
        description: `TLS downgrade detected between ${clientPart} and ${serverIp}: client offered ${clientOffer.version} but server negotiated ${serverResp.version}. A TLS downgrade attack (POODLE, FREAK, Logjam) forces the use of a weaker protocol version to exploit known vulnerabilities. This can also occur if the server is misconfigured with outdated TLS support.`,
        recommendation: `1. Disable TLS 1.0 and 1.1 on the server ${serverIp}.
2. Set the minimum TLS version to 1.2 on all servers.
3. Investigate whether a man-in-the-middle is forcing the downgrade.
4. Check server cipher suite configuration — remove weak ciphers.
5. Enable HSTS to prevent protocol downgrade in browsers.
6. Audit the TLS configuration using tools like SSL Labs (ssllabs.com).`,
        evidence: `Client offered: ${clientOffer.version}, Server negotiated: ${serverResp.version}, cipher: ${serverResp.cipherName}`,
        affectedIp: serverIp,
        category: FindingCategory.TLS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect weak cipher suites negotiated in TLS ServerHello.
 */
export function detectWeakTLSCiphers(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTPS) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const serverHello = parseTLSServerHello(pkt.appPayload);
    if (!serverHello) continue;

    if (WEAK_CIPHER_SUITES.has(serverHello.cipherSuite)) {
      const key = `${pkt.ip.srcIp}:${serverHello.cipherSuite}`;
      if (reported.has(key)) continue;
      reported.add(key);

      findings.push({
        id: nextId(),
        title: `Weak TLS Cipher Suite Negotiated: ${serverHello.cipherName}`,
        severity: Severity.High,
        description: `TLS connection from ${pkt.ip.srcIp} negotiated weak cipher suite "${serverHello.cipherName}" (${serverHello.version}). This cipher is known to be vulnerable: RC4 is biased (RFC 7465), NULL ciphers provide no encryption, export-grade ciphers are breakable (FREAK attack), DES/3DES is vulnerable to SWEET32 birthday attacks. These ciphers should be disabled on all servers.`,
        recommendation: `1. Remove the cipher suite "${serverHello.cipherName}" from the server's TLS configuration.
2. Configure the server to prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).
3. Set a minimum of TLS 1.2 with strong cipher suites only.
4. Test the server configuration using SSL Labs or testssl.sh.
5. Audit all TLS-enabled services for weak cipher support.`,
        evidence: `Cipher: ${serverHello.cipherName} (0x${serverHello.cipherSuite.toString(16)}), version: ${serverHello.version}`,
        affectedIp: pkt.ip.srcIp,
        category: FindingCategory.TLS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
