import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Parsed DNS question section
 */
interface DNSQuestion {
  name: string;
  type: number;
  class: number;
}

/**
 * Parse a DNS header + question section from a UDP payload.
 * Returns null if the payload is too small or malformed.
 */
function parseDNSQuestion(payload: ArrayBuffer): {
  id: number;
  isResponse: boolean;
  rcode: number;
  questionCount: number;
  answerCount: number;
  questions: DNSQuestion[];
} | null {
  if (!payload || payload.byteLength < 12) return null;

  const view = new DataView(payload);
  const id = view.getUint16(0, false);
  const flags = view.getUint16(2, false);
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;
  const questionCount = view.getUint16(4, false);
  const answerCount = view.getUint16(6, false);

  if (questionCount === 0 || questionCount > 50) return null;

  const questions: DNSQuestion[] = [];
  let offset = 12;

  for (let i = 0; i < Math.min(questionCount, 10); i++) {
    const nameResult = parseDNSName(view, offset, payload.byteLength);
    if (!nameResult) break;
    offset = nameResult.newOffset;

    if (offset + 4 > payload.byteLength) break;
    const qtype = view.getUint16(offset, false);
    const qclass = view.getUint16(offset + 2, false);
    offset += 4;

    questions.push({ name: nameResult.name, type: qtype, class: qclass });
  }

  return { id, isResponse, rcode, questionCount, answerCount, questions };
}

/**
 * Parse a DNS name from the packet, handling label pointers (compression).
 */
function parseDNSName(
  view: DataView,
  offset: number,
  maxLen: number
): { name: string; newOffset: number } | null {
  const labels: string[] = [];
  let pos = offset;
  let jumped = false;
  let jumpPos = -1;
  const visited = new Set<number>();

  while (pos < maxLen) {
    if (visited.has(pos)) return null; // Loop detection
    visited.add(pos);

    const len = view.getUint8(pos);

    // Pointer (compression): top 2 bits set
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= maxLen) return null;
      if (!jumped) jumpPos = pos + 2; // Return offset after the pointer
      jumped = true;
      pos = ((len & 0x3f) << 8) | view.getUint8(pos + 1);
      continue;
    }

    // Zero length = end of name
    if (len === 0) {
      pos++;
      break;
    }

    pos++;
    if (pos + len > maxLen) return null;

    let label = "";
    for (let i = 0; i < len; i++) {
      const ch = view.getUint8(pos + i);
      label += (ch >= 32 && ch <= 126) ? String.fromCharCode(ch) : "?";
    }
    labels.push(label);
    pos += len;
  }

  return {
    name: labels.join("."),
    newOffset: jumped ? jumpPos : pos,
  };
}

/**
 * Calculate Shannon entropy of a string.
 * Returns a value between 0 (no entropy) and ~8 (maximum for byte data).
 */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Detect high-entropy DNS query names — characteristic of DNS tunneling
 * or Domain Generation Algorithms (DGAs).
 * DNS tunneling encodes data in subdomain labels (e.g., a3f8b2c1d4e5.example.com).
 * DGAs produce seemingly random domain names for C2 communication.
 */
export function detectHighEntropyDNSNames(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DNS) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const parsed = parseDNSQuestion(pkt.appPayload);
    if (!parsed) continue;

    for (const q of parsed.questions) {
      // Split into labels and check the longest subdomain label
      const labels = q.name.split(".");
      for (const label of labels) {
        if (label.length < 8) continue; // Too short for meaningful entropy

        const entropy = shannonEntropy(label);

        // High entropy threshold: >3.5 bits/char for 8+ char labels
        // Normal domain labels rarely exceed 3.0
        if (entropy > 3.5) {
          const key = `${pkt.ip.srcIp}:${q.name}`;
          if (reported.has(key)) continue;
          reported.add(key);

          findings.push({
            id: nextId(),
            title: "High-Entropy DNS Query — Possible DNS Tunneling or DGA",
            severity: Severity.High,
            description: `DNS query from ${pkt.ip.srcIp} for "${q.name}" has a subdomain label with Shannon entropy of ${entropy.toFixed(2)} bits/char. High-entropy domain names are characteristic of DNS tunneling (where data is encoded in subdomain labels) or Domain Generation Algorithms used by malware for C2 communication. Normal domain labels rarely exceed 3.0 bits/char entropy.`,
            recommendation: `1. Investigate the source ${pkt.ip.srcIp} for DNS tunneling tools (iodine, dnscat2, dns2tcp).
2. Check for corresponding large DNS responses (TXT/CNAME records with encoded data).
3. Block DNS queries to the suspicious domain if not business-related.
4. Implement DNS filtering to block high-entropy or newly-registered domains.
5. Monitor the source host for other C2 indicators (beaconing, unusual ports).`,
            evidence: `Query: ${q.name}, entropy: ${entropy.toFixed(2)}, source: ${pkt.ip.srcIp}`,
            affectedIp: pkt.ip.srcIp,
            category: FindingCategory.DNS,
            timestamp: 0, // replaced with capture time by runAllRules
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Detect DNS responses with large TXT records — used for DNS tunneling
 * to exfiltrate data or receive C2 commands.
 */
export function detectDNSTunnelingTXT(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DNS) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    // Large DNS responses (>512 bytes for classic DNS, or >4096 for EDNS0)
    // are suspicious, especially TXT records which are the preferred tunneling type
    if (pkt.appPayload.byteLength > 512) {
      const parsed = parseDNSQuestion(pkt.appPayload);
      if (!parsed || !parsed.isResponse) continue;

      // Count how many questions are TXT type (type 16)
      const txtQuestions = parsed.questions.filter(q => q.type === 16);
      if (txtQuestions.length > 0) {
        findings.push({
          id: nextId(),
          title: "Large DNS TXT Response — Possible DNS Tunneling",
          severity: Severity.Medium,
          description: `Large DNS response (${pkt.appPayload.byteLength} bytes) with TXT record detected from ${pkt.ip.srcIp}. DNS TXT records are the preferred carrier for DNS tunneling because they can carry large amounts of base64/base32-encoded data per query. Each TXT record can hold up to 255 bytes, and EDNS0 allows responses up to 4096 bytes, making tunneling highly efficient.`,
          recommendation: `1. Investigate the queried domains for known DNS tunneling services.
2. Monitor the requesting client for unusual DNS volume or patterns.
3. Block large DNS TXT responses at the firewall if not required.
4. Implement DNS response size limits (reject EDNS0 if not needed).
5. Use DPI-based DNS tunneling detection tools.`,
          evidence: `Response size: ${pkt.appPayload.byteLength} bytes, source: ${pkt.ip.srcIp}`,
          affectedIp: pkt.ip.srcIp,
          category: FindingCategory.DNS,
          timestamp: 0, // replaced with capture time by runAllRules
        });
      }
    }
  }

  return findings;
}

/**
 * Detect excessive NXDOMAIN responses to a single client — indicates
 * DGA activity, stale bookmarks, or misconfigured applications.
 */
export function detectExcessiveNXDOMAINDeep(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const clientNxCount = new Map<string, { count: number; domains: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DNS) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const parsed = parseDNSQuestion(pkt.appPayload);
    if (!parsed || !parsed.isResponse) continue;

    if (parsed.rcode === 3) { // NXDOMAIN
      const clientIp = pkt.ip.dstIp; // Response goes TO the client
      const existing = clientNxCount.get(clientIp) || { count: 0, domains: new Set<string>() };
      existing.count++;
      for (const q of parsed.questions) {
        existing.domains.add(q.name);
      }
      clientNxCount.set(clientIp, existing);
    }
  }

  for (const [clientIp, data] of clientNxCount) {
    if (data.count >= 15) {
      findings.push({
        id: nextId(),
        title: "Excessive NXDOMAIN Responses — Possible DGA Activity",
        severity: Severity.High,
        description: `Client ${clientIp} received ${data.count} NXDOMAIN responses for ${data.domains.size} unique domains. A high NXDOMAIN rate is a strong indicator of Domain Generation Algorithm (DGA) activity, where malware generates many random domain names trying to reach its C2 server. It can also indicate misconfigured applications or stale DNS records.`,
        recommendation: `1. Investigate ${clientIp} for malware — run a full anti-malware scan.
2. Check the queried domains against known DGA domain lists.
3. Implement DNS sinkholing for known DGA families.
4. If legitimate, identify the application generating the queries and fix its configuration.
5. Consider deploying a DNS security solution with DGA detection.`,
        evidence: `Client: ${clientIp}, NXDOMAIN count: ${data.count}, unique domains: ${data.domains.size}, samples: ${Array.from(data.domains).slice(0, 5).join(", ")}`,
        affectedIp: clientIp,
        category: FindingCategory.DNS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Parse A record IPs from the DNS answer section.
 * Skips past the question section and reads answer resource records.
 */
function extractARecordIPs(
  view: DataView,
  questionCount: number,
  offset: number,
  maxLen: number
): string[] {
  const ips: string[] = [];

  // Skip past question section
  let pos = offset;
  for (let i = 0; i < questionCount && pos < maxLen; i++) {
    const nameResult = parseDNSName(view, pos, maxLen);
    if (!nameResult) return ips;
    pos = nameResult.newOffset;
    pos += 4; // QTYPE(2) + QCLASS(2)
  }

  // Parse answer records
  for (let i = 0; i < 50 && pos + 10 <= maxLen; i++) {
    // Skip owner name (may use compression)
    const nameResult = parseDNSName(view, pos, maxLen);
    if (!nameResult) break;
    pos = nameResult.newOffset;

    if (pos + 10 > maxLen) break;
    const rtype = view.getUint16(pos, false);
    // const rclass = view.getUint16(pos + 2, false);
    // const ttl = view.getUint32(pos + 4, false);
    const rdlength = view.getUint16(pos + 8, false);
    pos += 10;

    if (pos + rdlength > maxLen) break;

    // A record (type 1, class IN=1): 4 bytes = IP address
    if (rtype === 1 && rdlength === 4) {
      const ip = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
      ips.push(ip);
    }

    pos += rdlength;
  }

  return ips;
}

/**
 * Detect DNS fast-flux — same domain resolving to many different IP addresses
 * in a short time, characteristic of fast-flux botnets.
 */
export function detectDNSFastFlux(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track domain → set of resolved A record IPs
  const domainIPs = new Map<string, { ips: Set<string>; responseCount: number }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DNS) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const parsed = parseDNSQuestion(pkt.appPayload);
    if (!parsed || !parsed.isResponse) continue;
    if (parsed.rcode !== 0) continue; // Only successful responses

    const view = new DataView(pkt.appPayload);

    for (const q of parsed.questions) {
      const domain = q.name.toLowerCase();
      if (domain.length < 4 || domain === "localhost") continue;

      const existing = domainIPs.get(domain) || { ips: new Set<string>(), responseCount: 0 };
      existing.responseCount++;

      // Extract A record IPs from the answer section
      // offset 12 = start of DNS packet after header; question section starts there
      const aRecords = extractARecordIPs(view, parsed.questionCount, 12, pkt.appPayload.byteLength);
      for (const ip of aRecords) {
        existing.ips.add(ip);
      }

      domainIPs.set(domain, existing);
    }
  }

  // Flag domains with many distinct resolved IPs (fast-flux indicator)
  // A legitimate domain typically has 1-4 IPs; fast-flux uses 5+ rotating IPs
  for (const [domain, data] of domainIPs) {
    if (data.responseCount >= 10 && data.ips.size >= 5) {
      findings.push({
        id: nextId(),
        title: "Potential DNS Fast-Flux Domain",
        severity: Severity.Medium,
        description: `Domain "${domain}" resolved to ${data.ips.size} different IP addresses across ${data.responseCount} DNS responses. Fast-flux DNS is a technique used by botnets where the DNS A record for a domain changes rapidly (every few minutes), rotating through many different compromised host IPs. This makes it difficult to block the malicious server since the IP keeps changing.`,
        recommendation: `1. Investigate the domain "${domain}" — check WHOIS, registration date, and reputation.
2. Block the domain in DNS filtering if confirmed malicious.
3. Monitor clients querying this domain for signs of malware infection.
4. Check the domain against threat intelligence feeds.
5. Implement DNS response policy zones (RPZ) to sinkhole suspicious domains.`,
        evidence: `Domain: ${domain}, distinct IPs: ${data.ips.size}, responses: ${data.responseCount}, IPs: ${Array.from(data.ips).slice(0, 8).join(", ")}`,
        affectedIp: domain,
        category: FindingCategory.DNS,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
