import type { Packet } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { createFinding, formatUs, MAX_PACKET_REFS } from "../findings";

/* ------------------------------------------------------------------ */
/* Tunables                                                            */
/* ------------------------------------------------------------------ */

/** Minimum connections/datagrams before timing is judged. */
export const BEACON_MIN_EVENTS = 10;
/** Coefficient of variation (stdev / mean) of intervals below which timing is "too regular". */
export const BEACON_MAX_INTERVAL_CV = 0.2;
export const BEACON_MIN_INTERVAL_S = 5;
export const BEACON_MAX_INTERVAL_S = 3600;
/** Events closer together than this are one burst (SYN retransmits, double-sends). */
const BURST_MERGE_US = 1_000_000;

/**
 * Destination ports whose clients legitimately talk on a timer. Excluded so NTP polling,
 * DHCP renewals, mDNS/SSDP/NetBIOS/LLMNR chatter and similar don't read as C2.
 */
export const BEACON_ALLOWLIST_PORTS = new Set<number>([
  67, 68, // DHCP
  123, // NTP
  137, 138, // NetBIOS name/datagram
  161, 162, // SNMP polling
  546, 547, // DHCPv6
  1900, // SSDP
  5353, // mDNS
  5355, // LLMNR
]);

interface Series {
  times: number[];
  indices: number[];
  /** First client payload size per connection (TCP) or datagram size (UDP) */
  sizes: number[];
}

function stats(values: number[]): { mean: number; stdev: number; cv: number } {
  const n = values.length;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
  const stdev = Math.sqrt(variance);
  return { mean, stdev, cv: mean > 0 ? stdev / mean : Infinity };
}

/**
 * Detect command-and-control style beaconing: a host contacting the same destination service at
 * suspiciously regular intervals.
 *
 * Events are TCP connection starts (SYN without ACK) and UDP datagrams to non-allowlisted ports.
 * Regularity is the coefficient of variation of the inter-event gaps, which tolerates the
 * 10-30% jitter most implants add. Randomly timed human traffic has a CV near 1.
 */
export function detectBeaconing(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const series = new Map<string, Series>();
  /** TCP: srcPort → recorded already? (so only the first client payload per connection counts) */
  const payloadSeen = new Set<string>();

  for (const pkt of packets) {
    const t = pkt.transport;
    if (!pkt.ip || !t || !("srcPort" in t)) continue;
    const isTcp = "syn" in t;
    if (BEACON_ALLOWLIST_PORTS.has(t.dstPort)) continue;

    if (isTcp) {
      const key = `tcp|${pkt.ip.srcIp}|${pkt.ip.dstIp}|${t.dstPort}`;
      if (t.syn && !t.ack) {
        let s = series.get(key);
        if (!s) series.set(key, (s = { times: [], indices: [], sizes: [] }));
        s.times.push(pkt.timestampUs);
        s.indices.push(pkt.index);
      } else if (pkt.appPayload && pkt.appPayload.byteLength > 0 && !t.syn) {
        const connKey = `${key}|${t.srcPort}`;
        if (!payloadSeen.has(connKey)) {
          payloadSeen.add(connKey);
          series.get(key)?.sizes.push(pkt.appPayload.byteLength);
        }
      }
    } else {
      const key = `udp|${pkt.ip.srcIp}|${pkt.ip.dstIp}|${t.dstPort}`;
      let s = series.get(key);
      if (!s) series.set(key, (s = { times: [], indices: [], sizes: [] }));
      s.times.push(pkt.timestampUs);
      s.indices.push(pkt.index);
      s.sizes.push(pkt.appPayload?.byteLength ?? 0);
    }
  }

  for (const [key, s] of series) {
    if (s.times.length < BEACON_MIN_EVENTS) continue;

    // Order events, then collapse bursts.
    const order = s.times.map((_, i) => i).sort((a, b) => s.times[a] - s.times[b]);
    const times: number[] = [];
    const indices: number[] = [];
    for (const i of order) {
      const t = s.times[i];
      if (times.length > 0 && t - times[times.length - 1] < BURST_MERGE_US) continue;
      times.push(t);
      indices.push(s.indices[i]);
    }
    if (times.length < BEACON_MIN_EVENTS) continue;

    const gaps: number[] = [];
    for (let i = 1; i < times.length; i++) gaps.push((times[i] - times[i - 1]) / 1e6);
    const g = stats(gaps);
    if (g.mean < BEACON_MIN_INTERVAL_S || g.mean > BEACON_MAX_INTERVAL_S) continue;
    if (g.cv >= BEACON_MAX_INTERVAL_CV) continue;

    const sizeStats = s.sizes.length >= BEACON_MIN_EVENTS ? stats(s.sizes) : null;
    const sizesRegular = sizeStats !== null && sizeStats.cv < 0.1;
    const [proto, srcIp, dstIp, port] = key.split("|");

    const confidence =
      times.length >= 20 && g.cv < 0.1 && sizesRegular
        ? "high"
        : times.length >= 20 || sizesRegular
          ? "medium"
          : "low";

    findings.push(
      createFinding({
        title: "Possible C2 Beaconing (Regular Callback Interval)",
        severity: Severity.Medium,
        confidence,
        description: `${srcIp} contacted ${dstIp}:${port}/${proto.toUpperCase()} ${times.length} times at a very regular interval (about every ${g.mean.toFixed(g.mean < 100 ? 1 : 0)}s, variation ${(g.cv * 100).toFixed(1)}%). Automated callbacks on a fixed timer are how many malware implants check in with a command-and-control server, although legitimate software (monitoring agents, update checkers, keep-alives) behaves the same way.`,
        recommendation: `1. Identify the process on ${srcIp} that opens connections to ${dstIp}:${port} and confirm it is expected.\n2. Check the reputation and ownership of ${dstIp} (threat-intelligence, WHOIS, passive DNS).\n3. Inspect the payloads or TLS SNI/JA3 of these connections for known C2 frameworks.\n4. If it is unexpected, isolate ${srcIp} and begin incident response; block ${dstIp} at the egress firewall.\n5. If it is legitimate, document it so it can be allowlisted.`,
        evidence: `${times.length} events, mean interval ${g.mean.toFixed(2)}s, stdev ${g.stdev.toFixed(2)}s, CV ${g.cv.toFixed(3)}${
          sizeStats
            ? `; payload size mean ${sizeStats.mean.toFixed(0)}B CV ${sizeStats.cv.toFixed(3)}`
            : ""
        } | ${formatUs(times[0])} → ${formatUs(times[times.length - 1])}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        dedupKey: `beacon|${proto}|${dstIp}|${port}`,
        packetIndices: indices.slice(0, MAX_PACKET_REFS),
        firstSeenUs: times[0],
        lastSeenUs: times[times.length - 1],
      })
    );
  }

  return findings;
}
