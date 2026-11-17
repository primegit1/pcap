import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding, FlowRecord } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";
import { createFinding, formatUs, MAX_PACKET_REFS } from "../findings";

/* ------------------------------------------------------------------ */
/* Tunables                                                            */
/* ------------------------------------------------------------------ */

/** Sliding window used by scan and flood detection (microseconds). */
export const SCAN_WINDOW_US = 60 * 1_000_000;
/** Distinct destination ports one source must probe on one target inside the window. */
export const VERTICAL_SCAN_PORT_THRESHOLD = 20;
/** Distinct hosts one source must probe on the same port inside the window. */
export const HORIZONTAL_SCAN_HOST_THRESHOLD = 20;
/** UDP probes to ports at/above this are treated as ephemeral replies, not probes. */
const UDP_MAX_PROBE_PORT = 49152;

export const SYN_FLOOD_WINDOW_US = 10 * 1_000_000;
export const SYN_FLOOD_SYN_THRESHOLD = 100;
/** SYNs per SYN-ACK above which the target is considered not answering normally. */
export const SYN_FLOOD_UNANSWERED_RATIO = 10;

interface ProbeEvent {
  t: number;
  /** distinct-key (port for vertical scans, host for horizontal scans) */
  key: string | number;
  index: number;
}

interface WindowHit {
  distinct: number;
  startIdx: number;
  endIdx: number;
}

/**
 * Slide a time window over time-ordered events and return the window that contained the most
 * distinct keys. O(n).
 */
function bestWindow(events: ProbeEvent[], windowUs: number): WindowHit {
  events.sort((a, b) => a.t - b.t);
  const counts = new Map<string | number, number>();
  let left = 0;
  let best: WindowHit = { distinct: 0, startIdx: 0, endIdx: 0 };

  for (let right = 0; right < events.length; right++) {
    const e = events[right];
    counts.set(e.key, (counts.get(e.key) ?? 0) + 1);
    while (e.t - events[left].t > windowUs) {
      const k = events[left].key;
      const c = (counts.get(k) ?? 1) - 1;
      if (c <= 0) counts.delete(k);
      else counts.set(k, c);
      left++;
    }
    if (counts.size > best.distinct) {
      best = { distinct: counts.size, startIdx: left, endIdx: right };
    }
  }
  return best;
}

/**
 * Port scan detection.
 *
 * Only *probes* count: TCP packets with SYN set and ACK clear (connection attempts, never
 * replies), and UDP datagrams to non-ephemeral ports that the target never answered.
 * Counting replies (as an earlier version did) made a server answering a browser's parallel
 * connections look like it was "scanning" the client's ephemeral ports.
 *
 * Vertical: >= VERTICAL_SCAN_PORT_THRESHOLD distinct ports on one target within SCAN_WINDOW_US.
 * Horizontal: the same port on >= HORIZONTAL_SCAN_HOST_THRESHOLD distinct hosts within the window.
 *
 * Pass the TCP/UDP subset (PacketIndex.withPorts) for speed; any packet list works.
 */
export function detectPortScanning(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // UDP replies seen: "client|server|serverPort" means server:serverPort sent something to client.
  const udpAnswered = new Set<string>();
  for (const pkt of packets) {
    const t = pkt.transport;
    if (!pkt.ip || !t || !("srcPort" in t) || "syn" in t) continue;
    udpAnswered.add(`${pkt.ip.dstIp}|${pkt.ip.srcIp}|${t.srcPort}`);
  }

  const vertical = new Map<string, ProbeEvent[]>(); // "src>dst|proto" -> events keyed by port
  const horizontal = new Map<string, ProbeEvent[]>(); // "src|proto|port" -> events keyed by dst ip

  for (const pkt of packets) {
    const t = pkt.transport;
    if (!pkt.ip || !t || !("srcPort" in t)) continue;
    const { srcIp, dstIp } = pkt.ip;
    const isTcp = "syn" in t;
    const dstPort = t.dstPort;

    if (isTcp) {
      if (!(t.syn && !t.ack)) continue;
    } else {
      if (dstPort >= UDP_MAX_PROBE_PORT || dstPort === 0) continue;
      if (udpAnswered.has(`${srcIp}|${dstIp}|${dstPort}`)) continue;
    }
    const proto = isTcp ? "tcp" : "udp";

    const vKey = `${srcIp}>${dstIp}|${proto}`;
    let v = vertical.get(vKey);
    if (!v) vertical.set(vKey, (v = []));
    v.push({ t: pkt.timestampUs, key: dstPort, index: pkt.index });

    const hKey = `${srcIp}|${proto}|${dstPort}`;
    let h = horizontal.get(hKey);
    if (!h) horizontal.set(hKey, (h = []));
    h.push({ t: pkt.timestampUs, key: dstIp, index: pkt.index });
  }

  for (const [key, events] of vertical) {
    if (events.length < VERTICAL_SCAN_PORT_THRESHOLD) continue;
    const hit = bestWindow(events, SCAN_WINDOW_US);
    if (hit.distinct < VERTICAL_SCAN_PORT_THRESHOLD) continue;

    const [pair, proto] = key.split("|");
    const [srcIp, dstIp] = pair.split(">");
    const inWindow = events.slice(hit.startIdx, hit.endIdx + 1);
    const ports = [...new Set(inWindow.map((e) => e.key as number))].sort((a, b) => a - b);
    const first = inWindow[0].t;
    const last = inWindow[inWindow.length - 1].t;

    findings.push(
      createFinding({
        title: "Port Scan Activity Observed (Passive Detection)",
        severity: Severity.High,
        confidence: proto === "tcp" ? "high" : "medium",
        description: `${srcIp} probed ${hit.distinct} different ${proto.toUpperCase()} ports on ${dstIp} within ${Math.max(1, Math.round((last - first) / 1e6))}s. Probing many ports on one host in a short window is the signature of a port scan used to enumerate exposed services before an attack.`,
        recommendation: `1. Block or rate-limit ${srcIp} at the firewall if it is external.\n2. If ${srcIp} is internal, investigate the host for unauthorized scanning tools or compromise (it may be an approved vulnerability scanner).\n3. Review which of the probed ports are actually open on ${dstIp} and close unnecessary services.\n4. Enable IDS/IPS scan detection and alert on repeats.`,
        evidence: `Probed ${proto.toUpperCase()} ports (${ports.length}): ${ports.slice(0, 25).join(", ")}${ports.length > 25 ? ` … +${ports.length - 25} more` : ""} | window ${formatUs(first)} → ${formatUs(last)}`,
        affectedIp: dstIp,
        category: FindingCategory.Network,
        dedupKey: `scan-v|${srcIp}|${proto}`,
        packetIndices: inWindow.map((e) => e.index).slice(0, MAX_PACKET_REFS),
        firstSeenUs: first,
        lastSeenUs: last,
      })
    );
  }

  for (const [key, events] of horizontal) {
    if (events.length < HORIZONTAL_SCAN_HOST_THRESHOLD) continue;
    const hit = bestWindow(events, SCAN_WINDOW_US);
    if (hit.distinct < HORIZONTAL_SCAN_HOST_THRESHOLD) continue;

    const [srcIp, proto, port] = key.split("|");
    const inWindow = events.slice(hit.startIdx, hit.endIdx + 1);
    const hosts = [...new Set(inWindow.map((e) => e.key as string))];
    const first = inWindow[0].t;
    const last = inWindow[inWindow.length - 1].t;

    findings.push(
      createFinding({
        title: "Horizontal Port Sweep Observed (Passive Detection)",
        severity: Severity.High,
        confidence: proto === "tcp" ? "high" : "medium",
        description: `${srcIp} probed ${proto.toUpperCase()} port ${port} on ${hit.distinct} different hosts within ${Math.max(1, Math.round((last - first) / 1e6))}s. Sweeping one service across many hosts is typical of reconnaissance for a specific vulnerability (for example SMB/445 or RDP/3389) or of worm propagation.`,
        recommendation: `1. Investigate ${srcIp}: unexpected sweeping from an internal host often means malware or an unapproved scanner.\n2. Block or rate-limit the source at the perimeter if external.\n3. Make sure port ${port} is not exposed on hosts that do not need it, and that those that do are patched.\n4. Segment the network so one host cannot reach every other host on this port.`,
        evidence: `Targets (${hosts.length}): ${hosts.slice(0, 10).join(", ")}${hosts.length > 10 ? ` … +${hosts.length - 10} more` : ""} | port ${proto.toUpperCase()}/${port}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        dedupKey: `scan-h|${proto}|${port}`,
        packetIndices: inWindow.map((e) => e.index).slice(0, MAX_PACKET_REFS),
        firstSeenUs: first,
        lastSeenUs: last,
      })
    );
  }

  return findings;
}

/**
 * SYN flood detection.
 *
 * Counts SYNs per client→server:port inside a sliding window and compares with the SYN-ACKs the
 * server sent back (keyed in the opposite direction). A normal service answers almost every SYN,
 * so a high SYN rate with (almost) no SYN-ACKs is a flood. An earlier version looked for the
 * SYN-ACK on the client's side, never found one, and flagged any 100 SYNs in a capture.
 */
export function detectSYNFlood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  interface Ev {
    t: number;
    syn: boolean;
    index: number;
  }
  const byTarget = new Map<string, Ev[]>(); // "client>server:port"

  for (const pkt of packets) {
    const t = pkt.transport;
    if (!pkt.ip || !t || !("syn" in t) || !t.syn) continue;
    if (t.ack) {
      // SYN-ACK from server:srcPort → client
      const key = `${pkt.ip.dstIp}>${pkt.ip.srcIp}:${t.srcPort}`;
      let list = byTarget.get(key);
      if (!list) byTarget.set(key, (list = []));
      list.push({ t: pkt.timestampUs, syn: false, index: pkt.index });
    } else {
      const key = `${pkt.ip.srcIp}>${pkt.ip.dstIp}:${t.dstPort}`;
      let list = byTarget.get(key);
      if (!list) byTarget.set(key, (list = []));
      list.push({ t: pkt.timestampUs, syn: true, index: pkt.index });
    }
  }

  for (const [key, events] of byTarget) {
    events.sort((a, b) => a.t - b.t);
    let left = 0;
    let syns = 0;
    let acks = 0;
    let bestSyns = 0;
    let bestAcks = 0;
    let bestL = 0;
    let bestR = 0;

    for (let right = 0; right < events.length; right++) {
      if (events[right].syn) syns++;
      else acks++;
      while (events[right].t - events[left].t > SYN_FLOOD_WINDOW_US) {
        if (events[left].syn) syns--;
        else acks--;
        left++;
      }
      const unanswered = acks === 0 || syns / acks > SYN_FLOOD_UNANSWERED_RATIO;
      if (syns >= SYN_FLOOD_SYN_THRESHOLD && unanswered && syns > bestSyns) {
        bestSyns = syns;
        bestAcks = acks;
        bestL = left;
        bestR = right;
      }
    }
    if (bestSyns === 0) continue;

    const [clientIp, target] = key.split(">");
    const sep = target.lastIndexOf(":");
    const serverIp = target.slice(0, sep);
    const port = target.slice(sep + 1);
    const inWindow = events.slice(bestL, bestR + 1);
    const first = inWindow[0].t;
    const last = inWindow[inWindow.length - 1].t;

    findings.push(
      createFinding({
        title: "SYN Flood Pattern Observed (Passive Detection)",
        severity: Severity.High,
        confidence: bestAcks === 0 ? "high" : "medium",
        description: `${bestSyns} TCP SYN packets from ${clientIp} to ${serverIp}:${port} within ${SYN_FLOOD_WINDOW_US / 1e6}s, with only ${bestAcks} SYN-ACK replies. A high rate of connection attempts that the server does not complete is characteristic of a SYN flood (a denial-of-service attack that exhausts the server's half-open connection table).`,
        recommendation: `1. Enable SYN cookies on ${serverIp}.\n2. Rate-limit new connections per source at the firewall or load balancer.\n3. If ${clientIp} is external and unexpected, block it; if the source addresses are spoofed, work with the upstream provider.\n4. Check ${serverIp} for exhausted connection tables or service degradation.`,
        evidence: `SYN: ${bestSyns}, SYN-ACK: ${bestAcks} in ${SYN_FLOOD_WINDOW_US / 1e6}s window | ${formatUs(first)} → ${formatUs(last)}`,
        affectedIp: serverIp,
        category: FindingCategory.Network,
        dedupKey: `synflood|${clientIp}|${port}`,
        packetIndices: inWindow.filter((e) => e.syn).map((e) => e.index).slice(0, MAX_PACKET_REFS),
        firstSeenUs: first,
        lastSeenUs: last,
      })
    );
  }

  return findings;
}

/**
 * Detect large data transfers (>10MB in one flow). Direction is taken from the per-direction
 * byte counters: the endpoint that SENT most of the bytes is reported as the sender, so a
 * download is not mislabeled as the server "exfiltrating" to the client.
 */
export function detectLargeTransfer(flows: FlowRecord[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const threshold = 10 * 1024 * 1024; // 10MB

  for (const flow of flows) {
    if (flow.byteCount <= threshold) continue;

    const initiatorSends = flow.initiatorBytes >= flow.responderBytes;
    const sender = initiatorSends
      ? { ip: flow.srcIp, port: flow.srcPort, bytes: flow.initiatorBytes }
      : { ip: flow.dstIp, port: flow.dstPort, bytes: flow.responderBytes };
    const receiver = initiatorSends
      ? { ip: flow.dstIp, port: flow.dstPort }
      : { ip: flow.srcIp, port: flow.srcPort };
    const mb = (n: number) => (n / (1024 * 1024)).toFixed(1);

    findings.push(
      createFinding({
        title: "Large Data Transfer",
        severity: Severity.Medium,
        confidence: "low",
        description: `${sender.ip}:${sender.port} sent ${mb(sender.bytes)}MB to ${receiver.ip}:${receiver.port} (${mb(flow.byteCount)}MB total) over ${flow.appProtocol}. ${initiatorSends ? `The connection was opened by ${flow.srcIp}, so this is an upload from the initiator.` : `The connection was opened by ${flow.srcIp}, so this is a download by the initiator.`} Unusually large uploads can indicate data exfiltration, especially to an external IP or a cloud service not normally used by this host.`,
        recommendation: `1. Verify that ${receiver.ip} is a legitimate destination for this volume of data.\n2. Check whether ${sender.ip} shows signs of compromise (unusual processes, recent software installs).\n3. Review the data being transferred if possible (e.g., via DLP tools).\n4. Establish transfer baselines and alert on anomalies.\n5. Restrict outbound transfers with egress filtering where possible.`,
        evidence: `Protocol: ${flow.appProtocol}, total: ${flow.byteCount.toLocaleString()} B (initiator→responder ${flow.initiatorBytes.toLocaleString()} B, responder→initiator ${flow.responderBytes.toLocaleString()} B), packets: ${flow.packetCount}`,
        affectedIp: sender.ip,
        category: FindingCategory.Network,
        dedupKey: flow.id,
        flowIds: [flow.id],
        firstSeenUs: flow.startTimeUs,
        lastSeenUs: flow.endTimeUs,
      })
    );
  }

  return findings;
}

/**
 * Detect ICMP flood: 50+ ICMP packets from the same source to the same destination.
 */
export function detectICMPFlood(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const groups = new Map<string, Packet[]>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ICMP) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("type" in pkt.transport)) continue;

    const key = `${pkt.ip.srcIp}→${pkt.ip.dstIp}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = []));
    g.push(pkt);
  }

  for (const [key, group] of groups) {
    if (group.length < 50) continue;
    const [srcIp, dstIp] = key.split("→");
    findings.push(
      createFinding({
        title: "ICMP Flood Pattern Observed (Passive Detection)",
        severity: Severity.Medium,
        description: `${group.length} ICMP packets sent from ${srcIp} to ${dstIp}. A high volume of ICMP traffic may indicate a flood attack (aimed at consuming bandwidth or CPU) or a ping sweep for host discovery. ICMP floods can degrade network performance for legitimate users.`,
        recommendation: `1. Block ICMP from ${srcIp} at the firewall if external.\n2. If ${srcIp} is internal, investigate the host for malware.\n3. Consider rate-limiting ICMP traffic at the network perimeter.\n4. Use monitoring tools to distinguish between legitimate network testing and malicious activity.`,
        evidence: `ICMP packets: ${group.length}`,
        affectedIp: dstIp,
        category: FindingCategory.Network,
        dedupKey: `icmpflood|${srcIp}`,
        packetIndices: group.map((p) => p.index).slice(0, MAX_PACKET_REFS),
        firstSeenUs: group[0].timestampUs,
        lastSeenUs: group[group.length - 1].timestampUs,
      })
    );
  }

  return findings;
}

/**
 * Detect ping sweep: same source IP sending ICMP Echo Requests to 5+ different destination IPs.
 */
export function detectPingSweep(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const sweeperMap = new Map<string, { targets: Set<string>; pkts: Packet[] }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.ICMP) continue;
    if (!pkt.ip || !pkt.transport) continue;
    if (!("type" in pkt.transport)) continue;
    if (pkt.transport.type !== 8) continue; // Echo Request only

    let entry = sweeperMap.get(pkt.ip.srcIp);
    if (!entry) sweeperMap.set(pkt.ip.srcIp, (entry = { targets: new Set(), pkts: [] }));
    entry.targets.add(pkt.ip.dstIp);
    entry.pkts.push(pkt);
  }

  for (const [srcIp, { targets, pkts }] of sweeperMap) {
    if (targets.size < 5) continue;
    findings.push(
      createFinding({
        title: "ICMP Ping Sweep Observed (Passive Detection)",
        severity: Severity.Medium,
        description: `${srcIp} sent ICMP Echo Requests to ${targets.size} different hosts. A ping sweep is a reconnaissance technique used to map live hosts on a network before launching targeted attacks. The diversity of targets suggests active network discovery.`,
        recommendation: `1. Block ICMP echo requests from ${srcIp} if external.\n2. If ${srcIp} is internal, investigate the host for unauthorized scanning tools.\n3. Consider disabling ICMP echo response on critical servers if not required.\n4. Monitor for additional reconnaissance activity from the same source.`,
        evidence: `Targets: ${Array.from(targets).slice(0, 10).join(", ")}${targets.size > 10 ? `... and ${targets.size - 10} more` : ""}`,
        affectedIp: srcIp,
        category: FindingCategory.Network,
        dedupKey: `pingsweep|${srcIp}`,
        packetIndices: pkts.map((p) => p.index).slice(0, MAX_PACKET_REFS),
        firstSeenUs: pkts[0].timestampUs,
        lastSeenUs: pkts[pkts.length - 1].timestampUs,
      })
    );
  }

  return findings;
}
