import { Protocol } from "./packets";

/* ========== Flows ========== */

export interface FlowRecord {
  /** Stable flow key: "proto|initiatorIp|initiatorPort|responderIp|responderPort" */
  id: string;
  /** Initiator (client): the SYN sender for TCP, otherwise the first-seen sender */
  srcIp: string;
  /** Responder (server) */
  dstIp: string;
  /** Initiator port */
  srcPort: number;
  /** Responder port (the service port) */
  dstPort: number;
  /** IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.) */
  ipProtocol: number;
  /** Detected application protocol */
  appProtocol: Protocol;
  /** Total packets in both directions */
  packetCount: number;
  /** Total bytes in both directions */
  byteCount: number;
  /** Packets sent by the initiator (srcIp) */
  initiatorPackets: number;
  /** Packets sent by the responder (dstIp) */
  responderPackets: number;
  /** Bytes sent by the initiator (srcIp) */
  initiatorBytes: number;
  /** Bytes sent by the responder (dstIp) */
  responderBytes: number;
  /** TCP state seen on this flow (all false for non-TCP) */
  synSeen: boolean;
  synAckSeen: boolean;
  finSeen: boolean;
  rstSeen: boolean;
  /** Timestamp of first packet (μs) */
  startTimeUs: number;
  /** Timestamp of last packet (μs) */
  endTimeUs: number;
}

/* ========== Hosts ========== */

export interface HostInfo {
  ip: string;
  mac: string;
  packetCount: number;
  byteCount: number;
  protocols: Set<Protocol>;
  /** When this host was first seen (μs) */
  firstSeenUs: number;
  /** When this host was last seen (μs) */
  lastSeenUs: number;
  isPrivate: boolean;
}

export interface CommunicationPair {
  srcIp: string;
  dstIp: string;
  protocol: Protocol;
  packetCount: number;
  byteCount: number;
  flows: number;
}

/* ========== Security Findings ========== */

export const Severity = {
  Critical: "Critical",
  High: "High",
  Medium: "Medium",
  Low: "Low",
  Info: "Info",
} as const;
export type Severity = (typeof Severity)[keyof typeof Severity];

export interface SecurityFinding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  /** Remediation recommendation — actionable steps to address the finding */
  recommendation: string;
  /** Supporting data snippet */
  evidence: string;
  affectedIp: string;
  category: FindingCategory;
  /**
   * Epoch milliseconds of the first related packet in the capture (derived from
   * `firstSeenUs`). This is capture time, not the time the analysis ran.
   */
  timestamp: number;

  /* ----- Evidence linkage and quality (always populated by runAllRules) ----- */

  /** How sure the rule is that this is malicious/misconfigured rather than benign */
  confidence?: Confidence;
  /** Optional discriminator so distinct findings with the same title+IP are kept apart */
  dedupKey?: string;
  /** How many raw detections were merged into this finding */
  occurrences?: number;
  /** Indices (Packet.index) of packets that support the finding (capped) */
  packetIndices?: number[];
  /** IDs (FlowRecord.id) of flows that support the finding */
  flowIds?: string[];
  /** First / last related packet time (μs since epoch) */
  firstSeenUs?: number;
  lastSeenUs?: number;
  /**
   * True when `packetIndices`/times come from the generic fallback ("packets involving the
   * affected IP") instead of the rule pointing at the exact packets.
   */
  refsApproximate?: boolean;
}

export const Confidence = {
  Low: "low",
  Medium: "medium",
  High: "high",
} as const;
export type Confidence = (typeof Confidence)[keyof typeof Confidence];

export const FindingCategory = {
  Network: "Network",
  DNS: "DNS",
  HTTP: "HTTP",
  TLS: "TLS",
  Auth: "Auth",
  OTICS: "OT-ICS",
  Info: "Info",
  NTP: "NTP",
  DHCP: "DHCP",
  SSH: "SSH",
  Email: "Email",
  Database: "Database",
  FileShare: "FileShare",
  RemoteAccess: "RemoteAccess",
  Container: "Container",
  OPC: "OPC",
} as const;
export type FindingCategory = (typeof FindingCategory)[keyof typeof FindingCategory];

/* ========== NTP Analysis ========== */

/**
 * NTP server information for identification and display.
 */
export interface NTPServerInfo {
  /** IP address of the NTP server */
  ip: string;
  /** Port (always 123 for NTP) */
  port: number;
  /** NTP version used (3 or 4 typically) */
  version: number;
  /** Stratum level (1-15), 0 = unsynchronized, 255 = Kiss-of-death */
  stratum: number;
  /** Reference ID (for stratum 1: clock source name; for stratum 2+: source server IP) */
  referenceId: string;
  /** Root delay (seconds with 16.16 fixed-point encoding) */
  rootDelay: number;
  /** Root dispersion (seconds) */
  rootDispersion: number;
  /** Leap indicator (0-3) */
  leapIndicator: number;
  /** Poll interval in seconds (2^poll) */
  poll: number;
  /** Whether this is confirmed as a server (has responses) */
  isServer: boolean;
  /** Confidence level: high (matched with client), medium (valid server), low (single packet) */
  confidence: "high" | "medium" | "low";
}

/**
 * NTP conversation pair for correlation.
 */
export interface NTPConversation {
  /** Client IP address */
  clientIp: string;
  /** Client port */
  clientPort: number;
  /** Server IP address */
  serverIp: string;
  /** Server port (always 123) */
  serverPort: number;
  /** Number of client requests */
  requestCount: number;
  /** Number of server responses */
  responseCount: number;
  /** First packet timestamp (μs) */
  firstSeen: number;
  /** Last packet timestamp (μs) */
  lastSeen: number;
  /** Confidence in client/server identification */
  confidence: "high" | "medium" | "low";
}

/**
 * NTP analysis results.
 */
export interface NTPAnalysisResult {
  /** Identified NTP client IPs */
  clients: NTPServerInfo[];
  /** Confirmed NTP server IPs (have responded to requests) */
  servers: NTPServerInfo[];
  /** NTP conversation pairs with request/response correlation */
  conversations: NTPConversation[];
}

/* ========== Protocol Distribution ========== */

export interface ProtocolCount {
  protocol: Protocol;
  packetCount: number;
  byteCount: number;
  isOT: boolean;
}

/* ========== Summary ========== */

export interface AnalysisSummary {
  totalPackets: number;
  totalBytes: number;
  durationUs: number;
  uniqueHosts: number;
  protocolCounts: ProtocolCount[];
  topTalkers: { ip: string; packetCount: number; byteCount: number }[];
  topDestinations: { ip: string; packetCount: number; byteCount: number }[];
  flowCount: number;
  findingCount: number;
  /** Timeline buckets for traffic volume chart (binned by time interval) */
  timelineBuckets: { timestampUs: number; packetCount: number; byteCount: number }[];
}

/* ========== Full Analysis Result ========== */

export interface AnalysisResult {
  packets: import("./packets").Packet[];
  flows: FlowRecord[];
  hosts: Map<string, HostInfo>;
  findings: SecurityFinding[];
  protocolCounts: ProtocolCount[];
  summary: AnalysisSummary;
  /** The original filename */
  fileName: string;
  /** NTP-specific analysis results */
  ntpAnalysis?: NTPAnalysisResult;
  /** Wall-clock time spent in each detection rule (ms), slowest first */
  ruleTimings?: { rule: string; ms: number }[];
  /** Problems found while reading the file (unsupported link types, truncation, ...) */
  captureWarnings?: string[];
}
