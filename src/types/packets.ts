/* ========== Layer 2 / Ethernet ========== */

export interface EthernetFrame {
  dstMac: string;
  srcMac: string;
  etherType: number;
  /** Offset where payload begins */
  payloadOffset: number;
}

/* ========== Layer 3 / IP ========== */

export interface IPv4Header {
  version: 4;
  ihl: number;
  dscp: number;
  ecn: number;
  totalLength: number;
  identification: number;
  flags: number;
  fragmentOffset: number;
  ttl: number;
  protocol: number;
  headerChecksum: number;
  srcIp: string;
  dstIp: string;
  /** Offset where layer-4 payload begins */
  payloadOffset: number;
  payloadLen: number;
}

export interface IPv6Header {
  version: 6;
  trafficClass: number;
  flowLabel: number;
  payloadLength: number;
  nextHeader: number;
  /** Alias for nextHeader to match IPv4's protocol field name */
  protocol: number;
  hopLimit: number;
  srcIp: string;
  dstIp: string;
  /** Offset where layer-4 payload begins (after extension headers) */
  payloadOffset: number;
  payloadLen: number;
}

export type IPHeader = IPv4Header | IPv6Header;

/* ========== Layer 4 / Transport ========== */

export interface TCPHeader {
  srcPort: number;
  dstPort: number;
  sequenceNumber: number;
  acknowledgmentNumber: number;
  dataOffset: number;
  fin: boolean;
  syn: boolean;
  rst: boolean;
  psh: boolean;
  ack: boolean;
  urg: boolean;
  window: number;
  checksum: number;
  urgentPointer: number;
  options: TCPOption[];
  payloadOffset: number;
  payloadLength: number;
}

export interface TCPOption {
  kind: number;
  length?: number;
  data?: Uint8Array;
}

export interface UDPHeader {
  srcPort: number;
  dstPort: number;
  length: number;
  checksum: number;
  payloadOffset: number;
  payloadLength: number;
}

export interface ICMPHeader {
  type: number;
  code: number;
  checksum: number;
  /** ICMPv6 flag */
  isV6: boolean;
  payloadOffset: number;
  payloadLength: number;
}

export interface IGMPHeader {
  /** IGMP version: 1, 2, or 3 */
  version: number;
  /** Type field (2=Query, 1=Report/V2, 18=Report/V3, 16=Leave) */
  type: number;
  maxResponseTime: number;
  checksum: number;
  /** Group address (for queries/reports) */
  groupAddress?: string;
  /** Source addresses (for IGMPv3 reports only) */
  sourceAddresses?: string[];
}

/* ========== NTP Header ========== */

/**
 * NTP header structure (RFC 5905).
 * NTP uses a 48-byte packet (or more for autokey), but the first 16 bytes
 * contain the essential fields for client/server identification.
 */
export interface NTPHeader {
  /** Leap Indicator (2 bits): 0-3 warning states */
  leapIndicator: number;
  /** Version (3 bits): 1-15, typically 3 or 4 */
  version: number;
  /** Mode (3 bits): 1=Reserved, 2=Symmetric Active, 3=Client, 4=Server, 5=Broadcast, 6=Control, 7=Private */
  mode: number;
  /** Stratum (8 bits): 0=Unknown, 1=Primary, 2-15=Secondary, 16=Deprecated, 255=Kiss-of-Death */
  stratum: number;
  /** Poll interval (log2(seconds)) */
  poll: number;
  /** Precision (log2(seconds)) */
  precision: number;
  /** Root Delay (32-bit fixed point) */
  rootDelay: number;
  /** Root Dispersion (32-bit fixed point) */
  rootDispersion: number;
  /** Reference ID: for stratum 1, the primary server's ID; otherwise, the IP of the source clock */
  referenceId: string;
  /** Reference Timestamp (64-bit) - only parsed if needed */
  referenceTimestamp?: number;
  /** Originate Timestamp (64-bit) - part of request/response correlation */
  originateTimestamp?: number;
  /** Receive Timestamp (64-bit) - set by server */
  receiveTimestamp?: number;
  /** Transmit Timestamp (64-bit) - set by client for request, server for response */
  transmitTimestamp?: number;
}

/* ========== Application Layer Detection ========== */

export const Protocol = {
  Unknown: "Unknown",
  // Web
  HTTP: "HTTP",
  HTTPS: "HTTPS/TLS",
  // Email
  SMTP: "SMTP",
  IMAP: "IMAP",
  POP3: "POP3",
  // Directory / Auth
  LDAP: "LDAP",
  Kerberos: "Kerberos",
  RADIUS: "RADIUS",
  SSH: "SSH",
  FTP: "FTP",
  Telnet: "Telnet",
  // File sharing
  SMB: "SMB",
  // Database
  MSSQL: "MSSQL",
  MySQL: "MySQL",
  PostgreSQL: "PostgreSQL",
  Redis: "Redis",
  MongoDB: "MongoDB",
  Elasticsearch: "Elasticsearch",
  Memcached: "Memcached",
  OracleDB: "Oracle DB",
  // Infrastructure
  DNS: "DNS",
  DHCP: "DHCP",
  DHCPv6: "DHCPv6",
  LLMNR: "LLMNR",
  NTP: "NTP",
  SNMP: "SNMP",
  Syslog: "Syslog",
  mDNS: "mDNS",
  TFTP: "TFTP",
  BGP: "BGP",
  // Routing
  OSPF: "OSPF",
  EIGRP: "EIGRP",
  RIP: "RIP",
  VRRP: "VRRP",
  HSRP: "HSRP",
  // Remote access / VPN
  RDP: "RDP",
  VNC: "VNC",
  OpenVPN: "OpenVPN",
  WireGuard: "WireGuard",
  IPSecIKE: "IPSec/IKE",
  SSDP: "SSDP",
  // Tunneling
  GRE: "GRE",
  VXLAN: "VXLAN",
  // Container / Orchestration
  Docker: "Docker",
  Kubernetes: "Kubernetes",
  // Cloud-native / Data stores
  Kafka: "Kafka",
  ZooKeeper: "ZooKeeper",
  Etcd: "etcd",
  Consul: "Consul",
  // IoT / Messaging
  MQTT: "MQTT",
  CoAP: "CoAP",
  AMQP: "AMQP",
  RTSP: "RTSP",
  // Communication / C2
  IRC: "IRC",
  XMPP: "XMPP",
  STUN: "STUN",
  // VoIP
  SIP: "SIP",
  // QUIC (detected via UDP/443 heuristic, not port map)
  QUIC: "QUIC/HTTP3",
  // SCADA / OT / ICS
  Modbus: "Modbus TCP",
  DNP3: "DNP3",
  S7Comm: "S7Comm",
  EtherNetIP: "EtherNet/IP",
  OPCDA: "OPC DA",
  OPCUA: "OPC UA",
  IEC104: "IEC 60870-5-104",
  BACnet: "BACnet",
  Profinet: "Profinet",
  // OT/ICS extras
  GeSRTP: "GE SRTP",
  NiagaraFox: "Niagara Fox",
  HARTIP: "HART-IP",
  FFLR: "FF-LR (Fieldbus LAN Redundancy)",
  // Network layer
  ICMP: "ICMP",
  IGMP: "IGMP",
  ARP: "ARP",
  NetBIOS: "NetBIOS",
  // Windows
  DCERPC: "DCE/RPC",
} as const;
export type Protocol = (typeof Protocol)[keyof typeof Protocol];

/**
 * Returns true for protocols whose payload is plain-text / human-readable.
 */
export function isClearTextProtocol(protocol: Protocol): boolean {
  return ([
    Protocol.HTTP,
    Protocol.FTP,
    Protocol.Telnet,
    Protocol.SMTP,
    Protocol.SSH,
    Protocol.IMAP,
    Protocol.POP3,
    Protocol.LDAP,
    Protocol.Redis,
    Protocol.MySQL,
    Protocol.Memcached,
    Protocol.VNC,
    Protocol.TFTP,
    Protocol.SIP,
    Protocol.IRC,
    Protocol.XMPP,
  ] as readonly Protocol[]).includes(protocol);
}

/**
 * Returns true for OT/ICS protocols.
 */
export function isOTProtocol(protocol: Protocol): boolean {
  return ([
    Protocol.Modbus,
    Protocol.DNP3,
    Protocol.S7Comm,
    Protocol.EtherNetIP,
    Protocol.OPCDA,
    Protocol.OPCUA,
    Protocol.IEC104,
    Protocol.BACnet,
    Protocol.Profinet,
    Protocol.GeSRTP,
    Protocol.NiagaraFox,
    Protocol.HARTIP,
    Protocol.FFLR,
  ] as readonly Protocol[]).includes(protocol);
}

/* ========== Decoded Packet ========== */

export interface Packet {
  /** 0-based index of the frame in the capture (stable; used by findings to reference packets) */
  index: number;
  /** Timestamp in microseconds since epoch */
  timestampUs: number;
  /** Raw packet data (entire frame). For non-Ethernet link types a synthetic 14-byte Ethernet header is prepended. */
  raw: ArrayBuffer;
  /** Original capture link-layer type (LINKTYPE_*), when known */
  linkType?: number;
  /** Ethernet frame (null if not Ethernet) */
  ethernet: EthernetFrame | null;
  /** IP header (null if not IP) */
  ip: IPHeader | null;
  /** Transport header (null if not TCP/UDP/ICMP/IGMP) */
  transport: TCPHeader | UDPHeader | ICMPHeader | IGMPHeader | null;
  /** Detected application-layer protocol */
  protocol: Protocol;
  /** Human-readable summary — enriched with application-layer details */
  info: string;
  /** Total length of the captured frame */
  length: number;
  /**
   * Application-layer payload bytes extracted from the transport layer.
   * For TCP/UDP this is the data after the transport header.
   * null if no payload or non-transport protocol.
   */
  appPayload: ArrayBuffer | null;
  /**
   * Human-readable description of the application payload (first line / key fields)
   * e.g. "GET /admin/login.php HTTP/1.1" for HTTP, "Read Holding Registers" for Modbus.
   * Empty string if no payload or unreadable.
   */
  appPayloadSummary: string;
}

/* ========== PCAP Global Headers ========== */

export interface PcapGlobalHeader {
  magicNumber: number;
  versionMajor: number;
  versionMinor: number;
  thiszone: number;
  sigfigs: number;
  snaplen: number;
  network: number;
  /** Whether timestamps use microsecond (true) or nanosecond (false) resolution */
  isMicrosecond: boolean;
  /** Whether the file needs byte swapping */
  swapped: boolean;
}

export interface PcapPacketHeader {
  tsSec: number;
  tsFrac: number;
  inclLen: number;
  origLen: number;
}

/* ========== PCAPNG Block Types ========== */

export interface PcapngSectionHeaderBlock {
  blockType: number;
  blockLength: number;
  byteOrderMagic: number;
  majorVersion: number;
  minorVersion: number;
  sectionLength: number;
  options: Map<number, Uint8Array>;
}

export interface PcapngInterfaceDescriptionBlock {
  blockType: number;
  blockLength: number;
  linkType: number;
  reserved: number;
  options: Map<number, Uint8Array>;
  /** Link-layer snapshot length (0 = unlimited) */
  snapLen: number;
  /** Timestamp resolution in ticks per second (default 1_000_000) */
  timestampResolution: number;
}

export interface PcapngEnhancedPacketBlock {
  blockType: number;
  blockLength: number;
  interfaceId: number;
  timestamp: bigint;
  capturedPacketLength: number;
  originalPacketLength: number;
  packetData: ArrayBuffer;
  options: Map<number, Uint8Array>;
}

/** A pcapng packet resolved against its interface description. */
export interface PcapngPacket extends PcapngEnhancedPacketBlock {
  /** Link-layer type of the interface this packet was captured on */
  linkType: number;
  /** Timestamp resolution of the interface, in ticks per second */
  timestampResolution: number;
  /** Timestamp converted to microseconds since epoch (0 for Simple Packet Blocks) */
  timestampUs: number;
}
