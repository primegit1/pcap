import { Protocol } from "../types/packets";

/**
 * Well-known port ranges for protocol detection.
 */
export const PORT_PROTOCOL_MAP: Record<number, Protocol> = {
  // Web
  80: Protocol.HTTP,
  443: Protocol.HTTPS,
  8080: Protocol.HTTP,
  // Infrastructure
  53: Protocol.DNS,
  67: Protocol.DHCP,
  68: Protocol.DHCP,
  5355: Protocol.LLMNR,
  546: Protocol.DHCPv6,
  547: Protocol.DHCPv6,
  69: Protocol.TFTP,
  123: Protocol.NTP,
  161: Protocol.SNMP,
  162: Protocol.SNMP,
  179: Protocol.BGP,
  514: Protocol.Syslog,
  5353: Protocol.mDNS,
  // Routing (port-based; OSPF/EIGRP/VRRP are IP-protocol-level)
  520: Protocol.RIP,
  521: Protocol.RIP,
  1985: Protocol.HSRP,
  // Remote access / VPN
  22: Protocol.SSH,
  23: Protocol.Telnet,
  3389: Protocol.RDP,
  5900: Protocol.VNC,
  5901: Protocol.VNC,
  1194: Protocol.OpenVPN,
  51820: Protocol.WireGuard,
  500: Protocol.IPSecIKE,
  4500: Protocol.IPSecIKE,
  // Directory / Auth
  88: Protocol.Kerberos,
  389: Protocol.LDAP,
  636: Protocol.LDAP,
  1812: Protocol.RADIUS,
  1813: Protocol.RADIUS,
  // File transfer
  21: Protocol.FTP,
  // File sharing
  137: Protocol.NetBIOS,
  138: Protocol.NetBIOS,
  139: Protocol.SMB,
  445: Protocol.SMB,
  // Email
  25: Protocol.SMTP,
  587: Protocol.SMTP,
  143: Protocol.IMAP,
  993: Protocol.IMAP,
  110: Protocol.POP3,
  995: Protocol.POP3,
  // Database
  1433: Protocol.MSSQL,
  1521: Protocol.OracleDB,
  3306: Protocol.MySQL,
  5432: Protocol.PostgreSQL,
  6379: Protocol.Redis,
  27017: Protocol.MongoDB,
  9200: Protocol.Elasticsearch,
  11211: Protocol.Memcached,
  // Container / Orchestration
  2375: Protocol.Docker,
  2376: Protocol.Docker,
  6443: Protocol.Kubernetes,
  8443: Protocol.Kubernetes,
  // Cloud-native / Data stores
  9092: Protocol.Kafka,
  9093: Protocol.Kafka,
  2181: Protocol.ZooKeeper,
  2379: Protocol.Etcd,
  2380: Protocol.Etcd,
  8500: Protocol.Consul,
  8600: Protocol.Consul,
  // IoT / Messaging
  1883: Protocol.MQTT,
  8883: Protocol.MQTT,
  5672: Protocol.AMQP,
  5683: Protocol.CoAP,
  // Communication / C2
  6667: Protocol.IRC,
  6697: Protocol.IRC,
  5222: Protocol.XMPP,
  5223: Protocol.XMPP,
  5269: Protocol.XMPP,
  3478: Protocol.STUN,
  5349: Protocol.STUN,
  // Media / Streaming
  554: Protocol.RTSP,
  8554: Protocol.RTSP,
  // VoIP
  5060: Protocol.SIP,
  5061: Protocol.SIP,
  // SCADA / OT / ICS
  502: Protocol.Modbus,
  20000: Protocol.DNP3,
  102: Protocol.S7Comm,
  44818: Protocol.EtherNetIP,
  135: Protocol.OPCDA,
  4840: Protocol.OPCUA,
  2404: Protocol.IEC104,
  // Building automation
  47808: Protocol.BACnet,
  // IoT / UPnP
  1900: Protocol.SSDP,
  // Industrial automation
  34962: Protocol.Profinet,
  34964: Protocol.Profinet,
  // OT/ICS extras
  18245: Protocol.GeSRTP,
  1911: Protocol.NiagaraFox,
  4911: Protocol.NiagaraFox,
  5094: Protocol.HARTIP,
  // Tunneling
  4789: Protocol.VXLAN,
  // Windows
  // Note: port 135 is mapped to OPCDA above; DCE/RPC also uses 135 but OPCDA takes precedence
};


/**
 * Detect application-layer protocol from port numbers and payload.
 */
export function detectProtocol(
  ipProtocol: number,
  srcPort: number,
  dstPort: number,
  payload: ArrayBuffer | null
): Protocol {
  if (ipProtocol === 47) return Protocol.GRE;
  if (ipProtocol === 89) return Protocol.OSPF;
  if (ipProtocol === 88) return Protocol.EIGRP;
  if (ipProtocol === 112) return Protocol.VRRP;

  const port = PORT_PROTOCOL_MAP[srcPort] ?? PORT_PROTOCOL_MAP[dstPort] ?? Protocol.Unknown;

  // For TCP/UDP on port 53, confirm DNS by checking payload (if available)
  if ((srcPort === 53 || dstPort === 53) && payload && payload.byteLength >= 12) {
    return Protocol.DNS;
  }

  // For port 80/8080, try to confirm HTTP
  if ((port === Protocol.HTTP) && payload && payload.byteLength >= 4) {
    const view = new Uint8Array(payload);
    const prefix = String.fromCharCode(view[0], view[1], view[2], view[3]);
    if (
      prefix === "GET " || prefix === "POST" || prefix === "PUT " ||
      prefix === "HEAD" || prefix === "HTTP" || prefix === "DELE" ||
      prefix === "PATC"
    ) {
      return Protocol.HTTP;
    }
    return Protocol.HTTP;
  }

  return port;
}
