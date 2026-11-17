import { Protocol } from "../types/packets";
import { summarizeSSDP } from "./ssdp";
import { summarizeFTP, summarizeHTTP, summarizeIMAP, summarizeIRC, summarizePOP3, summarizeRDP, summarizeRTSP, summarizeSIP, summarizeSMTP, summarizeSSH, summarizeTelnet, summarizeXMPP } from "./summaries/text-protocols";
import { summarizeIPSecIKE, summarizeOpenVPN, summarizeQUIC, summarizeTLS, summarizeWireGuard } from "./summaries/secure-transport";
import { summarizeBGP, summarizeDHCP, summarizeDHCPv6Payload, summarizeDNS, summarizeIGMP, summarizeKerberos, summarizeLDAP, summarizeNetBIOS, summarizeNTP, summarizeRIP, summarizeSMB, summarizeSNMP, summarizeSTUN, summarizeSyslog } from "./summaries/network-services";
import { summarizeBACnet, summarizeDNP3, summarizeEtherNetIP, summarizeIEC104, summarizeModbus, summarizeOPCDA, summarizeOPCUA, summarizeProfinet, summarizeS7 } from "./summaries/industrial";
import { summarizeAMQP, summarizeMQTT, summarizeMSSQL, summarizeMemcached, summarizeMongoDB, summarizeMySQL, summarizeOracleTNS, summarizePostgreSQL, summarizeRedis } from "./summaries/databases-messaging";
import { summarizeRaw } from "./summaries/shared";

/**
 * Build a payload summary for known protocols.
 * Returns a short string like "GET /admin/login.php HTTP/1.1"
 * or "Read Holding Registers (FC=0x03)".
 */
export function summarizePayload(protocol: Protocol, payload: ArrayBuffer | null): string {
  if (!payload || payload.byteLength === 0) return "";

  switch (protocol) {
    case Protocol.HTTP:
      return summarizeHTTP(payload);
    case Protocol.HTTPS:
      return summarizeTLS(payload);
    case Protocol.FTP:
      return summarizeFTP(payload);
    case Protocol.Telnet:
      return summarizeTelnet(payload);
    case Protocol.SMTP:
      return summarizeSMTP(payload);
    case Protocol.IMAP:
      return summarizeIMAP(payload);
    case Protocol.LDAP:
      return summarizeLDAP(payload);
    case Protocol.SSH:
      return summarizeSSH(payload);
    case Protocol.DHCP:
      return summarizeDHCP(payload);
    case Protocol.NTP:
      return summarizeNTP(payload);
    case Protocol.Modbus:
      return summarizeModbus(payload);
    case Protocol.S7Comm:
      return summarizeS7(payload);
    case Protocol.SNMP:
      return summarizeSNMP(payload);
    case Protocol.DNS:
      return summarizeDNS(payload, Protocol.DNS);
    case Protocol.mDNS:
      return summarizeDNS(payload, Protocol.mDNS);
    case Protocol.LLMNR:
      return summarizeDNS(payload, Protocol.LLMNR);
    case Protocol.SSDP:
      return summarizeSSDP(payload);
    case Protocol.Syslog:
      return summarizeSyslog(payload);
    case Protocol.MSSQL:
      return summarizeMSSQL(payload);
    case Protocol.SMB:
      return summarizeSMB(payload);
    case Protocol.RDP:
      return summarizeRDP(payload);
    case Protocol.DNP3:
      return summarizeDNP3(payload);
    case Protocol.EtherNetIP:
      return summarizeEtherNetIP(payload);
    case Protocol.OPCDA:
      return summarizeOPCDA(payload);
    case Protocol.OPCUA:
      return summarizeOPCUA(payload);
    case Protocol.IEC104:
      return summarizeIEC104(payload);
    case Protocol.BACnet:
      return summarizeBACnet(payload);
    case Protocol.Profinet:
      return summarizeProfinet(payload);
    case Protocol.MQTT:
      return summarizeMQTT(payload);
    case Protocol.Redis:
      return summarizeRedis(payload);
    case Protocol.Memcached:
      return summarizeMemcached(payload);
    case Protocol.MySQL:
      return summarizeMySQL(payload);
    case Protocol.PostgreSQL:
      return summarizePostgreSQL(payload);
    case Protocol.MongoDB:
      return summarizeMongoDB(payload);
    case Protocol.SIP:
      return summarizeSIP(payload);
    case Protocol.IGMP:
      return summarizeIGMP(payload);
    case Protocol.DHCPv6:
      return summarizeDHCPv6Payload(payload);
    case Protocol.WireGuard:
      return summarizeWireGuard(payload);
    case Protocol.BGP:
      return summarizeBGP(payload);
    case Protocol.Kerberos:
      return summarizeKerberos(payload);
    case Protocol.IPSecIKE:
      return summarizeIPSecIKE(payload);
    case Protocol.RTSP:
      return summarizeRTSP(payload);
    case Protocol.OracleDB:
      return summarizeOracleTNS(payload);
    case Protocol.AMQP:
      return summarizeAMQP(payload);
    case Protocol.NetBIOS:
      return summarizeNetBIOS(payload);
    case Protocol.OpenVPN:
      return summarizeOpenVPN(payload);
    case Protocol.QUIC:
      return summarizeQUIC(payload);
    case Protocol.POP3:
      return summarizePOP3(payload);
    case Protocol.IRC:
      return summarizeIRC(payload);
    case Protocol.XMPP:
      return summarizeXMPP(payload);
    case Protocol.RIP:
      return summarizeRIP(payload);
    case Protocol.STUN:
      return summarizeSTUN(payload);
    case Protocol.Kafka:
      return `Kafka: ${payload.byteLength} bytes`;
    case Protocol.Etcd:
      return `etcd: ${payload.byteLength} bytes`;
    case Protocol.ZooKeeper:
      return `ZooKeeper: ${payload.byteLength} bytes`;
    case Protocol.Consul:
      return `Consul: ${payload.byteLength} bytes`;
    case Protocol.DCERPC:
      return `DCE/RPC: ${payload.byteLength} bytes`;
    case Protocol.GeSRTP:
      return `GE SRTP: ${payload.byteLength} bytes`;
    case Protocol.NiagaraFox:
      return `Niagara Fox: ${payload.byteLength} bytes`;
    case Protocol.HARTIP:
      return `HART-IP: ${payload.byteLength} bytes`;
    case Protocol.VXLAN:
      return `VXLAN: ${payload.byteLength} bytes`;
    case Protocol.GRE:
      return `GRE: ${payload.byteLength} bytes`;
    case Protocol.HSRP:
      return `HSRP: ${payload.byteLength} bytes`;
    case Protocol.OSPF:
      return `OSPF: ${payload.byteLength} bytes`;
    case Protocol.EIGRP:
      return `EIGRP: ${payload.byteLength} bytes`;
    case Protocol.VRRP:
      return `VRRP: ${payload.byteLength} bytes`;
    default:
      return summarizeRaw(payload);
  }
}
