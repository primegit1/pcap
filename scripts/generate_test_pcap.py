#!/usr/bin/env python3
"""Generate a synthetic PCAP file with diverse network traffic for testing."""

import struct
import os

# ── PCAP Global Header ──────────────────────────────────────────────────
PCAP_MAGIC = 0xa1b2c3d4
pcap_hdr = struct.pack("<IHHiIII",
    PCAP_MAGIC,  # magic
    2, 4,        # version 2.4
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1            # LINKTYPE_ETHERNET
)

def pcap_record(ts_sec, ts_usec, frame):
    return struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame

# ── EtherType constants ─────────────────────────────────────────────────
ETH_IP   = 0x0800
ETH_IPV6 = 0x86dd
ETH_ARP  = 0x0806

# MAC addresses
MAC_SRC   = bytes.fromhex("001122334455")
MAC_DST   = bytes.fromhex("aabbccddeeff")
MAC_BCAST = bytes.fromhex("ffffffffffff")
MAC_ROUTER = bytes.fromhex("deadbeef0001")
MAC_ATK    = bytes.fromhex("deadbeef0f0a")

def ethernet(dst, src, ethertype):
    return dst + src + struct.pack("!H", ethertype)

# ── IPv4 ─────────────────────────────────────────────────────────────────
def ipv4(src_ip, dst_ip, proto, payload_len):
    hl = 20
    total = hl + payload_len
    sip = bytes(map(int, src_ip.split(".")))
    dip = bytes(map(int, dst_ip.split(".")))
    # Build header with zero checksum
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, os.urandom(2)[0] | 0x4000, 0x4000, 64, proto, 0) + sip + dip
    # Checksum
    s = sum(struct.unpack("!10H", hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ck = (~s) & 0xffff
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, os.urandom(2)[0] | 0x4000, 0x4000, 64, proto, ck) + sip + dip
    return hdr

def IP(a,b,c,d): return f"{a}.{b}.{c}.{d}"

IP_SRC  = IP(192,168,1,100)
IP_DST1 = IP(10,0,0,1)
IP_DST2 = IP(10,0,0,2)
IP_DST3 = IP(10,0,0,3)
IP_DNS  = IP(8,8,8,8)
IP_EXT  = IP(8,8,4,4)
IP_ATK  = IP(192,168,1,101)
IP_C2   = IP(45,33,22,11)

# ── IPv6 ─────────────────────────────────────────────────────────────────
IP6_SRC       = "2001:db8::a:1"
IP6_DST       = "2001:db8::b:1"
IP6_EXT       = "2001:4860:4860::8888"
IP6_MULTICAST = "ff02::1:2"  # All Routers link-local

def parse_ip6(addr):
    """Parse an IPv6 address string into 16 raw bytes, expanding :: zero compression."""
    if addr == "::":
        return b"\x00" * 16
    # Split on :: to find the zero gap
    if "::" in addr:
        left, right = addr.split("::", 1)
        left_parts = [p for p in left.split(":") if p]
        right_parts = [p for p in right.split(":") if p]
        zero_count = 8 - len(left_parts) - len(right_parts)
        parts = left_parts + ["0"] * zero_count + right_parts
    else:
        parts = [p for p in addr.split(":") if p]
    # Pad short parts (zeros in leading position of a group)
    result = b""
    for p in parts:
        val = int(p, 16)
        result += struct.pack("!H", val)
    if len(result) < 16:
        result += b"\x00" * (16 - len(result))
    return result

def ipv6(src_ip, dst_ip, next_header, payload_len):
    """Build a 40-byte IPv6 header (no extension headers)."""
    sip = parse_ip6(src_ip)
    dip = parse_ip6(dst_ip)
    # version=6 (4 bits) | traffic_class=0 (8 bits) | flow_label=0 (20 bits) = 0x60000000
    return struct.pack("!IHBB", 0x60000000, payload_len, next_header, 64) + sip + dip

def ip6_tcp_pkt(ts_sec, ts_usec, mac_src, mac_dst, ip6_src, ip6_dst, sport, dport, flags, seq, ack, payload=b""):
    pl = len(payload)
    eth = ethernet(mac_dst, mac_src, ETH_IPV6)
    ip6 = ipv6(ip6_src, ip6_dst, 6, 20 + pl)  # next_header=6 (TCP)
    tc  = tcp(sport, dport, flags, seq, ack, pl)
    return pcap_record(ts_sec, ts_usec, eth + ip6 + tc + payload)

def ip6_udp_pkt(ts_sec, ts_usec, mac_src, mac_dst, ip6_src, ip6_dst, sport, dport, payload=b""):
    pl = len(payload)
    eth = ethernet(mac_dst, mac_src, ETH_IPV6)
    ip6 = ipv6(ip6_src, ip6_dst, 17, 8 + pl)  # next_header=17 (UDP)
    ud  = udp(sport, dport, pl)
    return pcap_record(ts_sec, ts_usec, eth + ip6 + ud + payload)

# ── TCP ──────────────────────────────────────────────────────────────────
SYN = 0x02; ACK = 0x10; PSH = 0x08; RST = 0x04
SYNACK = SYN | ACK; PSHACK = PSH | ACK

def tcp(sport, dport, flags, seq, ack, payload_len=0):
    off = 5  # 5 * 4 = 20 bytes
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (off << 4), flags, 65535, 0, 0)

# ── UDP ──────────────────────────────────────────────────────────────────
def udp(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)

# ── ICMP ─────────────────────────────────────────────────────────────────
def icmp_echo(id, seqnum):
    hdr = struct.pack("!BBHHH", 8, 0, 0, id, seqnum)
    s = sum(struct.unpack("!4H", hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ck = (~s) & 0xffff
    return struct.pack("!BBHHH", 8, 0, ck, id, seqnum)

def icmp_reply(id, seqnum):
    hdr = struct.pack("!BBHHH", 0, 0, 0, id, seqnum)
    s = sum(struct.unpack("!4H", hdr))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ck = (~s) & 0xffff
    return struct.pack("!BBHHH", 0, 0, ck, id, seqnum)

# ── Build helpers ────────────────────────────────────────────────────────
def tcp_pkt(ts_sec, ts_usec, mac_src, mac_dst, ip_src, ip_dst, sport, dport, flags, seq, ack, payload=b""):
    pl = len(payload)
    eth = ethernet(mac_dst, mac_src, ETH_IP)
    ip  = ipv4(ip_src, ip_dst, 6, 20 + pl)
    tc  = tcp(sport, dport, flags, seq, ack, pl)
    return pcap_record(ts_sec, ts_usec, eth + ip + tc + payload)

def udp_pkt(ts_sec, ts_usec, mac_src, mac_dst, ip_src, ip_dst, sport, dport, payload=b""):
    pl = len(payload)
    eth = ethernet(mac_dst, mac_src, ETH_IP)
    ip  = ipv4(ip_src, ip_dst, 17, 8 + pl)
    ud  = udp(sport, dport, pl)
    return pcap_record(ts_sec, ts_usec, eth + ip + ud + payload)

# ── Application payloads ─────────────────────────────────────────────────
def http_get(path, host, ua="Mozilla/5.0"):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()

def dns_query(name):
    parts = name.split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)

def tls_client_hello(sni):
    """Minimal TLS 1.2 ClientHello with SNI extension."""
    session_id = b""
    cipher_suites = struct.pack("!HH", 0xc02b, 0xc02f)  # 2 suites
    comp_methods = b"\x01\x00"  # length 1, null
    sni_bytes = struct.pack("!HH", 0, len(sni) + 5)  # SNI entry type=0, len(server_name_list)
    sni_bytes += struct.pack("!H", len(sni) + 3)      # server_name_list length
    sni_bytes += b"\x00" + struct.pack("!H", len(sni)) + sni.encode("ascii")  # name_type=0, name_len, name
    ext_len = len(sni_bytes)
    session_len = len(session_id)
    cipher_len = len(cipher_suites)
    body = struct.pack("!H", 0x0303)  # version
    body += os.urandom(32)             # random
    body += bytes([session_len]) + session_id
    body += struct.pack("!H", cipher_len) + cipher_suites
    body += comp_methods
    body += struct.pack("!H", ext_len) + sni_bytes
    # TLS record header
    rec = struct.pack("!BHH", 0x16, 0x0303, len(body))  # Handshake, TLS 1.2, length
    # Handshake header inside record
    rec += struct.pack("!B", 0x01)  # ClientHello
    rec += struct.pack("!I", len(body) - 4)[1:4]  # length (3 bytes, big-endian)
    rec += body
    return rec

def arp_request(sender_ip, target_ip, sender_mac):
    sip = bytes(map(int, sender_ip.split(".")))
    tip = bytes(map(int, target_ip.split(".")))
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + sip + b"\x00" * 6 + tip

def arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    """Build a complete ARP reply frame."""
    smac = bytes.fromhex(sender_mac.replace(":", ""))
    tmac = bytes.fromhex(target_mac.replace(":", ""))
    sip = bytes(map(int, sender_ip.split(".")))
    tip = bytes(map(int, target_ip.split(".")))
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + smac + sip + tmac + tip

def arp_pkt(ts_sec, ts_usec, mac_src, mac_dst, sender_mac, sender_ip, target_mac, target_ip, operation):
    """Build a complete ARP-over-Ethernet packet (helper for consistency)."""
    smac = bytes.fromhex(sender_mac.replace(":", ""))
    tmac = bytes.fromhex(target_mac.replace(":", ""))
    sip = bytes(map(int, sender_ip.split(".")))
    tip = bytes(map(int, target_ip.split(".")))
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation) + smac + sip + tmac + tip
    eth = ethernet(mac_dst, mac_src, ETH_ARP)
    return pcap_record(ts_sec, ts_usec, eth + arp)

# ═════════════════════════════════════════════════════════════════════════
#  Build the test PCAP
# ═════════════════════════════════════════════════════════════════════════

packets = []
ts = 1_000_000  # microseconds

mac_src_str   = "00:11:22:33:44:55"
mac_router_str = "de:ad:be:ef:00:01"
mac_atk_str    = "de:ad:be:ef:0f:0a"

# 1. ARP request: 192.168.1.100 asking "Who has 10.0.0.1?"
packets.append(arp_pkt(ts // 1_000_000, ts % 1_000_000,
    MAC_SRC, MAC_BCAST, mac_src_str, "192.168.1.100",
    "00:00:00:00:00:00", "10.0.0.1", 1))

# 1b. ARP reply: 10.0.0.1 responds
ts += 500
packets.append(arp_pkt(ts // 1_000_000, ts % 1_000_000,
    MAC_ROUTER, MAC_SRC, mac_router_str, "10.0.0.1",
    mac_src_str, "192.168.1.100", 2))

# 1c. Gratuitous ARP: router announces itself
ts += 200
packets.append(arp_pkt(ts // 1_000_000, ts % 1_000_000,
    MAC_ROUTER, MAC_BCAST, mac_router_str, "10.0.0.1",
    "00:00:00:00:00:00", "10.0.0.1", 1))  # gratuitous: sender_ip == target_ip

# 1d. ARP scan: rapid requests for 3 sequential IPs (.240, .241, .242)
for i, octet in enumerate([240, 241, 242]):
    ts += 50
    packets.append(arp_pkt(ts // 1_000_000, ts % 1_000_000,
        MAC_ATK, MAC_BCAST, mac_atk_str, f"192.168.1.{octet}",
        "00:00:00:00:00:00", f"192.168.1.{octet}", 1))

# 1e. ARP poisoning: attacker claims to be the gateway (10.0.0.1) from ATK MAC
ts += 300
packets.append(arp_pkt(ts // 1_000_000, ts % 1_000_000,
    MAC_ATK, MAC_SRC, mac_atk_str, "10.0.0.1",
    mac_src_str, "192.168.1.100", 2))  # Reply: "10.0.0.1 is at ATK's MAC"
ts += 1_000

# 2. TCP SYN scan to port 22 (SSH) — port scan / brute-force rule
for i in range(3):
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_ROUTER, IP_SRC, IP_DST1,
                           50000 + i, 22, SYN, 1000 + i * 1000, 0))
    ts += 200
for i in range(3):
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_ROUTER, MAC_SRC, IP_DST1, IP_SRC,
                           22, 50000 + i, RST | ACK, 50000, 1001 + i * 1000))
    ts += 100

# 3. SSH brute-force (5 auth attempts)
for attempt in range(5):
    # SYN
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_ROUTER, IP_ATK, IP_DST1,
                           60000 + attempt, 22, SYN, 10000 + attempt * 1000, 0))
    ts += 100
    # SYN-ACK
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_ROUTER, MAC_SRC, IP_DST1, IP_ATK,
                           22, 60000 + attempt, SYNACK, 90000, 10001 + attempt * 1000))
    ts += 100
    # SSH banner
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_ROUTER, MAC_SRC, IP_DST1, IP_ATK,
                           22, 60000 + attempt, PSHACK, 90001, 10002 + attempt * 1000,
                           b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"))
    ts += 300
    # Auth attempt
    auth = b"\x00\x00\x00\x2cssh-userauth\x00\x0eroot\x00\x0epassword\x00\x10" + b"\x00" * 16
    packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_ROUTER, IP_ATK, IP_DST1,
                           60000 + attempt, 22, PSHACK, 10002 + attempt * 1000, 90002, auth))
    ts += 500

# 4. HTTP GET to internal server with sqlmap UA
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DST2,
                       54321, 80, PSHACK, 20000, 100000,
                       http_get("/admin/login.php", "internal-server.local", "sqlmap/1.7.2")))
ts += 500

# 5. HTTP admin panel access
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DST2,
                       54322, 80, PSHACK, 21000, 101000,
                       http_get("/admin/panel?action=view_users&debug=true", "admin-panel.internal", "curl/7.88")))
ts += 800

# 6. HTTP POST login
body = b"username=admin&password=letmein&submit=Login"
req = f"POST /login HTTP/1.1\r\nHost: app.internal\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DST2,
                       54323, 80, PSHACK, 22000, 102000, req))
ts += 600

# 7. DNS query (normal)
packets.append(udp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DNS,
                       54324, 53, dns_query("example.com")))
ts += 400

# 8. TLS ClientHello to internal server (suspicious SNI)
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DST3,
                       54325, 443, PSHACK, 30000, 200000,
                       tls_client_hello("vulnerable-server.internal.corp")))
ts += 700

# 9. TLS ClientHello to external (benign)
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_EXT,
                       54326, 443, PSHACK, 31000, 201000,
                       tls_client_hello("www.google.com")))
ts += 500

# 10. ICMP ping flood (3 rapid)
for i in range(3):
    eth = ethernet(MAC_DST, MAC_SRC, ETH_IP)
    ip  = ipv4(IP_SRC, IP_DST1, 1, 8)
    ic  = icmp_echo(1, i)
    packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + ic))
    ts += 10
ts += 2000

# 11. Normal encrypted traffic (TLS App Data)
app_data = struct.pack("!BHH", 0x17, 0x0303, 59) + b"\xab" * 59
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_EXT,
                       54327, 443, PSHACK, 40000, 300000, app_data))

# 12. DNS query to suspicious domain
ts += 500
packets.append(udp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_DNS,
                       54328, 53, dns_query("evil-malware-download.xyz")))

# 13. Suspicious outbound SYN to unknown port
ts += 300
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP_SRC, IP_C2,
                       54329, 4444, SYN, 50000, 0))

# 14. HTTP response with sensitive data leak
ts += 500
resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><pre>DB_PASSWORD=SuperSecret123!</pre></body></html>"
packets.append(tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_DST, MAC_SRC, IP_DST2, IP_SRC,
                       80, 54321, PSHACK, 100000, 20000 + len(resp), resp))

# 15. ICMP echo reply (normal)
ts += 100
eth = ethernet(MAC_SRC, MAC_DST, ETH_IP)
ip  = ipv4(IP_DST1, IP_SRC, 1, 8)
ic  = icmp_reply(1, 0)
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + ic))

# 16. IGMPv2 Membership Report (joining group 239.255.255.250 - SSDP)
def igmp_report(group_ip):
    """IGMPv2 Membership Report: type=0x12, code=0, checksum, group IP"""
    g = bytes(map(int, group_ip.split(".")))
    # Type=18 (Report), Code=0, Checksum=0 (placeholder), Group Address
    # Checksum calculation skipped for simplicity
    return struct.pack("!BBH", 0x12, 0, 0) + struct.pack("!HH", 0, 0) + g

ts += 500
eth = ethernet(MAC_DST, MAC_SRC, ETH_IP)
ip  = ipv4(IP_SRC, "224.0.0.22", 2, 8)  # All Groups Router address (IGMP)
igmp = igmp_report("239.255.255.250")
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + igmp))

# 17. IGMPv3 Membership Report with source (suspicious - could be C2)
def igmp_v3_report(group_ip, sources):
    """IGMPv3 Report with source addresses."""
    g = bytes(map(int, group_ip.split(".")))
    src_bytes = b""
    for src in sources:
        src_bytes += bytes(map(int, src.split(".")))
    # IGMPv3 header + 1 group record
    # Type=22 (v3 Report), MaxResp=0, Checksum=0, NumGroups=1, then group record
    return struct.pack("!BBHH", 22, 0, 0, 0) + struct.pack("!H", 1) + \
           struct.pack("!BBH", 1, len(sources), 0) + g + src_bytes

ts += 300
eth = ethernet(MAC_SRC, MAC_DST, ETH_IP)
ip  = ipv4(IP_SRC, "224.0.0.251", 2, 24)  # mDNS address
# Report joining 239.255.255.200 (high-numbered multicast) with source from C2
igmp_v3 = igmp_v3_report("239.255.255.200", [IP_C2])
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + igmp_v3))

ts += 300
eth = ethernet(MAC_SRC, MAC_DST, ETH_IP)
ip  = ipv4(IP_SRC, "224.0.0.251", 2, 24)
igmp_v3 = igmp_v3_report("239.255.255.200", [IP_C2])
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + igmp_v3))

# 18. IGMP Leave Group
def igmp_leave(group_ip):
    """IGMPv2 Leave Group: type=0x17, code=0, checksum, group IP"""
    g = bytes(map(int, group_ip.split(".")))
    return struct.pack("!BBH", 0x17, 0, 0) + struct.pack("!HH", 0, 0) + g

ts += 200
eth = ethernet(MAC_SRC, MAC_DST, ETH_IP)
ip  = ipv4(IP_SRC, "224.0.0.22", 2, 8)
igmp_leave_pkt = igmp_leave("239.255.255.250")
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip + igmp_leave_pkt))

# ── IPv6 Test Traffic ────────────────────────────────────────────────────

# 19. IPv6 TCP → HTTP GET to internal server
ts += 1000
packets.append(ip6_tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP6_SRC, IP6_DST,
                            49152, 80, PSHACK, 100, 0,
                            http_get("/api/status", "ipv6-server.internal")))

# 20. IPv6 UDP → DNS query (Google DNS over IPv6)
ts += 500
packets.append(ip6_udp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP6_SRC, IP6_EXT,
                            49153, 53, dns_query("ipv6-only.example.com")))

# 21. ICMPv6 Echo Request (ping6)
ts += 300
icmp6_echo = struct.pack("!BBHHH", 128, 0, 0, 0xbeef, 1)  # type=128 (Echo Request)
# Recompute checksum
s = sum(struct.unpack("!4H", icmp6_echo))
while s >> 16:
    s = (s & 0xffff) + (s >> 16)
icmp6_echo = struct.pack("!BBHHH", 128, 0, (~s) & 0xffff, 0xbeef, 1)
eth = ethernet(MAC_DST, MAC_SRC, ETH_IPV6)
ip6 = ipv6(IP6_SRC, IP6_DST, 58, 8)  # next_header=58 (ICMPv6)
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip6 + icmp6_echo))

# 22. ICMPv6 Echo Reply
ts += 200
icmp6_reply = struct.pack("!BBHHH", 129, 0, 0, 0xbeef, 1)  # type=129 (Echo Reply)
s = sum(struct.unpack("!4H", icmp6_reply))
while s >> 16:
    s = (s & 0xffff) + (s >> 16)
icmp6_reply = struct.pack("!BBHHH", 129, 0, (~s) & 0xffff, 0xbeef, 1)
eth = ethernet(MAC_SRC, MAC_DST, ETH_IPV6)
ip6 = ipv6(IP6_DST, IP6_SRC, 58, 8)
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip6 + icmp6_reply))

# 23. ICMPv6 Neighbor Solicitation (NDP)
ts += 500
# Neighbor Solicitation: type=135, code=0, reserved=0, target=IP6_DST
target = parse_ip6(IP6_DST)
ns_hdr = struct.pack("!BBHI", 135, 0, 0, 0) + target
# Add Source Link-Layer Address option (type=1, length=1 [in 8-byte units], MAC=MAC_SRC)
slla_opt = struct.pack("!BB", 1, 1) + MAC_SRC
ns_payload = ns_hdr + slla_opt
# Compute ICMPv6 checksum over pseudo-header + payload
pseudo = parse_ip6(IP6_SRC) + parse_ip6("ff02::1:ff00:1") + struct.pack("!I", len(ns_payload)) + b"\x00\x00\x00\x3a"
ck_data = pseudo + ns_payload
s = sum(struct.unpack(f"!{len(ck_data)//2}H", ck_data))
if len(ck_data) % 2:
    s += ck_data[-1] << 8
while s >> 16:
    s = (s & 0xffff) + (s >> 16)
ns_checksum = (~s) & 0xffff
ns_hdr = struct.pack("!BBHI", 135, 0, ns_checksum, 0) + target
ns_payload = ns_hdr + slla_opt
eth = ethernet(MAC_BCAST, MAC_SRC, ETH_IPV6)
ip6 = ipv6(IP6_SRC, "ff02::1:ff00:1", 58, len(ns_payload))
packets.append(pcap_record(ts // 1_000_000, ts % 1_000_000, eth + ip6 + ns_payload))

# 24. IPv6 TCP → alternate port (8443) with TLS ClientHello
ts += 600
packets.append(ip6_tcp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST, IP6_SRC, IP6_DST,
                            49154, 8443, PSHACK, 200, 0,
                            tls_client_hello("api6.internal.example.com")))

# ── SSDP Test Traffic ────────────────────────────────────────────────────

def ssdp_pkt(ts_sec, ts_usec, mac_src, mac_dst, ip_src, ip_dst, payload):
    """Build a complete SSDP packet (UDP over IPv4, port 1900)."""
    pl = len(payload)
    eth = ethernet(mac_dst, mac_src, ETH_IP)
    ip  = ipv4(ip_src, ip_dst, 17, 8 + pl)  # protocol 17 = UDP
    ud  = udp(1900, 1900, pl)
    return pcap_record(ts_sec, ts_usec, eth + ip + ud + payload)

SSDP_MULTICAST = "239.255.255.250"

# 25. SSDP NOTIFY ssdp:alive — Internet Gateway Device announcement
ts += 1000
igd_notify = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "NTS: ssdp:alive\r\n"
    "USN: uuid:75802409-bccb-40e7-8e6c-abcdef123456::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
    "SERVER: Linux/4.9 UPnP/1.1 MiniUPnPd/2.0\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "\r\n"
).encode()
packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                         IP_SRC, SSDP_MULTICAST, igd_notify))

# 26. SSDP M-SEARCH — client searching for all devices
ts += 500
msearch_all = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()
packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                         IP_SRC, SSDP_MULTICAST, msearch_all))

# 27. SSDP M-SEARCH — searching for WAN IP Connection service
ts += 200
msearch_wan = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 5\r\n"
    "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
    "\r\n"
).encode()
packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                         IP_SRC, SSDP_MULTICAST, msearch_wan))

# 28. SSDP NOTIFY ssdp:alive — Media Renderer
ts += 300
media_notify = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    "NTS: ssdp:alive\r\n"
    "USN: uuid:abc123-render::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    "LOCATION: http://192.168.1.50:9197/dmr.xml\r\n"
    "SERVER: Linux/5.10 UPnP/1.1\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "\r\n"
).encode()
packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                         IP_SRC, SSDP_MULTICAST, media_notify))

# 29-31. Amplification scan — multiple M-SEARCH from external IP
for i in range(3):
    ts += 100
    msearch_amp = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()
    packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                             IP_ATK, SSDP_MULTICAST, msearch_amp))

# 32. SSDP NOTIFY ssdp:byebye — device going offline
ts += 400
byebye_notify = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    "NTS: ssdp:byebye\r\n"
    "USN: uuid:abc123-render::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
    "\r\n"
).encode()
packets.append(ssdp_pkt(ts // 1_000_000, ts % 1_000_000, MAC_SRC, MAC_DST,
                         IP_SRC, SSDP_MULTICAST, byebye_notify))

# ═════════════════════════════════════════════════════════════════════════
#  Write PCAP
# ═════════════════════════════════════════════════════════════════════════

out_path = "public/test-traffic.pcap"
os.makedirs("public", exist_ok=True)
data = pcap_hdr + b"".join(packets)
with open(out_path, "wb") as f:
    f.write(data)
print(f"Generated {len(packets)} packets -> {out_path} ({len(data) / 1024:.1f} KB)")
