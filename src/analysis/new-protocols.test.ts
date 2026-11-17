import { describe, expect, it } from "vitest";
import {
  analyze,
  makePcap,
  tcpFrame,
  udpFrame,
  TCP,
  type Frame,
  type Ip4,
} from "../test-utils/pcapBuilder";
import { Protocol } from "../types/packets";

const C: Ip4 = [10, 0, 0, 5];
const S: Ip4 = [10, 0, 0, 9];
const T0 = 1_700_000_000;

function textBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("new protocol detection & security rules", () => {
  it("detects POP3 cleartext credentials", () => {
    const payload = textBytes("USER testuser\r\nPASS secret123\r\n");
    const frames: Frame[] = [
      { t: T0, d: tcpFrame(C, S, 49152, 110, TCP.PSH | TCP.ACK, payload) },
    ];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.POP3);
    const pop3Finding = res.findings.find((f) => f.title.includes("POP3 Cleartext"));
    expect(pop3Finding).toBeDefined();
    expect(pop3Finding?.severity).toBe("High");
    expect(pop3Finding?.affectedIp).toBe("10.0.0.9");
  });

  it("detects etcd exposure with Critical severity", () => {
    const payload = textBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}");
    const frames: Frame[] = [
      { t: T0, d: tcpFrame(C, S, 49152, 2379, TCP.PSH | TCP.ACK, payload) },
    ];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.Etcd);
    const etcdFinding = res.findings.find((f) => f.title.includes("etcd Traffic Detected"));
    expect(etcdFinding).toBeDefined();
    expect(etcdFinding?.severity).toBe("Critical");
    expect(etcdFinding?.affectedIp).toBe("10.0.0.9");
  });

  it("detects Kafka cleartext broker exposure", () => {
    const frames: Frame[] = [
      { t: T0, d: tcpFrame(C, S, 49152, 9092, TCP.SYN) },
    ];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.Kafka);
    const kafkaFinding = res.findings.find((f) => f.title.includes("Kafka"));
    expect(kafkaFinding).toBeDefined();
    expect(kafkaFinding?.affectedIp).toBe("10.0.0.9");
  });

  it("detects IRC traffic on port 6667 as potential C2 / cleartext chat", () => {
    const payload = textBytes("NICK bot123\r\nUSER bot123 0 * :bot\r\nJOIN #c2channel\r\n");
    const frames: Frame[] = [
      { t: T0, d: tcpFrame(C, S, 49152, 6667, TCP.PSH | TCP.ACK, payload) },
    ];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.IRC);
    const ircFinding = res.findings.find((f) => f.title.includes("IRC"));
    expect(ircFinding).toBeDefined();
    expect(ircFinding?.severity).toBe("High");
  });

  it("detects RIPv1 routing updates without authentication", () => {
    // RIP packet: Command = 2 (Response), Version = 1
    const ripPayload = new Uint8Array(24);
    ripPayload[0] = 2; // Response
    ripPayload[1] = 1; // RIPv1
    const frames: Frame[] = [
      { t: T0, d: udpFrame(S, [224, 0, 0, 9], 520, 520, ripPayload) },
    ];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.RIP);
    const ripFinding = res.findings.find((f) => f.title.includes("RIPv1"));
    expect(ripFinding).toBeDefined();
    expect(ripFinding?.severity).toBe("High");
  });

  it("detects OSPF (IP proto 89) and flags missing authentication", () => {
    // Synthetic raw Ethernet + IPv4 + OSPF packet
    const b = new Uint8Array(14 + 20 + 24);
    const v = new DataView(b.buffer);
    b.set([2, 0, 0, 0, 0, 1], 0);
    b.set([2, 0, 0, 0, 0, 2], 6);
    v.setUint16(12, 0x0800); // IPv4
    b[14] = 0x45;
    v.setUint16(16, 20 + 24);
    b[22] = 64;
    b[23] = 89; // OSPF IP protocol
    b.set(S, 26);
    b.set([224, 0, 0, 5], 30);
    // OSPF header: Auth type at offset 14 (relative to payload) = 0 (None)
    b[34 + 0] = 2; // OSPF v2
    b[34 + 1] = 1; // Hello
    v.setUint16(34 + 14, 0); // Auth Type 0 (None)

    const frames: Frame[] = [{ t: T0, d: b }];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.OSPF);
    const ospfFinding = res.findings.find((f) => f.title.includes("OSPF"));
    expect(ospfFinding).toBeDefined();
    expect(ospfFinding?.severity).toBe("High");
  });

  it("detects GRE (IP proto 47) tunnel traffic", () => {
    const b = new Uint8Array(14 + 20 + 20);
    const v = new DataView(b.buffer);
    b.set([2, 0, 0, 0, 0, 1], 0);
    b.set([2, 0, 0, 0, 0, 2], 6);
    v.setUint16(12, 0x0800); // IPv4
    b[14] = 0x45;
    v.setUint16(16, 20 + 20);
    b[22] = 64;
    b[23] = 47; // GRE IP protocol
    b.set(C, 26);
    b.set(S, 30);

    const frames: Frame[] = [{ t: T0, d: b }];
    const res = analyze(makePcap(frames));
    expect(res.packets[0].protocol).toBe(Protocol.GRE);
    const greFinding = res.findings.find((f) => f.title.includes("GRE Tunnel"));
    expect(greFinding).toBeDefined();
    expect(greFinding?.affectedIp).toBe("10.0.0.5");
  });
});
