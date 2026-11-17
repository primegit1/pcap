import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";
import { decodeAscii } from "../ascii";

/**
 * Known suspicious user agents commonly used by scanners, exploit tools,
 * and malware.
 */
const SUSPICIOUS_USER_AGENTS: [RegExp, string][] = [
  [/nmap/i, "Nmap port scanner"],
  [/nikto/i, "Nikto web vulnerability scanner"],
  [/sqlmap/i, "SQLMap SQL injection tool"],
  [/dirbuster/i, "DirBuster directory brute-forcer"],
  [/gobuster/i, "Gobuster directory brute-forcer"],
  [/wfuzz/i, "Wfuzz web fuzzer"],
  [/burpsuite/i, "Burp Suite proxy/scanner"],
  [/metasploit/i, "Metasploit exploit framework"],
  [/masscan/i, "Masscan port scanner"],
  [/zgrab/i, "ZGrab internet scanner"],
  [/python-requests/i, "Python requests library (often used in scripts)"],
  [/python-urllib/i, "Python urllib (often used in scripts)"],
  [/curl/i, "curl (command-line HTTP client)"],
  [/wget/i, "wget (command-line file downloader)"],
  [/httpclient/i, "Generic HTTP client library"],
];

/**
 * Known malicious/suspicious MIME types for executable downloads.
 */
const EXECUTABLE_CONTENT_TYPES: [RegExp, string][] = [
  [/application\/x-dosexec/i, "Windows executable (PE)"],
  [/application\/x-msdownload/i, "Windows download (PE)"],
  [/application\/octet-stream/i, "Binary data (possible executable)"],
  [/application\/x-sh/i, "Shell script"],
  [/application\/x-bat/i, "Batch script"],
  [/application\/x-msi/i, "Windows Installer package"],
  [/application\/x-java-archive/i, "Java archive (JAR)"],
  [/application\/x-executable/i, "Executable binary"],
];

/**
 * Parse HTTP request line and headers from app payload.
 */
function parseHTTPRequest(payload: ArrayBuffer): {
  method: string;
  path: string;
  version: string;
  headers: Map<string, string>;
} | null {
  if (!payload || payload.byteLength < 16) return null;

  const text = decodeASCII(payload);
  const firstLineEnd = text.indexOf("\r\n");
  if (firstLineEnd < 0 || firstLineEnd > 8192) return null;

  const requestLine = text.slice(0, firstLineEnd);
  const parts = requestLine.split(" ");
  if (parts.length < 2) return null;

  const method = parts[0];
  const path = parts[1];
  const version = parts[2] || "";

  const headers = new Map<string, string>();
  const headerSection = text.slice(firstLineEnd + 2);
  for (const line of headerSection.split("\r\n")) {
    if (line === "") break;
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      headers.set(key, value);
    }
  }

  return { method, path, version, headers };
}

/**
 * Parse HTTP response status line and headers from app payload.
 */
function parseHTTPResponse(payload: ArrayBuffer): {
  version: string;
  statusCode: number;
  statusText: string;
  headers: Map<string, string>;
} | null {
  if (!payload || payload.byteLength < 16) return null;

  const text = decodeASCII(payload);
  const firstLineEnd = text.indexOf("\r\n");
  if (firstLineEnd < 0 || firstLineEnd > 8192) return null;

  const statusLine = text.slice(0, firstLineEnd);
  const match = statusLine.match(/^HTTP\/([\d.]+)\s+(\d{3})\s*(.*)/);
  if (!match) return null;

  const version = match[1];
  const statusCode = parseInt(match[2], 10);
  const statusText = match[3] || "";

  const headers = new Map<string, string>();
  const headerSection = text.slice(firstLineEnd + 2);
  for (const line of headerSection.split("\r\n")) {
    if (line === "") break;
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      headers.set(key, value);
    }
  }

  return { version, statusCode, statusText, headers };
}

/**
 * Detect suspicious HTTP User-Agent strings in request payloads.
 */
export function detectSuspiciousUserAgentsDeep(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    // Try to parse as HTTP request
    const req = parseHTTPRequest(pkt.appPayload);
    if (!req) continue;

    const ua = req.headers.get("user-agent");
    if (!ua) continue;

    for (const [pattern, label] of SUSPICIOUS_USER_AGENTS) {
      if (pattern.test(ua)) {
        const key = `${pkt.ip.srcIp}:${label}`;
        if (reported.has(key)) continue;
        reported.add(key);

        findings.push({
          id: nextId(),
          title: `Suspicious HTTP User-Agent: ${label}`,
          severity: Severity.High,
          description: `HTTP request from ${pkt.ip.srcIp} to ${pkt.ip.dstIp} uses User-Agent "${ua.slice(0, 80)}". This User-Agent is associated with ${label}, which is commonly used for reconnaissance, vulnerability scanning, or exploitation. Its presence in network traffic strongly suggests active security testing or attack activity.`,
          recommendation: `1. Investigate ${pkt.ip.srcIp} for the presence of ${label} or similar tools.
2. If this is authorized penetration testing, document and approve it.
3. If unauthorized, block the source and audit for damage.
4. Review web server access logs for all requests from this source.
5. Ensure WAF rules are configured to detect and block known scanner signatures.`,
          evidence: `User-Agent: ${ua.slice(0, 100)}, tool: ${label}, request: ${req.method} ${req.path.slice(0, 60)}`,
          affectedIp: pkt.ip.srcIp,
          category: FindingCategory.HTTP,
          timestamp: 0, // replaced with capture time by runAllRules
        });
        break; // One finding per packet
      }
    }
  }

  return findings;
}

/**
 * Detect HTTP responses with suspicious content types (executable downloads).
 */
export function detectExecutableDownloadsDeep(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const reported = new Set<string>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const resp = parseHTTPResponse(pkt.appPayload);
    if (!resp) continue;

    const contentType = resp.headers.get("content-type");
    if (!contentType) continue;

    for (const [pattern, label] of EXECUTABLE_CONTENT_TYPES) {
      if (pattern.test(contentType)) {
        const key = `${pkt.ip.srcIp}:${pkt.ip.dstIp}:${contentType}`;
        if (reported.has(key)) continue;
        reported.add(key);

        findings.push({
          id: nextId(),
          title: `Executable Download via HTTP: ${label}`,
          severity: Severity.Medium,
          description: `HTTP response from ${pkt.ip.srcIp} to ${pkt.ip.dstIp} with Content-Type "${contentType}" (${label}). Downloading executables over unencrypted HTTP is risky because the content can be modified in transit (man-in-the-middle injection of malware). Even legitimate downloads should use HTTPS to ensure integrity.`,
          recommendation: `1. Verify the download source is legitimate and expected.
2. Scan the downloaded file for malware.
3. Ensure future downloads use HTTPS instead of HTTP.
4. Consider deploying a web proxy with content-type filtering.
5. If this download was unexpected, investigate the client for compromise.`,
          evidence: `Content-Type: ${contentType}, status: ${resp.statusCode}, server: ${pkt.ip.srcIp}`,
          affectedIp: pkt.ip.dstIp,
          category: FindingCategory.HTTP,
          timestamp: 0, // replaced with capture time by runAllRules
        });
        break;
      }
    }
  }

  return findings;
}

/**
 * Detect HTTP authentication failures — many 401/403 responses to the same
 * client indicate credential stuffing or brute force attempts.
 */
export function detectHTTPAuthFailures(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track per client → server: count of 401/403 responses
  const authFailures = new Map<string, { count: number; serverIp: string; paths: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const resp = parseHTTPResponse(pkt.appPayload);
    if (!resp) continue;

    if (resp.statusCode === 401 || resp.statusCode === 403) {
      // Response from server → client was denied
      const clientIp = pkt.ip.dstIp;
      const key = `${clientIp}→${pkt.ip.srcIp}`;
      const existing = authFailures.get(key) || { count: 0, serverIp: pkt.ip.srcIp, paths: new Set<string>() };
      existing.count++;
      authFailures.set(key, existing);
    }
  }

  for (const [key, data] of authFailures) {
    if (data.count >= 10) {
      findings.push({
        id: nextId(),
        title: "HTTP Authentication Failure Pattern — Possible Credential Stuffing",
        severity: Severity.High,
        description: `Client ${key.split("→")[0]} received ${data.count} HTTP 401/403 responses from ${data.serverIp}. Repeated authentication failures suggest credential stuffing (using leaked username/password combinations) or brute-force password guessing against a web application. This is one of the most common attack vectors against web services.`,
        recommendation: `1. Implement rate limiting on login endpoints.
2. Deploy CAPTCHA after 3-5 failed attempts.
3. Enable multi-factor authentication (MFA) for all web accounts.
4. Check the source IP against known credential stuffing botnet IPs.
5. Review web application logs for the targeted accounts.
6. Consider account lockout after excessive failures (with timeout unlock).`,
        evidence: `Client: ${key.split("→")[0]}, failures: ${data.count}, server: ${data.serverIp}`,
        affectedIp: key.split("→")[0],
        category: FindingCategory.HTTP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect unusual HTTP methods — PUT, DELETE, OPTIONS, TRACE, CONNECT
 * may indicate reconnaissance or exploitation attempts.
 */
export function detectUnusualHTTPMethods(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const standardMethods = new Set(["GET", "POST", "HEAD"]);
  const reportedMethods = new Map<string, Set<string>>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.HTTP) continue;
    if (!pkt.ip || !pkt.appPayload) continue;

    const req = parseHTTPRequest(pkt.appPayload);
    if (!req) continue;
    // Responses start with "HTTP/1.1 200 OK"; they are not requests, and "HTTP/1.1" is not a method.
    if (!/^[A-Za-z]+$/.test(req.method)) continue;

    if (!standardMethods.has(req.method.toUpperCase())) {
      const method = req.method.toUpperCase();
      const srcIp = pkt.ip.srcIp;
      const methods = reportedMethods.get(srcIp) || new Set<string>();
      methods.add(method);
      reportedMethods.set(srcIp, methods);
    }
  }

  for (const [srcIp, methods] of reportedMethods) {
    findings.push({
      id: nextId(),
      title: `Unusual HTTP Methods Detected: ${Array.from(methods).join(", ")}`,
      severity: Severity.Medium,
      description: `Source ${srcIp} used non-standard HTTP methods: ${Array.from(methods).join(", ")}. Methods like PUT (file upload), DELETE (file removal), TRACE (XST attack vector), and CONNECT (proxy tunneling) are often disabled on production web servers. Their use may indicate active reconnaissance or exploitation attempts.`,
      recommendation: `1. Review web server logs for all requests using these methods from ${srcIp}.
2. Disable unnecessary HTTP methods on the web server (allow only GET, POST, HEAD).
3. If PUT/DELETE are required for a REST API, ensure proper authentication and authorization.
4. Block TRACE and CONNECT methods on all production servers.
5. Investigate ${srcIp} for automated testing tools.`,
      evidence: `Source: ${srcIp}, methods: ${Array.from(methods).join(", ")}`,
      affectedIp: srcIp,
      category: FindingCategory.HTTP,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Decode ArrayBuffer to ASCII string.
 */
function decodeASCII(payload: ArrayBuffer): string {
  return decodeAscii(payload, true);
}
