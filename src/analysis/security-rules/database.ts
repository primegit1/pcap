import type { Packet } from "../../types/packets";
import { Protocol } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/**
 * Detect MySQL cleartext authentication — MySQL default auth transmits
 * passwords without TLS encryption.
 */
export function detectMySQLCleartextAuth(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const mysqlServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.MySQL) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    mysqlServers.set(serverIp, (mysqlServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of mysqlServers) {
    findings.push({
      id: nextId(),
      title: "MySQL Traffic Detected — Verify Encryption",
      severity: Severity.High,
      description: `MySQL traffic detected to ${ip} (${count} packets). MySQL's default authentication transmits credentials in cleartext unless TLS is explicitly configured. Without encryption, database credentials, queries, and result sets are visible to anyone with network access. MySQL servers are frequently targeted in brute-force and credential-stuffing attacks.`,
      recommendation: `1. Enable TLS encryption on the MySQL server (require_secure_transport=ON).
2. Migrate from mysql_native_password to caching_sha2_password auth plugin.
3. Bind MySQL to localhost (127.0.0.1) unless remote access is required.
4. Restrict MySQL user accounts to specific IP ranges.
5. Implement rate limiting on failed authentication attempts.
6. Never expose MySQL (port 3306) directly to the internet.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect PostgreSQL cleartext authentication — PostgreSQL password auth
 * without TLS exposes credentials.
 */
export function detectPostgreSQLCleartextAuth(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const pgServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.PostgreSQL) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    pgServers.set(serverIp, (pgServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of pgServers) {
    findings.push({
      id: nextId(),
      title: "PostgreSQL Traffic Detected — Verify Encryption",
      severity: Severity.High,
      description: `PostgreSQL traffic detected to ${ip} (${count} packets). PostgreSQL's default password authentication (md5 or plaintext) without TLS encryption exposes database credentials and query data on the network. An attacker with packet capture access can extract credentials or sensitive query results.`,
      recommendation: `1. Enable SSL/TLS on the PostgreSQL server (ssl=on in postgresql.conf).
2. Set ssl_min_protocol_version = 'TLSv1.2' in postgresql.conf.
3. Use SCRAM-SHA-256 authentication instead of md5 or plaintext.
4. Configure pg_hba.conf to require SSL for remote connections.
5. Bind PostgreSQL to localhost unless remote access is needed.
6. Never expose PostgreSQL (port 5432) directly to the internet.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect MSSQL traffic — TDS protocol without encryption exposes credentials.
 */
export function detectMSSQLCleartextAuth(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const mssqlServers = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.MSSQL) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    mssqlServers.set(serverIp, (mssqlServers.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of mssqlServers) {
    findings.push({
      id: nextId(),
      title: "MSSQL Traffic Detected — Verify Encryption",
      severity: Severity.High,
      description: `MSSQL traffic detected to ${ip} (${count} packets). The TDS protocol without TLS encryption transmits SQL authentication credentials and query data in cleartext. MSSQL on port 1433 is one of the most frequently brute-forced database ports on the internet.`,
      recommendation: `1. Enable TLS encryption on the MSSQL server (ForceEncryption option).
2. Use Windows Integrated Authentication (Kerberos) instead of SQL authentication.
3. Bind MSSQL to listen only on required IP addresses.
4. Implement failed login lockout policies.
5. Never expose MSSQL (port 1433) directly to the internet.
6. Use a firewall or VPN for all remote database access.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect Elasticsearch unauthenticated access — default config allows
 * unauthenticated access on port 9200.
 */
export function detectElasticsearchExposure(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const esEndpoints = new Map<string, number>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.Elasticsearch) continue;
    if (!pkt.ip) continue;

    const serverIp = pkt.ip.dstIp;
    esEndpoints.set(serverIp, (esEndpoints.get(serverIp) || 0) + 1);
  }

  for (const [ip, count] of esEndpoints) {
    findings.push({
      id: nextId(),
      title: "Elasticsearch Traffic Detected — Verify Authentication",
      severity: Severity.High,
      description: `Elasticsearch traffic detected to ${ip} (${count} packets). Elasticsearch versions before 8.0 had authentication disabled by default, allowing unrestricted access to all indices and data. Even in version 8+, misconfiguration can expose the API. Unsecured Elasticsearch instances have been widely exploited in ransomware campaigns where data is deleted and a ransom note is inserted.`,
      recommendation: `1. Enable Elasticsearch security (xpack.security.enabled=true).
2. Configure authentication with native realm or Active Directory integration.
3. Enable TLS for the HTTP and transport layers.
4. Implement index-level and cluster-level access controls.
5. Bind Elasticsearch to localhost unless remote access is explicitly required.
6. Never expose Elasticsearch (port 9200) directly to the internet.`,
      evidence: `Server: ${ip}, packets: ${count}`,
      affectedIp: ip,
      category: FindingCategory.Database,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}
