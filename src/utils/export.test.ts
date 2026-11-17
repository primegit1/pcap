import { describe, expect, it } from "vitest";
import { buildCsv, buildHtmlReport, buildJson, escapeCsv } from "./export";
import { calculateRiskScore } from "../analysis/risk-scoring";
import type { AnalysisResult, SecurityFinding } from "../types/analysis";

function finding(over: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "F-00001",
    title: "Suspicious HTTP User-Agent",
    severity: "High",
    description: "desc",
    recommendation: "1. Investigate",
    evidence: "ev",
    affectedIp: "10.0.0.5",
    category: "HTTP",
    timestamp: 1_700_000_000_000,
    confidence: "medium",
    occurrences: 1,
    packetIndices: [3, 4],
    firstSeenUs: 1_700_000_000_000_000,
    lastSeenUs: 1_700_000_001_000_000,
    ...over,
  } as SecurityFinding;
}

function result(findings: SecurityFinding[]): AnalysisResult {
  return {
    packets: [],
    flows: [],
    hosts: new Map(),
    findings,
    protocolCounts: [],
    fileName: "x.pcap",
    summary: {
      totalPackets: 0,
      totalBytes: 0,
      durationUs: 0,
      uniqueHosts: 0,
      protocolCounts: [],
      topTalkers: [],
      topDestinations: [],
      flowCount: 0,
      findingCount: findings.length,
      timelineBuckets: [],
    },
  } as AnalysisResult;
}

describe("CSV export", () => {
  it("neutralizes spreadsheet formulas in attacker-controlled text", () => {
    for (const evil of ['=HYPERLINK("http://x","y")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\tcmd"]) {
      const cell = escapeCsv(evil);
      expect(cell.startsWith(`"'`)).toBe(true);
    }
    expect(escapeCsv("plain, with comma")).toBe('"plain, with comma"');
    expect(escapeCsv('say "hi"')).toBe('"say ""hi"""');
  });

  it("includes recommendation, id, confidence and times, plus a UTF-8 BOM", () => {
    const csv = buildCsv([finding({ evidence: '=HYPERLINK("http://x","y")' })]);
    expect(csv.charCodeAt(0)).toBe(0xfeff);
    expect(csv).toContain('"Recommendation"');
    expect(csv).toContain('"1. Investigate"');
    expect(csv).toContain('"F-00001"');
    expect(csv).toContain('"medium"');
    expect(csv).toContain("2023-11-14T22:13:20.000Z");
    expect(csv).toContain(`"'=HYPERLINK(""http://x"",""y"")"`);
  });
});

describe("JSON export", () => {
  it("carries id, recommendation, confidence and packet references", () => {
    const json = JSON.parse(buildJson(result([finding()])));
    const f = json.findings[0];
    expect(f.id).toBe("F-00001");
    expect(f.recommendation).toBe("1. Investigate");
    expect(f.confidence).toBe("medium");
    expect(f.packetIndices).toEqual([3, 4]);
    expect(f.firstSeen).toBe("2023-11-14T22:13:20.000Z");
  });
});

describe("HTML export", () => {
  it("escapes evidence and contains no scripts", () => {
    const html = buildHtmlReport(
      result([finding({ evidence: "<script>alert(1)</script>", title: '<img src=x onerror="y">' })])
    );
    expect(html).not.toContain("<script>alert(1)");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("1. Investigate");
  });

  it("never interpolates an unknown severity into a class name", () => {
    const html = buildHtmlReport(result([finding({ severity: 'x" onmouseover="evil' as never })]));
    expect(html).toContain('class="badge badge-info"');
    expect(html).not.toContain('class="badge badge-x"');
  });

  it("uses the shared risk score", () => {
    const findings = [finding(), finding({ severity: "Critical" })];
    const { score, rating } = calculateRiskScore(findings);
    const html = buildHtmlReport(result(findings));
    expect(html).toContain(`>${score}</div>`);
    expect(html).toContain(rating);
  });
});
