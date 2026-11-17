import type { SecurityFinding } from "../types/analysis";
import { Severity } from "../types/analysis";

/**
 * Risk score weights per severity level.
 */
const SEVERITY_WEIGHTS: Record<string, number> = {
  [Severity.Critical]: 10,
  [Severity.High]: 5,
  [Severity.Medium]: 2,
  [Severity.Low]: 1,
  [Severity.Info]: 0,
};

/**
 * Risk rating thresholds.
 */
const RISK_THRESHOLDS = [
  { min: 50, rating: "Critical Risk" },
  { min: 20, rating: "High Risk" },
  { min: 5, rating: "Medium Risk" },
  { min: 0, rating: "Low Risk" },
];

export interface RiskScoreResult {
  /** Weighted risk score */
  score: number;
  /** Human-readable risk rating */
  rating: string;
  /** Breakdown by severity level */
  breakdown: Record<string, number>;
  /** Total findings */
  totalFindings: number;
}

/**
 * Calculate a risk score from a list of security findings.
 * Uses weighted scoring: Critical=10, High=5, Medium=2, Low=1, Info=0.
 */
export function calculateRiskScore(findings: SecurityFinding[]): RiskScoreResult {
  const breakdown: Record<string, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 0,
    [Severity.Medium]: 0,
    [Severity.Low]: 0,
    [Severity.Info]: 0,
  };

  for (const finding of findings) {
    if (breakdown[finding.severity] !== undefined) {
      breakdown[finding.severity]++;
    }
  }

  let score = 0;
  for (const [severity, count] of Object.entries(breakdown)) {
    score += count * (SEVERITY_WEIGHTS[severity] ?? 0);
  }

  let rating = "Low Risk";
  for (const threshold of RISK_THRESHOLDS) {
    if (score >= threshold.min) {
      rating = threshold.rating;
      break;
    }
  }

  return {
    score,
    rating,
    breakdown,
    totalFindings: findings.length,
  };
}

/**
 * Sort findings by severity (Critical first).
 */
export function sortFindingsBySeverity(findings: SecurityFinding[]): SecurityFinding[] {
  const severityOrder: Record<string, number> = {
    [Severity.Critical]: 0,
    [Severity.High]: 1,
    [Severity.Medium]: 2,
    [Severity.Low]: 3,
    [Severity.Info]: 4,
  };

  return [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99)
  );
}
