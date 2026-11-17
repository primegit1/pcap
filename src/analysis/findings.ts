import type { Confidence, SecurityFinding } from "../types/analysis";

/**
 * Shared finding-ID allocator.
 *
 * Every rule used to keep its own module-level counter, and several started at 0 with the
 * same prefix ("finding-1" in network.ts, igmp.ts and snmp.ts), so IDs collided and the
 * Findings page (which keys rows and expansion state by ID) mixed findings up.
 * One counter, reset at the start of each analysis run, makes IDs unique per result.
 */
let counter = 0;

export function resetFindingIds(): void {
  counter = 0;
}

export function nextFindingId(): string {
  counter += 1;
  return `F-${String(counter).padStart(5, "0")}`;
}

/** Evidence arrays are capped so a flood of matches can't bloat the result. */
export const MAX_PACKET_REFS = 50;

export interface FindingInput
  extends Omit<SecurityFinding, "id" | "timestamp" | "confidence" | "occurrences"> {
  confidence?: Confidence;
}

/**
 * Build a finding with a unique ID, capture-time timestamps, and evidence references.
 * Rules that know exactly which packets triggered them should pass `packetIndices`,
 * `firstSeenUs` and `lastSeenUs`; the rest are enriched generically by runAllRules.
 */
export function createFinding(input: FindingInput): SecurityFinding {
  const firstSeenUs = input.firstSeenUs;
  return {
    ...input,
    id: nextFindingId(),
    confidence: input.confidence ?? "medium",
    occurrences: 1,
    packetIndices: input.packetIndices?.slice(0, MAX_PACKET_REFS),
    timestamp: firstSeenUs ? Math.floor(firstSeenUs / 1000) : 0,
  };
}

export function formatUs(us: number): string {
  return new Date(Math.floor(us / 1000)).toISOString();
}
