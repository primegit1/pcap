# Contributing

## Setup

```bash
npm ci
npm run dev        # local dev server
```

Before opening a pull request, run everything CI runs:

```bash
npm run typecheck && npm run lint && npm test && npm run build
```

## Adding or changing a detection rule

1. Put the rule in `src/analysis/security-rules/` (a new file, or next to related rules). A rule is a
   function `(packets: Packet[]) => SecurityFinding[]` (or `(flows: FlowRecord[]) => ...`).
2. Build findings with `createFinding()` from `src/analysis/findings.ts`. It assigns a unique ID and
   lets you attach evidence. Whenever you know the exact packets, pass `packetIndices`,
   `firstSeenUs`, `lastSeenUs` (and `flowIds` for flow-based rules) so the UI can link to them.
3. Set `dedupKey` when two detections can legitimately share a title and affected IP
   (for example the same scan type from two different scanners); otherwise they are merged.
4. Set `confidence` honestly (`low` / `medium` / `high`).
5. Register the rule in `runAllRules()` in `src/analysis/index.ts`. If the rule only ever looks at one
   kind of packet, pass a selector (e.g. `(i) => i.tcp`) so it gets a pre-filtered list. Only do this
   when the rule's own first filter guarantees it would have ignored all other packets.
6. Add tests in `src/analysis/*.test.ts` using the synthetic capture builders in
   `src/test-utils/pcapBuilder.ts`. Cover at least one true positive **and** one benign look-alike.
   Detection rules without a false-positive test will not be merged.

## Parsers

Parsers must never trust lengths from the file. Validate them, never allocate based on an unvalidated
value, and throw a descriptive `Error` (or report via the capture warnings) instead of silently skipping
data. Add a test with a malformed input.

## Style

`npm run format` runs Prettier. Keep comments for *why*, not *what*.
