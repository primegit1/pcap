# Security Policy

## Reporting a vulnerability

Please report security issues privately using GitHub's **"Report a vulnerability"** button on the
repository's *Security* tab (private vulnerability reporting). Do not open a public issue for
anything exploitable. Include a minimal capture or steps that reproduce the problem.

## Threat model

PCAP Security Analyzer parses **untrusted input** (capture files) entirely in the user's browser.
Nothing is uploaded; there is no backend.

What we consider in scope:

- A crafted capture that crashes, hangs, or exhausts the memory of the analysis worker
  (parsers must fail with an error, never loop or over-allocate).
- Script injection through capture-derived strings in the UI or in exported reports
  (the HTML export escapes every interpolated value and ships a restrictive CSP; the CSV export
  neutralizes spreadsheet formulas).
- Supply-chain issues in the build or dependencies.

Out of scope: findings produced by the detection rules being wrong (false positives/negatives) —
please open a normal issue for those, ideally with a minimal capture.

## Hardening already in place

- Capture format is detected from magic bytes, not file names; unknown files are rejected.
- Per-file size limit (500 MB) and a warning above 100 MB.
- Record/block lengths are validated; truncated captures are reported rather than silently trimmed.
- Parsing and analysis run in a Web Worker, so a pathological capture cannot freeze the page.
