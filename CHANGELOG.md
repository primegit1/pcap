# Changelog

## 0.1.0 — review fixes

### Fixed (confirmed bugs)

- **pcapng:** little-endian files (what Wireshark/dumpcap write on x86) parsed to 0 packets. The
  parser now honors each section's byte-order magic, tracks interfaces per section, validates block
  lengths, and reports truncation. Interface options were also read at the wrong offset, so
  `if_tsresol` (nanosecond timestamps) was ignored; fixed.
- **pcap:** the byte-swapped *nanosecond* magic was wrong (`0x4c3b2a1d` instead of `0x4d3cb2a1`), so such
  files were rejected. Records are no longer silently skipped; zero-length, truncated and implausible
  records are counted and surfaced as warnings.
- **Large captures:** `Math.max(...timestamps)` threw `RangeError` at roughly 150k packets (reproduced
  at 200k packets in the original pipeline). Replaced by loops everywhere.
- **Timeline / combine:** no longer assumes packets are time-ordered; combined captures are merged in
  time order with unique packet indices.
- **Port scan:** replies were counted as probes, so a browser opening parallel connections made the
  *server* look like it was scanning the client. Now only TCP SYN-without-ACK (and unanswered UDP)
  count, inside a 60 s sliding window; a horizontal-sweep detector was added.
- **SYN flood:** looked for SYN-ACKs on the wrong side, so any 100 SYNs fired. Now windowed and
  compares SYNs with the server's SYN-ACKs.
- **Directional flows:** one-way flows produced false positives such as "HTTP on non-standard port"
  for every HTTP *response*, and double-counted connections. Flows are now bidirectional with an
  initiator/responder and per-direction counters; "large transfer" reports the real sender.
- **HTTP rule:** responses (`HTTP/1.1 200 OK`) were reported as an "unusual HTTP method".
- **React:** `PacketViewer`, `Assets` and `Findings` called hooks after an early return (crash when the
  analysis result appears after first render). Fixed.
- **Findings:** IDs collided across rule files (`finding-1` in three files); now unique per run.
  Duplicates are merged instead of discarded.
- **Exports:** CSV formula injection (attacker-controlled strings), recommendations missing from
  exports, risk score duplicated in two places.
- **Upload:** extension check was case-sensitive; now content-sniffed. Size limits and rejection reasons added.

### Changed

- Parsing and analysis run in a Web Worker (previously on the main thread; the old worker/hooks were
  unused). Progress, cancel, zero-copy transfer of packet buffers.
- Link types beyond Ethernet (SLL, SLL2, raw IP, loopback) are supported; unsupported ones are reported.
- Findings carry `confidence`, `occurrences`, capture-time range, packet references and flow IDs; the
  Findings page can open the referenced packets in the Packet Viewer.
- Faster analysis: payload ASCII decoding rewritten (identical output), pre-filtered packet subsets for
  ten rules whose own first filter makes this safe, one fewer retained copy of every packet.
- `parsers/index.ts` (2,900 lines) split into `detect.ts`, `payload.ts` and `summaries/*`.

### Added

- C2 beaconing rule, horizontal port sweep rule.
- Vitest suite (56 tests) with synthetic capture builders; ESLint, Prettier, CI workflow, README,
  LICENSE, SECURITY.md, CONTRIBUTING.md.

### Removed

- Dead code: `performance-optimizations.ts` (broken duplicates), unused hooks/worker, unused
  `ProgressBar`, svgr plugin and its shims, stale design notes.
