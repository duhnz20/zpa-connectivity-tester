# Changelog

## v1.3.0
Output is now built around what to do next, rather than a flat probe dump.
Validated 145/145 on Linux, macOS (Python 3.9), and Windows 11 (Python 3.14).

- **A verdict line** states whether the run proved anything: `ZPA IS
  STEERING`, `NO STEERING OBSERVED`, `BASELINE CAPTURED`, or `BASELINE
  INVALID`. The last one catches a silent trap — running `--phase pre` on
  an endpoint that is already enrolled records a post-state labelled
  "pre", which previously only surfaced as a nonsensical `compare`.
- **Failures are grouped by host and by what they imply.** `REFUSED` is
  no longer lumped in with `TIMEOUT`: a refusal proves the path works and
  nothing is listening, while a timeout is the signature of traffic not
  being steered. One unreachable host with a wide port range now prints
  one line instead of one line per port.
- **Latency is summarized instead of discarded.** Median/p95/max plus the
  slowest segments per run, and `compare` reports the pre-vs-post delta.
  Deltas from small samples are labelled indicative rather than stated as
  findings.
- **Segment health table** — per-segment probed/open/failed/steered, the
  view that answers "which segments are broken".
- **ZPA-steered domains are listed**, not just counted.
- **Status histogram** and consistent section headers throughout. Rules
  are ASCII, since box-drawing characters corrupt on legacy Windows
  consoles.
- `meta.json` gains `verdict`, `status_counts`, `latency`,
  `slowest_segments`, and `intercepted_domain_list`; the HTML report
  gains a verdict banner and a median-latency tile.
- **Coverage section** states what fraction of the inventory was actually
  probed, so a heavily sampled run cannot read as full validation.
- **Next steps** are derived from the run's own results.

## v1.2.3
- **Fixed a crash when `--targets-file` points at a missing file.** The
  preflight check flags it, but that failure is overridable (the prompt, or
  `--yes`), so the run continued and died with a raw `FileNotFoundError`
  traceback inside `load_segments`. It now exits with the reason and the
  `export-targets` command that creates the file. Unreadable and malformed
  targets files exit cleanly too.

## v1.2.2
Bug-fix release. Validated 105/105 (unit) and 28/28 (end-to-end CLI) on
Linux, macOS (Python 3.9), and Windows 11 (Python 3.14).

- **Results CSV is now written as UTF-8.** Windows still defaults to the
  locale code page (cp1252), so a segment name containing a character
  outside it raised `UnicodeEncodeError` *after every probe had already
  run* — losing the entire run. All file I/O is now explicit UTF-8;
  reads accept a BOM, so a CSV re-saved from Excel still parses.
- **`--max-ports` no longer drops individually-defined ports.** Range
  endpoints were front-loaded per-range but truncated globally, so a
  segment defined as `1-1000` plus `443` probed 1, 1000 and the low
  interior — and silently skipped 443. Endpoints of every range are now
  queued ahead of every range's interior.
- **`--cidr-hosts 1` no longer crashes** with `ZeroDivisionError` (the
  spread formula divides by `n-1`).
- **A targets file that is a bare JSON array now loads.** The array shape
  was advertised in the code's own fallback but `.get()` was called
  before the type was tested, raising `AttributeError`. A file that is
  neither shape now exits with a clear message.
- **A segment without a `name` key no longer aborts the run** — it is
  labelled `(unnamed-<id>)`. Non-dict entries are skipped.
- **One failing probe worker no longer discards the whole run.**
  `fut.result()` was called outside any handler, so a single unexpected
  exception threw away every row collected so far. Failures are now
  recorded as `PROBE_ERROR:<type>` rows and counted in the metadata.
- **Transient network errors during the inventory pull are retried.**
  Only HTTP 429/5xx were; a DNS or TLS blip mid-pagination surfaced as a
  raw traceback. `URLError` is now retried and, if it persists, reported
  with the `--ca-bundle` hint.
- **`compare`/`report` reject a CSV that is not from this tool** with a
  message naming the missing columns, instead of a `KeyError`.
- **Added `--no-show-failures`.** `--show-failures` defaulted to on with
  `store_true`, so it could never actually be turned off.
- `sipa-verify` tolerates non-string values in an `--anchor-map` file.

## v1.2.1
- **Interactive credential entry** — the tool now prompts for the four
  OneAPI values (client ID / vanity domain / customer ID / secret) when
  they are not already in the environment, so end users run it with zero
  setup. Flag > env > prompt; secret read hidden, never stored.
- README reframed around a one-command quick start.

## v1.2.0
- **New `sipa-verify` subcommand** — verifies Source IP Anchoring by
  reflecting the observed public egress IP through a SIPA-enrolled endpoint
  and comparing it to the configured anchor. Enrollment check against the
  segment inventory + baseline-reflector contrast guard against false
  positives.
- Validated 80/80 on Linux, macOS (Python 3.9), and Windows 11
  (Python 3.14).

## v1.1.0
- Validated the ZPA OneAPI paths against the official `zscaler-sdk-python`
  source. Fixed the **dual port-shape bug**: ZPA returns ports as both
  `tcpPortRange` (objects) and `tcpPortRanges` (flat pairs) in the same
  payload; reading only one silently found zero ports and falsely passed.
  Now reads and unions both.
- Added `--microtenant-id` (microtenant segments are not returned by the
  default parent view).
- Per-cloud base URLs documented (commercial `api.<cloud>.zsapi.net`, gov
  `api.zscalergov.net/.us`).
- Fixed a Windows non-interactive crash (`isatty()` unreliable on Windows
  when stdin is `NUL`; now EOF-driven). Documented the ~2s Windows
  connection-refusal timing (don't set `--timeout` below 3 on Windows).
- Preflight DNS check no longer false-fails on filtered public resolvers.
- Retries with jitter + `OPEN_FLAKY` status; optional `--l7` TLS/HTTP
  verification; per-run `.meta.json`; self-contained HTML reports.

## v1.0.0
- Initial release: `preflight`, `export-targets`, `test`, `compare`,
  `report`. Full/sample scope, all four ZPA entry types (FQDN, IP, CIDR,
  wildcard), pre/post diffing, credential-free frozen-inventory mode.
