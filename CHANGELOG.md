# Changelog

## v1.8.0
Drive a run from an enterprise DNS export and cross-reference it against the
ZPA segment inventory. Validated 296/296 on Linux, up from 247/247, plus 80/80 on a new
--dns-csv regression suite.

The segment inventory says what ZPA is *configured* to steer. A DNS export
says what actually *exists*, and — because it is captured from a DNS-server
vantage with no Client Connector in the path — what each name resolved to
before ZPA. Joining the two answers the question neither side can answer
alone: which internal names are not enrolled in ZPA at all.

- **`--dns-csv [CSV]`** drives the run from the export instead of the
  segment list. Bare `--dns-csv` looks for `dns_destinations.csv` beside the
  script. Reads the standard export schema (`Name`, `RecordType`,
  `TerminalName`, `ResolvedIPs`, `OnlyExternalIPs`, `HasAnyInternalIP`,
  `IsWildcard`, `LookupStatus`), tolerates an Excel BOM or a cp1252 file,
  and reports every row it skipped and why.
- **No guessed ports, by design.** An enterprise-wide record list spans
  every server role. Ports come only from a matching segment, and only where
  that segment says something specific: a segment defining discrete ports is
  probed on them, a segment whose ranges are all wide is not probed at all,
  and a name matching no segment is resolved only. Resolution alone settles
  steering, because steering is visible in what the resolver returns.
- **Most records land in the unprobed case, deliberately.** Few names match
  a segment by exact FQDN; they are caught by a wildcard segment with a
  broad range, which says nothing about what any one host listens on.
  `expand_ports` keeps range endpoints first, so `1-65535` would yield ports
  1, 65535, 2 and 3 — across thousands of names that is a scan producing
  only timeouts. The filter is per *range*, so `443, 8000-8100` still
  contributes 443 while discarding the range. Everything dropped is counted
  and attributed to the segment that caused it.
- **Why that matters twice over.** A fixed port set would report a steered
  database host as `TIMEOUT`, which the summary classifies as "nothing
  answered — traffic may not be steered": the exact opposite of the truth.
  It would also constitute a horizontal port scan across the enterprise from
  a managed endpoint.
- **Two gaps, reported separately.** *Steering gap* — enrolled in a segment
  but resolved to an internal IP rather than into the synthetic range.
  *Enrolment gap* — internal in DNS and in no segment at all, so it cannot
  be steered until one covers it. Plus DNS divergence, where the endpoint
  resolved to an address the export does not list.
- **New output.** A `DNS CROSS-REFERENCE` console section with per-verdict
  meanings, eight `dns_*` CSV columns, three clickable report tiles, a
  `dns_csv` block in `meta.json`, and `NEXT STEPS` entries for each gap.
- **Bounded.** Ports per name are capped at 4 regardless of `--scope`.
  `--scope` deliberately does not thin the export — sampling would drop
  exactly the unenrolled names being hunted — and `--dns-sample N` caps it
  explicitly instead.
- Works without credentials: with no segment source it degrades to a
  resolution-only sweep and says so.
- Fixed: `write_html_report` indexed `row["domain"]` directly and raised
  `KeyError` on a caller-supplied row missing that column.

## v1.7.0
L7 verification reaches the summary, and three measurement fixes behind it.
Validated 247/247 on Linux.

A run can report `249/249 TCP REACHABLE`, `0 FAILING PROBES` and
`0 actionable findings` while fewer than half of those probes had an
application respond. Every number in that headline is correct; none of them
says so.

- **`--l7` results now appear in the summary and the report.** The data was
  already written to every CSV, but nothing that summarised a run mentioned
  it: no console line, no HTML tile, and `FINDINGS` printed "every probed
  entry behaved as expected" on the strength of the TCP result alone. There
  is now an `L7` line beside `RESULTS`, an `L7 VERIFICATION` section with a
  per-outcome breakdown and per-segment attribution, two clickable report
  tiles (`L7 verified`, `no app response`), an `l7` block in `meta.json`,
  and a `NEXT STEPS` entry. `FINDINGS` no longer claims a clean pass when
  the L7 step disagrees.
- **Why the distinction matters.** Through ZPA a TCP connection is accepted
  locally by Client Connector, so a port reads as `OPEN` whether or not
  anything behind the App Connector is serving. Reachability is not an
  application pass, and the tool now says so rather than implying otherwise.
- **`--l7-timeout`, separate from `--timeout`.** The L7 step shared the
  connect budget, which is tuned for a connect that completes locally — but
  a TLS handshake has to traverse the App Connector to the backend. Working
  applications were being reported as L7 timeouts. The default is 4x
  `--timeout`, clamped to 5-15s; an explicit value is not clamped.
- **`OPEN_NO_L7_RESPONSE` split into `OPEN_NO_L7_DATA` and
  `OPEN_NON_HTTP`.** One status covered two unrelated findings: a peer that
  accepts and then sends nothing (the ZPA signature of a connector with
  nothing behind it) and a peer that answers in a protocol this probe does
  not speak (a live service). Existing CSVs keep their old values; new runs
  use the split.
- **Fixed: latency included name resolution, and `--timeout` bounded only
  half the probe.** `socket.create_connection()` resolves inside the region
  it timed, so DNS latency was reported as connect latency — a run with
  `--timeout 2` could legitimately report a 5.8s probe. Resolution now
  happens before the clock starts. The probe still resolves per attempt, so
  it takes exactly the path `create_connection` would have.
- **Fixed: `--synthetic-net` before the subcommand failed unhelpfully.**
  The natural global position produced `argument cmd: invalid choice:
  '100.64.0.0/16'`, an error that never names the option typed. It is now
  accepted in either position; on `compare`, `report` and `tenants` — which
  read the range from the run's saved metadata — it is rejected with an
  explanation rather than silently ignored.

## v1.6.0
The ZCC synthetic IP range is now configurable. Validated 207/207 unit and
52/52 end-to-end on macOS; unit suite also green on Linux and Windows 11.

- **`--synthetic-net CIDR`, and a per-tenant `synthetic_net` field.** The
  range was hardcoded to Zscaler's documented default `100.64.0.0/10`, but
  it is tenant-configurable and commonly narrowed (e.g. `100.64.0.0/16`).
- **This was a correctness bug, not a missing setting.** `100.64.0.0/10` is
  the RFC 6598 carrier-grade NAT range. Against a `/16` tenant the assumed
  range is 64x too wide, leaving 4.1M addresses the tool would report as
  ZPA-steered that the tenant never issues — and on a CGNAT network (hotel
  Wi-Fi, mobile hotspot) an ISP-assigned address falls in exactly that gap,
  producing a false `ZPA IS STEERING` verdict.
- **Preflight states the range** and flags when it is still the default, so
  a misconfiguration is visible before probing rather than never.
- **Fixed: `--tenant` crashed on `export-targets` and `sipa-verify`.**
  `select_tenant()` read `args.yes` directly, but only `test` defines
  `--yes`, so both died with `AttributeError` — the exact commands
  `--tenant` exists to serve.
- Invalid or IPv6 ranges are rejected at startup on every subcommand.

## v1.5.0
Port-level parallelism. Validated 195/195 on Linux and macOS, 194/194 on
Windows 11.

- **Ports within a segment now probe in parallel.** The pool previously
  submitted one task per *target* and walked that target's ports serially,
  so concurrency was capped by target count rather than probe count — a
  50-target run could not beat `ports x timeout` no matter how many workers
  were configured. Same 400-probe workload, before vs after:
  workers 20: 48.3s -> 40.5s; 50: 16.2s -> 16.2s; 100: 16.2s -> 8.2s;
  200: 16.2s -> 4.2s.
- `run_test` runs two pooled phases: resolve each target once, then one
  task per `(target, port)`. Deliberately a single flat pool — nesting a
  pool per target would multiply to `workers x ports` and exhaust the
  process FD limit (256 by default on macOS).
- Probes still connect **by hostname**, not the resolved IP. That looks
  redundant beside `resolved_ip`, but it is load-bearing: ZPA steering is
  FQDN-driven, so connecting to a resolved address would bypass Client
  Connector's app-list matching and silently invalidate the run.
- Progress reports ports probed rather than targets.

## v1.4.2
Validated 195/195 on Linux and macOS, 194/194 on Windows 11.

- **The HTML report's stat tiles are now click-to-filter.** Clicking
  *failing probes*, *TCP reachable*, *flaky*, *DNS failures* or
  *ZPA-steered domains* narrows the results table to exactly those rows;
  clicking again clears it. Previously the tiles were inert and the only
  way to narrow the table was the free-text box, which matched whole rows
  — typing `OPEN` also matched `OPEN_FLAKY` and any segment name
  containing "open", and there was no way to ask for "everything that
  failed".
- **Status cells are clickable too** — click a `TIMEOUT` cell to see every
  timeout.
- Tile filters compose with the search box, are keyboard reachable, and
  show a "showing N of M rows" bar with a clear button. The median-latency
  tile is deliberately not clickable: a median is not a set of rows.
- Rows now carry `data-status` / `data-proto` / `data-steered`, so the
  filter predicates match the Python that computed the tile counts rather
  than re-deriving state from rendered text. The suite asserts each tile's
  filter selects exactly what the tile claims, so the two cannot drift.
- The report remains fully self-contained — no external references.

## v1.4.1
Validated 184/184 on Linux and macOS, 183/183 on Windows 11.

- **The name-typing confirmation is now scoped to production tenants.**
  Non-production selection is a single `y/N`. Requiring the same friction
  everywhere trains people to type through it, which weakens the prompt
  exactly where it matters; production still requires typing the tenant
  name and still rejects a second bare `y`.

## v1.4.0
Saved tenants. Validated 178/178 on Linux and macOS, 177/177 on Windows 11
(one assertion is POSIX-only).

- **New `tenants` subcommand** — `add`, `list`, `remove`. A pilot usually
  spans a model/test tenant and production; saving each removes the need to
  retype four OneAPI values per run, and removes the chance of pasting the
  wrong set.
- **Selecting a tenant is confirmed twice**, and the second confirmation
  requires typing the tenant name rather than another y/N. A second yes/no
  gets answered reflexively; the failure being guarded against is sweeping
  production while believing you are on the model tenant. Production
  tenants are flagged `** PRODUCTION **` in every listing.
- `--tenant NAME` skips the menu and still confirms twice.
  `--tenant NAME --yes` skips confirmation, for scripted runs where the
  choice is already explicit. Explicit `--client-id` / `--vanity-domain` /
  `--customer-id` still win over saved values, and the environment
  variables behave as before.
- **The client secret is only stored if you opt in.** The default remains
  that it is prompted each run and never written to disk; opting in states
  plainly that it is stored in plaintext.
- The store is `~/.zpa-connectivity-tester/tenants.json`, created mode
  `0600` at creation time (not chmod'd afterwards, so there is no window
  where it is world-readable), inside a `0700` directory. Loading warns if
  the permissions have since been widened. `$ZPA_TENANT_STORE` overrides
  the location.

## v1.3.1
Safety fix. Validated 155/155 on Linux, macOS, and Windows 11.

- **Runs that cannot finish are now refused, not merely confirmed.** A
  `--scope full` run against a 22-segment tenant (3,962 entries, 156 CIDR
  entries expanded to every usable host, against full port ranges) planned
  ~456 billion probes — roughly 3,615 years at 20 workers, and still about
  4 years if every probe answered instantly. The tool printed the count and
  asked for confirmation, but a number that large does not read as
  impossible. It now estimates wall-clock duration and exits above a
  12-hour worst case, listing the flags that narrow the run
  (`--scope sample`, `--max-ports`, `--cidr-hosts`, `--segment`,
  `--enabled-only`) and stating that a sweep of that size reaches the App
  Connectors as a port scan.
  - `--yes` does **not** bypass the ceiling: unattended is not unbounded.
  - `--force-huge-run` overrides it deliberately.
- **The confirmation prompt now shows estimated duration** at ordinary
  sizes too, so the cost of a run is visible before agreeing to it.
- **README:** the `compare` example used `<host>`/`<ts>` placeholders.
  Pasting it verbatim fails in bash and zsh with
  `no such file or directory: host`, because `<` is a redirection operator
  and the shell errors before the tool runs. Replaced with plain
  placeholders plus a glob form that works as written.

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
