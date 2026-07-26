# Changelog

## v2.1.0-windows
PowerShell removed from the probe path, and four bugs that produced
confidently wrong answers. Validated 444/444 on Windows 11 / Python 3.14.6,
up from 385, plus an end-to-end run and two regression suites.

### Startup is 71x faster

The four environment probes spawned nine PowerShell processes. Each
`powershell -NoProfile -Command` costs roughly 175ms of process startup
before it does any work. They are now `winreg` and `ctypes` calls, and every
native answer was checked to AGREE with the PowerShell answer it replaced —
the same interface index, the same adapter, the same resolvers, the same
NRPT count, the same Client Connector state.

| probe | before | after |
|---|---|---|
| Client Connector detection | 935 ms | ~9 ms |
| synthetic-range routing | 1,565 ms | ~0.1 ms |
| DNS servers + NRPT | 1,107 ms | ~0.7 ms |
| proxy | 239 ms | ~0.1 ms |
| **all four** | **3,587 ms** | **50.5 ms** |

- Service state through `OpenSCManager`/`QueryServiceStatusEx`, which needs
  only read rights and so works unprivileged. Installed-but-stopped stays
  distinct from absent, because the remedies differ.
- Processes through `CreateToolhelp32Snapshot` rather than parsing
  `tasklist`.
- Routing through `GetBestRoute`, which also yields the next hop that the
  previous implementation needed a second command to obtain.
- NRPT read from both the Group Policy hive and the Dnscache hive. Client
  Connector applies its policy locally, which writes the latter — reading
  only the former would have missed it.
- WinHTTP read through its own API instead of parsing the undocumented
  binary registry blob behind it.

Every ctypes binding declares `argtypes` and `restype`. Without them a
64-bit handle is silently truncated; that defect occurred three times during
development, so the validator now asserts it for all eleven bindings rather
than leaving it to discipline.

### Wrong answers

- **An ALL-CAPS DNS export silently produced worthless verdicts.**
  `_dns_row_get` documented case-insensitive column lookup and performed an
  exact dictionary lookup. `RecordType`, `ResolvedIPs` and
  `HasAnyInternalIP` all read as empty, so every name classified
  `NOT_STEERED_UNKNOWN`, the run reported success, and the entire
  cross-reference was meaningless. Now genuinely case-insensitive, and a
  missing classifying column is called out rather than read as empty.
- **A run whose filters matched nothing still printed a causal verdict.**
  With `--phase pre` that wrote a zero-target `BASELINE CAPTURED` to disk to
  be diffed later. It now refuses and names the filters responsible.
- **`estimate_duration` ignored retries**, understating the worst case by
  roughly half at the default `--retries 1` — and `confirm_run` gates on
  that number, which `--yes` does not bypass.
- **The metadata dictionary contained `slowest_segments` twice**, so a full
  scan of every row was computed and discarded.

### L7 verification

A peer that accepts a connection and then says nothing used to cost twice
the L7 budget, because the TLS read and the HTTP read each blocked a full
timeout on the same dead peer. One shared deadline now covers both attempts.

The result deliberately remains `L7_ERROR` rather than becoming
`OPEN_NO_L7_DATA`. Those describe different situations, and collapsing them
would report a slow application as a silent one — the precise misreading
that a separate L7 budget exists to prevent. The second attempt keeps a
generous floor so an application that fails TLS quickly but answers HTTP
slowly is not misclassified by a small remainder.

### Robustness

- **Results survive an unwritable output directory.** They previously lived
  only in memory until a single unguarded write; a read-only directory or a
  path over MAX_PATH discarded an entire run at the last step. The CSV and
  metadata now fall back to the temp directory and say so.
- **Invalid numeric options are rejected at parse time.** `--workers 0`,
  `--retries -1` and `--timeout 0` previously failed deep inside the run,
  after the credential exchange, the full inventory fetch and the operator's
  confirmation.
- **The tenant store no longer claims a protection it did not verify.** It
  asserted a numeric file mode, which describes nothing on NTFS, about a
  file whose ACL may have failed to apply. It now reports what is actually true
  and reads the ACL back to confirm it.
- Console tools return OEM-encoded output while Python decoded it as ANSI;
  a bad decode raised out of functions documented as never raising. All four
  call sites decode leniently and the handlers catch it.
- Startup sets the console output code page as well as the stream encoding.
  Setting only the stream renders every non-ASCII character as mojibake in a
  real console.
- The Client Connector version was invisible to a 32-bit interpreter,
  because the uninstall registry was read without the 64-bit view.
- DNS resolvers were collected from every network interface the registry has
  ever held, presenting disconnected adapters as live. Only interfaces
  holding an address are reported.
- The ACL check compared against English principal names and so mis-warned
  on any localized Windows. It is now locale-independent by construction.
- The module remains importable on other platforms, so the platform guard
  can print a clear message instead of the interpreter raising an import
  error first.

## v2.0.0-windows

**Breaking: this build is now Windows-only.** It refuses to run anywhere
else. Everything that was a portable approximation is now a native Windows
answer.

Native surfaces, each recorded in the run metadata:

- **`Find-NetRoute`** against the first host of the synthetic range — the
  `route -n get` equivalent. It resolves what the stack would actually do
  with a packet to that address, *before* any probe runs, so a run can
  report "Private Access is off" instead of collecting a directory of false
  negatives and calling them failures.
- **ZCC state from services + processes + the uninstall registry**, so
  *installed but not running* is distinct from *not detected* — the remedies
  differ (start the service, versus install the client).
- **`Get-DnsClientNrptPolicy`** as the split-DNS signal. ZCC drives
  per-domain resolution through the Name Resolution Policy Table; zero rules
  on an enrolled host means names are resolving via the LAN resolver
  whatever the tray icon says. There is no portable equivalent of this.
- **WinINET + WinHTTP proxy state**, since a proxy changes what a successful
  connect means.
- **`SetThreadExecutionState`** holds a power request for the probe phase,
  so a long run cannot be failed wholesale by idle sleep.
- **`ipconfig /flushdns`** only — and it needs no elevation, so the guidance
  no longer advises an elevated re-run. A failure means policy or a stopped
  DNS Client service.

Defaults measured on Windows 11 / Python 3.14.6, not guessed:

- **`--workers` 20 -> 400.** 20 gives ~569 probes/s, 200 ~1,106, 400 ~1,827,
  800 only ~1,888 — three percent more for double the threads. Windows has
  no small per-process socket cap to raise.
- **`--timeout` 5.0 -> 3.0.** Windows delivers a TCP connection refusal at
  ~2.04s, so anything below ~2.5 reports `REFUSED` as `TIMEOUT` — and the
  summary reads those oppositely. The run warns if you go below the floor.

**Security: the saved client secret now actually gets protected.** The
tenant store claimed "mode 0600", but that describes nothing on Windows and
the readable-by-others check was a no-op — so the file inherited whatever
the profile granted and nothing ever verified it. The ACL is now set explicitly with inheritance stripped, granted to the
current user only, read back, and a failure is reported rather than assumed.

Two bugs in that fix, both found only by running on Windows:

- `_current_user` built `%USERDOMAIN%\%USERNAME%`, but on a machine that is
  not domain-joined that is `WORKGROUP\user` while the real principal is
  `COMPUTERNAME\user`. `icacls` rejected it with rc1332, "no mapping
  between account names and security IDs". It now asks `whoami`, which
  reports the form `icacls` accepts.
- The ACL parser split each line on `:` and captured the drive letter `C` as
  a principal, so it matched nothing real and missed a deliberate
  `Everyone:(R)` grant. It now splits on the ACE marker `:(`.

Validator re-coded for Windows — **385 checks, all passing on Windows 11**:

- Descriptor-leak detection uses `GetProcessHandleCount` (there is no
  no handle-count file to read). This needs `restype`/`argtypes` set:
  without them
  the `GetCurrentProcess` pseudo-handle truncates to 32 bits and the call
  fails silently — which it did, until caught.
- Tenant-store protection is asserted by reading the real ACL back, in both
  directions: silent when restricted, and catching a deliberately widened
  grant.
- Every native probe is covered for *shape*, not for values only true on one
  machine: `_ps`, `Find-NetRoute` parsing and its range-keyed cache, NRPT,
  proxy, `SleepBlocker` acquire/release, and `_current_user`.
- The verdict is exercised across all four routing-evidence combinations.
- The `--timeout` default is asserted against the parser itself, so it
  cannot drift below the refusal latency that justified it.

Docs rewritten for Windows: `py -3` invocation, PowerShell/cmd continuation
noted, the preflight section shows real Windows output, and shell-specific
line continuations that only work in other shells are gone from every
example. All 12 documented
commands verified to parse on Windows.

## v1.8.2
Fixes a false finding that contradicted the run's own verdict.

A `--dns-csv` run without a segment source reported every name as an
enrolment gap — including the ones ZPA was demonstrably steering. On any
export large enough to show it, the verdict reads `ZPA IS STEERING — <N>
domains` while `ENROLMENT GAP (<M>) — in no ZPA segment at all` appears
twenty lines below it, with each CSV row carrying `dns_in_zpa=False` next to
`dns_verdict=STEERED`.

- **`dns_in_zpa` is now tri-state.** `False` means checked and absent; `""`
  means never checked, which is what an absent segment inventory actually
  produces. Recording "unasked" as "absent" is what manufactured the finding.
- The enrolment gap, its report tile, its click-to-filter predicate and its
  `NEXT STEPS` entry all now require enrolment to have been *checked*. When
  it was not, the summary says `UNKNOWN — no segment inventory was loaded`,
  the tile reads `n/a`, and `NEXT STEPS` tells you to add `--targets-file`
  rather than inventing a coverage number.
- The segment column reads `(no segment inventory loaded)` instead of
  `(not in any ZPA segment)` when nothing was loaded to match against.
- A name known absent from every segment is no longer counted as a
  *steering* gap — not being steered is the expected consequence of not
  being enrolled, and conflating the two hid the real cases.
- **Portability fix in the test suite itself.** The descriptor-leak check
  read a handle-count path that does not exist on Windows, so it silently
  never ran here. It now uses GetProcessHandleCount.
- Names whose enrolment is unknown still surface when they resolve to an
  internal IP instead of into ZPA; the wording just no longer claims they
  are enrolled.

## v1.8.1
Ordered probes and a sharper scan warning.

- **`--dns-ports` is now walked in the given order, stopping at the first
  port that answers**, then moving to the next destination. A liveness check
  does not need a port inventory: once one port replies the path through ZPA
  is proven, and every further connect is pure scan volume. On a host where
  the first port is open that is one connect instead of four. `REFUSED`
  counts as an answer — something replied, which proves the path as
  conclusively as an accepted connection.
- Ports a segment actually defines are **not** ordered; there each port's
  individual status is the point. `--dns-ports-all` opts out.
- An `ORDERED PROBES` summary section reports destinations answered, ports
  not tried, and connects avoided, so the saving is visible rather than an
  unexplained gap between planned and actual.
- **The sweep warning now names your ports.** `SCAN_SENSITIVE_PORTS` covers
  the ports whose horizontal sweep is a standard IDS/EDR signature (21, 22,
  23, 111, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017), and
  the run names whichever of them you asked for instead of issuing a vague
  caution. 443 is deliberately absent — an HTTPS sweep is unremarkable.

## v1.8.0
Drive a run from an enterprise DNS export and cross-reference it against the
ZPA segment inventory. Validated 315/315, up from 247/247, plus 101/101 on a new
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
- **`--dns-ports PORTS`** names TCP ports for records the segments cannot
  supply one for. It never overrides a segment that defines discrete ports,
  and the default is still none. Ports whose service is UDP (123 NTP, 161
  SNMP, 514 syslog, ...) are flagged at startup and in NEXT STEPS: this tool
  probes TCP only, so a connect there times out on a healthy host and the
  summary would read that TIMEOUT as "traffic may not be steered" — a
  protocol mismatch turned into a false ZPA finding on every host. Each
  requested port is also cross-checked against the matched segment's own
  `udpPortRange`, which is direct evidence from ZPA rather than an inference
  from a well-known-ports table. The run states the resulting connect
  volume, because a fixed port set across a whole export is a horizontal
  scan and 111/161 are classic enumeration signatures.
- Fixed: `next_steps` read `args.dns_csv` directly, the third recurrence of
  the attribute-access bug that broke `--tenant` in v1.8.1. All summary
  helpers now tolerate a namespace assembled without the newer flags, with a
  general regression guard rather than one check per flag.
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
Validated 247/247 on Windows 11.

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
52/52 end-to-end on Windows 11.

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
Port-level parallelism. Validated 194/194 on Windows 11.

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
  limit on how many sockets one process can hold open.
- Probes still connect **by hostname**, not the resolved IP. That looks
  redundant beside `resolved_ip`, but it is load-bearing: ZPA steering is
  FQDN-driven, so connecting to a resolved address would bypass Client
  Connector's app-list matching and silently invalidate the run.
- Progress reports ports probed rather than targets.

## v1.4.2
Validated 194/194 on Windows 11.

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
Validated 183/183 on Windows 11.

- **The name-typing confirmation is now scoped to production tenants.**
  Non-production selection is a single `y/N`. Requiring the same friction
  everywhere trains people to type through it, which weakens the prompt
  exactly where it matters; production still requires typing the tenant
  name and still rejects a second bare `y`.

## v1.4.0
Saved tenants. Validated 177/177 on Windows 11.

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
- The store is `%USERPROFILE%\.zpa-connectivity-tester\tenants.json`, with
  its ACL restricted at creation time, so there is no window in which
  another account can read it. Loading warns if the ACL has since been
  widened. `$ZPA_TENANT_STORE` overrides
  the location.

## v1.3.1
Safety fix. Validated 155/155 on Windows 11.

- **Runs that cannot finish are now refused, not merely confirmed.** A
  `--scope full` run against a large tenant (a few thousand entries, with
  CIDR entries expanded to every usable host, against full port ranges) can
  plan hundreds of billions of probes — millennia at 20 workers, and still
  years even if every probe answered instantly. The tool printed the count and
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
Validated 145/145 on Windows 11.

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
Windows 11.

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
- Validated 80/80 on Windows 11
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
