# ZPA Application Segment Connectivity Test

Admin tool for validating reachability to ZPA application segments from an
endpoint running Zscaler Client Connector. Run it before ZPA is enabled for
an account, again after, then diff the two runs.

- Script: `zpa_segment_connectivity.py` (v1.6.0)
- Python 3.9+, standard library only — **no `pip install`**
- Windows / macOS / Linux. Read-only against the ZPA API (GET).
- **Runs entirely on your own machine.** Nothing is installed or sent
  anywhere; it just calls the ZPA API and probes from your endpoint.

---

## Setup

**Python** — Windows: Microsoft Store install (per-user, no admin), then
use `py -3`. macOS: `xcode-select --install`, then `python3`.

**Credentials** — you do **not** need to set anything up. Just run the tool
and it will **prompt you** for the four OneAPI values your ZPA administrator
gives you:

```
  OneAPI client ID: ...
  Zidentity vanity domain (the <name> in <name>.zslogin.net): ...
  ZPA customer ID: ...
  OneAPI client secret (hidden): ...        <- not shown as you type
```

The client secret is read with hidden input and is never written to disk,
your shell history, or the command line.

> Optional: if you run the tool repeatedly you can pre-set the values as
> environment variables (`ZSCALER_CLIENT_ID`, `ZSCALER_VANITY_DOMAIN`,
> `ZPA_CUSTOMER_ID`, `ZSCALER_CLIENT_SECRET`) to skip the prompts.
> PowerShell: `$env:ZSCALER_CLIENT_ID = "..."`.

### Saving tenants (model vs production)

A pilot usually spans two tenants — a model/test one and production. Save
each once instead of retyping four values per run:

```
python3 zpa_segment_connectivity.py tenants add model
python3 zpa_segment_connectivity.py tenants add production
python3 zpa_segment_connectivity.py tenants list
```

`tenants add` asks whether the tenant is **production**, then for the client
ID, vanity domain and customer ID. The store is
`~/.zpa-connectivity-tester/tenants.json`, created mode `0600` (override the
location with `$ZPA_TENANT_STORE`).

> The client secret is **only** saved if you opt in, and it is stored in
> plaintext. The default is to prompt for it each run so it never touches
> disk — keep that default unless you have a reason not to.

Any run that needs credentials then offers the saved tenants:

```
Saved tenants:
  [1] model
        vanity domain : acme-model
        ...
  [2] production  ** PRODUCTION **
        ...
  [0] none of these — enter credentials manually
Select tenant [0-2]: 2

  Selected PRODUCTION tenant:
    ...
  Run against 'production'? [y/N]: y
  PRODUCTION — confirm by typing the tenant name exactly ('production'): production
```

**Production tenants are confirmed twice**, and the second confirmation
requires typing the tenant name — a second yes/no gets answered reflexively,
and the mistake being guarded against is sweeping production while believing
you are on the model tenant. Typing anything else aborts.

Non-production tenants take a single `y/N`. That asymmetry is deliberate:
demanding the same friction everywhere trains people to type through it,
which would weaken the prompt exactly where it matters.

Skip the menu with `--tenant NAME` (production still confirmed twice), or
`--tenant NAME --yes` for scripted runs where the choice is already
explicit. Values from `--client-id`/`--vanity-domain`/`--customer-id` always
win over the saved tenant; env vars still work as before.

Remove one with `tenants remove NAME`.

**Check readiness** — verifies Python, output folder, ZCC presence, and DNS
without probing or authenticating:

```
python3 zpa_segment_connectivity.py preflight
```

---

## Quick start (everything on your machine)

Run one command; paste the credentials when prompted. It authenticates,
pulls the segment list from ZPA, and probes from your endpoint:

```
python3 zpa_segment_connectivity.py test --phase post --scope sample
```

That is the whole thing — no setup, no separate steps. The rest of this
document covers the pre-vs-post pilot workflow and the options.

---

## Workflow

### 1. (Optional) Freeze the segment inventory — for coordinated pilots

```
python3 zpa_segment_connectivity.py export-targets --out zpa-targets.json
```

Adding `--targets-file zpa-targets.json` to later runs pins an identical
target list across pre and post (so a mid-pilot segment change can't
pollute the diff) and avoids re-hitting the API. Skip this to just fetch
live each run. When a run has no `--targets-file`, it prompts for
credentials and pulls the inventory itself.

### 2. PRE run — before ZPA is enabled for your account

```
python3 zpa_segment_connectivity.py test --phase pre --scope sample \
    --targets-file zpa-targets.json --sipa-only
```

Confirm first that your account is **not** assigned ZPA in its App Profile
and not covered by a ZPA access policy. An enrolled laptop is not
automatically a pre-ZPA baseline — otherwise you capture a post-state and
label it "pre".

### 3. POST run — after ZPA is enabled and ZCC shows Private Access authenticated

```
python3 zpa_segment_connectivity.py test --phase post --scope sample \
    --targets-file zpa-targets.json --flush-dns --l7 --report
```

Drop `--sipa-only` so all segments are covered. `--flush-dns` matters —
see caveat 2 below.

### 4. Compare

```
python3 zpa_segment_connectivity.py compare \
    zpa-test-results/pre_sample_HOST_TIMESTAMP.csv \
    zpa-test-results/post_sample_HOST_TIMESTAMP.csv \
    --html readout.html
```

Substitute the real filenames — `ls zpa-test-results/` shows them. Do not
paste `<host>` literally: in bash and zsh `<` is a redirection operator, so
a placeholder in angle brackets fails with `no such file or directory: host`
before the tool ever runs. On macOS/Linux the shell will expand a glob for
you:

```
python3 zpa_segment_connectivity.py compare \
    zpa-test-results/pre_sample_*.csv \
    zpa-test-results/post_sample_*.csv \
    --html readout.html
```

Compare like scopes (`sample` vs `sample`). A scope mismatch is detected
and warned about, because the `(absent)` rows it produces are an artifact,
not a regression. Exit code is `1` if anything regressed.

---

## Scope

| Scope | Tests | Use when |
|---|---|---|
| `full` | Every FQDN, IP, **every usable CIDR host**, every port | Final validation |
| `sample` | 3 entries/segment, 5 spread hosts/CIDR, 10 ports/segment | Routine runs |

Prompted interactively if `--scope` is omitted. The planned probe count is
printed and confirmed before anything is sent. A `full` run against wide
CIDRs or large port ranges is a legitimate port sweep across the App
Connectors — notify whoever watches IDS and connector metrics first.

---

## Output

`./zpa-test-results/` relative to your working directory:

| File | Contents |
|---|---|
| `<phase>_<scope>_<host>_<ts>.csv` | One row per probe |
| `<phase>_<scope>_<host>_<ts>.meta.json` | Run context: ZCC state, scope, filters, DNS-flush result, counts |
| `<phase>_<scope>_<host>_<ts>.html` | Self-contained report (with `--report`) |

Ctrl-C still writes what was collected, tagged `_PARTIAL`. The absolute
path is printed at the end of every run.

> Results contain internal FQDNs, IPs, and CIDRs. Treat them as
> confidential and never commit them to a public repo. `zpa-test-results/`
> and `zpa-targets.json` are gitignored here; if you change `--output-dir`,
> make sure the new location is ignored too.

### Key columns

| Column | Meaning |
|---|---|
| `entry_kind` | `fqdn` / `ip` / `cidr` / `wildcard` |
| `zpa_intercepted` | `True` = resolved into `100.64.0.0/10` → ZCC steered it into ZPA. `N/A` for ip/cidr — see caveat 1 |
| `status` | `OPEN`, `OPEN_FLAKY` (only succeeded on retry), `REFUSED`, `TIMEOUT`, `DNS_FAIL:…`, `UDP_NOT_PROBED`, `WILDCARD_SKIPPED` |
| `attempts` | How many tries the result took |
| `l7_result` | With `--l7`. `TLS:…` / `HTTP:…` prove an application answered. `OPEN_NO_L7_DATA` = accepted then sent nothing (typically nothing serving behind the App Connector). `OPEN_NON_HTTP` = a live service this probe cannot speak to. `L7_ERROR:…` = the exchange failed — raise `--l7-timeout` before reading these as application faults |

**The signal ZPA is working:** post-run `zpa_intercepted` flips to `True`
for FQDN segments while `status` stays `OPEN`. The compare output's
"newly intercepted domains" is the headline number.

---

### TCP reachable is not an application pass

Through ZPA the TCP connection is accepted **locally by Client Connector**,
so a port reads as `OPEN` whether or not anything behind the App Connector
is serving. A run can therefore report `249/249 TCP REACHABLE` and
`0 FAILING PROBES` while most of those probes had nothing on the other end.

`--l7` is what separates the two, and its result is now in the summary:

```
  RESULTS   OPEN 249  WILDCARD_SKIPPED 15
  L7        107/249 OPEN probes had an application respond (43.0%)
```

with an `L7 VERIFICATION` section breaking that down per outcome and per
segment, two clickable tiles in the HTML report (`L7 verified`, `no app
response`), and an `l7` block in the run's `meta.json`.

The L7 step has its own timeout. A ZPA connect completes locally and fast,
so `--timeout` is tuned low, but a TLS handshake has to traverse the App
Connector to the backend — sharing one budget reports working applications
as L7 timeouts. `--l7-timeout` defaults to 4x `--timeout`, clamped to
5-15s; pass it explicitly to go outside that range.

If raising it does not move the numbers, the finding is real: those
segments have nothing answering.

---

## Driving a run from a DNS export (`--dns-csv`)

The segment inventory says what ZPA is *configured* to steer. A DNS export
says what actually *exists* — and because it is captured from a DNS-server
vantage with no Client Connector in the path, it also records what each name
resolved to **before** ZPA. Joining the two answers the question neither
side answers alone: which internal names are not enrolled in ZPA at all.

```bash
# put dns_destinations.csv beside the script, then:
python3 zpa_segment_connectivity.py test --phase post \
    --targets-file zpa-targets.json --dns-csv --report
```

Expected columns (extras are ignored, missing optional ones degrade
gracefully): `Name`, `RecordType`, `TerminalName`, `ResolvedIPs`,
`OnlyExternalIPs`, `HasAnyInternalIP`, `IsWildcard`, `LookupStatus`. An
Excel BOM or a cp1252 file is handled.

### It does not guess ports

An enterprise-wide record list spans every server role, so there is no port
set that would be right. Ports come only from a matching segment, and only
where that segment says something specific:

| the name | what happens |
|---|---|
| matches a segment defining discrete ports (`443`, `8443`) | probed on those ports |
| matches a segment whose ranges are all wide (`1-65535`) | resolved, **never probed** |
| matches no segment | resolved, **never probed** |

**Most records will land in the middle row.** In practice few names match a
segment by exact FQDN — they are caught by a wildcard segment with a broad
range, and a broad range says nothing about what any single host behind it
listens on. `expand_ports` keeps range endpoints first, so `1-65535` would
yield ports 1, 65535, 2 and 3: probing those across thousands of names
produces only `TIMEOUT` rows, which the summary classifies as *"nothing
answered — traffic may not be steered"* — the exact opposite of the truth —
and reproduces the horizontal scan this mode exists to avoid.

The filter is per *range*, not per segment, so a segment defining
`443, 8000-8100` still contributes `443` — real evidence — while discarding
the range, which is not. Ports per name are then capped at 4 regardless of
`--scope`. Everything dropped is counted and attributed to the segment that
caused it, never silent.

**None of this affects the answer.** Steering is settled by resolution, so
coverage is complete whether or not a single connect is made. The run
reports how many names matched by exact name, how many via a wildcard, and
how many were left unprobed because their segment's ranges were too wide.

### If you do want ports probed: `--dns-ports`

For names the segments cannot supply a port for, you can name ports
explicitly. It never overrides a segment that defines discrete ports:

```bash
--dns-csv --dns-ports 111,123,161
```

**Check the protocol first.** Of that example set, only 111 (rpcbind) is
normally a TCP service. 123 (NTP) and 161 (SNMP) are UDP, and this tool
probes TCP only — so a TCP connect to them times out on a perfectly healthy,
correctly steered host, and the summary classifies `TIMEOUT` as *"nothing
answered, traffic may not be steered"*. That turns a protocol mismatch into
a false ZPA finding on every host you own.

The run warns about this at startup, cross-checks each port against the
matched segment's own `udpPortRange` — direct evidence from ZPA rather than
a guess from a well-known-ports table — and adds a `NEXT STEPS` entry saying
to read those rows as *not tested* rather than as failures.

ZPA records UDP ports separately. This tool lists them as `UDP_NOT_PROBED`
and never probes them, so UDP reachability is not something a run can
currently answer either way.

Note the volume: names x ports connects across the estate. Ports 111 and 161
in particular are classic enumeration signatures. Tell whoever watches IDS
before running it.

---

### What it finds

```
  -- DNS CROSS-REFERENCE (export vs endpoint) ------------------
    names checked    2847
    in a ZPA segment  412   in none    2435
    steered           298  (10.5% of names)

    verdicts:
      [!] NOT_STEERED_INTERNAL   96  — resolved to an internal IP, not
                                       into ZPA
          STEERED               298  — resolved into the synthetic range
          NOT_STEERED_EXTERNAL   18  — external-only in DNS, expected

    STEERING GAP (96) — enrolled in a ZPA segment, but resolved to an
    internal IP instead of into ZPA
    ENROLMENT GAP (2435) — internal in DNS and in no ZPA segment at all
```

*Steering gap* means enrolled but not being steered — check access policy
and for a local resolver short-circuiting Client Connector. *Enrolment gap*
means the name cannot be steered until a segment covers it. Eight `dns_*`
columns land in the CSV, three clickable tiles in the HTML report, and a
`dns_csv` block in `meta.json`.

`--scope` deliberately does not thin the export: sampling would drop exactly
the unenrolled names being hunted. Use `--dns-sample N` to cap it
explicitly. Without a segment source the run degrades to a resolution-only
sweep and says so.

---

## Two caveats that affect how you read results

Both follow from how Client Connector implements ZPA steering, and both
change how a post-run result should be read.

**1. ZPA steering is FQDN-driven, so IP/CIDR segments can't be verified
from the endpoint alone.** Client Connector holds a local app-list of
*names*; a match produces the synthetic `100.64.x.x` address. IP- and
CIDR-defined entries generate no synthetic IP, which is why
`zpa_intercepted` is `N/A` for them. Consequently **a successful post-run
connect to an IP/CIDR entry does not prove the traffic traversed ZPA** —
it may have gone direct. Confirm those segments in the ZPA admin portal's
access logs.

**2. Negative DNS cache can fake a post-run failure.** The pre run queries
internal names that don't yet resolve, and those negative answers get
cached. In the post run the same name can still return NXDOMAIN even
though ZPA is steering it. Use `--flush-dns` on post runs (macOS needs
sudo). If an enrolled domain still fails, restart ZCC before recording it
as a real failure.

---

## Verifying SIPA source-IP anchoring

`test` proves you can *reach* a SIPA segment, but a TCP connect cannot prove
that Source IP Anchoring actually put the expected source IP on the wire —
anchoring happens in the Zscaler cloud, invisible to local sockets. The
`sipa-verify` subcommand closes that gap.

**How it works:** the one thing an endpoint can observe is the public source
IP a destination *sees*. So it fetches a source-IP **reflector** (an HTTP
endpoint that echoes the caller's IP) and compares the observed egress IP to
the **anchor the admin configured**.

**The one hard requirement:** the reflector's FQDN must be **enrolled in the
SIPA segment** — otherwise the request egresses via the normal path and
reports the wrong IP. Best practice is a small internal/customer-hosted
reflector (e.g. an nginx returning `$remote_addr`) added to the SIPA segment.
A third-party echo (ipify, etc.) sends your anchor IP off-network — avoid it
for anything but a throwaway test.

```
sipa-verify \
  --targets-file zpa-targets.json \                  # confirms reflector enrollment
  --reflector https://ipcheck.corp.example/ip \      # enrolled in the SIPA segment
  --expected-anchor 198.51.100.0/24 \                # the configured anchor egress
  --baseline-reflector https://api.ipify.org         # NOT in ZPA — contrast IP
```

**Verdicts** (exit 1 if any MISMATCH/UNREACHABLE):

| Verdict | Meaning |
|---|---|
| `ANCHORED` | observed egress IP is within `--expected-anchor` — SIPA is working |
| `MISMATCH` | got an IP, but not the expected anchor. If it equals the `--baseline-reflector` IP, the tool says so outright: traffic is **not** being anchored |
| `UNVERIFIED` | no `--expected-anchor` given — just reports the observed IP (discovery) |
| `UNREACHABLE` | reflector didn't respond |

With `--targets-file`, each reflector is checked against the SIPA
(`ipAnchored`) segments and **warns if its host is not enrolled** — a
reflector that isn't in a SIPA segment makes the result meaningless.
`--expected-anchor` accepts an IP or CIDR (repeatable); `--anchor-map FILE`
maps per-reflector expectations. Results write to a `sipa-verify_*.csv` +
`.meta.json` in the output dir.

> This verifies the **source IP a destination sees**, corroborated by the
> enrollment check and the baseline contrast. It does not replace ZIA/ZPA
> access-log confirmation, but it is the strongest signal obtainable from the
> endpoint itself.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot reach https://<vanity>.zslogin.net`, cert error | Egress is TLS-inspected. Windows Python reads the enterprise root from the cert store and usually works; macOS python.org builds ignore the System Keychain — use `--ca-bundle corp-root.pem`, or get `zslogin.net` + `api.zsapi.net` exempted from SSL inspection |
| `HTTP 401` / `403` | Wrong vanity domain or customer ID, expired secret, or the API client lacks ZPA read scope |
| `HTTP 429` | Rate limited — the script backs off and retries automatically (honors `Retry-After`) |
| `ERROR: no interactive terminal` | Pass `--scope` and `--yes` explicitly for unattended runs |
| Everything TIMEOUTs post-run | ZCC → Private Access ON and authenticated? User in the ZPA access policy? A ZCC restart is often needed after a policy change |
| Preflight: ZCC `not_detected` | Process names vary by ZCC version — this is a hint, not proof. Verify in the ZCC UI; the authoritative signal is synthetic IPs appearing in results |
| Windows run is slow / everything shows TIMEOUT | **Do not set `--timeout` below 3 on Windows.** Windows takes ~2s to return a connection refusal (vs instant on Linux/macOS), so a shorter timeout converts every `REFUSED` into `TIMEOUT` — which then burns retries and misreports "something answered and said no" as "nothing answered". The 5s default is safe |

---

## Command reference

```
preflight        environment + ZCC readiness check, no probing
export-targets   fetch segment inventory to JSON  [--out]
test             probe and write CSV/meta/HTML
sipa-verify      verify SIPA source-IP anchoring via egress-IP reflection
compare          diff pre vs post CSVs            [--html]
report           build HTML from one or two CSVs  [--out]
```

Useful `test` flags: `--segment SUBSTR`, `--enabled-only`,
`--wildcard-probe www`, `--sample-domains N`, `--cidr-hosts N`,
`--max-ports N`, `--retries N`, `--l7`, `--l7-timeout S`, `--dns-csv [CSV]`, `--dns-ports PORTS`, `--dns-sample N`, `--flush-dns`, `--report`,
`--timeout S`, `--workers N` (keep under ~200 on macOS, FD limit 256),
`--no-show-failures`,
`--ca-bundle PEM`, `--yes`.
