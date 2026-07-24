# ZPA Application Segment Connectivity Test

Admin tool for validating reachability to ZPA application segments from an
endpoint running Zscaler Client Connector. Run it before ZPA is enabled for
an account, again after, then diff the two runs.

- Script: `zpa_segment_connectivity.py` (v1.2.3)
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
    zpa-test-results/pre_sample_<host>_<ts>.csv \
    zpa-test-results/post_sample_<host>_<ts>.csv \
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
| `l7_result` | With `--l7`: `TLS:TLSv1.3`, `HTTP:200`, etc. — proof an app answered, not just TCP |

**The signal ZPA is working:** post-run `zpa_intercepted` flips to `True`
for FQDN segments while `status` stays `OPEN`. The compare output's
"newly intercepted domains" is the headline number.

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
`--max-ports N`, `--retries N`, `--l7`, `--flush-dns`, `--report`,
`--timeout S`, `--workers N` (keep under ~200 on macOS, FD limit 256),
`--no-show-failures`,
`--ca-bundle PEM`, `--yes`.
