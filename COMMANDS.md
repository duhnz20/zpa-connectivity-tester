# Commands, and why each one exists

A working runbook, in the order you would actually run things. Every command
here is real; every one has a reason attached, because a command you do not
understand produces a result you cannot defend.

Run everything from the folder containing `zpa_segment_connectivity.py`.

**Invocation.** Examples use `py -3`, the Python launcher. In **PowerShell**
line continuation is a backtick `` ` ``; in **cmd.exe** it is a caret `^`.
The examples below are written on one line where practical to avoid the
difference entirely.

Two conventions in the examples:

- `--synthetic-net 100.64.0.0/16` — **replace with your tenant's range.**
  See [The one setting that silently invalidates a run](#the-one-setting-that-silently-invalidates-a-run).
- `zpa-targets.json` — a frozen segment inventory, produced by
  `export-targets` below.

> **This build is Windows-only** and refuses to run elsewhere. For macOS use
> [zpa-connectivity-tester-macos](https://github.com/duhnz20/zpa-connectivity-tester-macos),
> which does the same job through macOS-native surfaces.

---

## 0. Before anything: does this host make sense to test from?

```bash
py -3 zpa_segment_connectivity.py preflight --synthetic-net 100.64.0.0/16
```

**Why.** Ten seconds here saves a run you have to throw away. It asks
Windows directly for everything that determines whether the run is even
meaningful:

```
  [PASS] ZPA synthetic range          100.64.0.0/16 (65,536 addresses)
  [FAIL] Zscaler Client Connector     not_detected — no Zscaler service,
                                      process or install record found
  [FAIL] ZPA synthetic-range route    100.64.0.1 routes via Ethernet 2 —
                                      no ZCC adapter claims this range
  [PASS] DNS resolvers                1 server(s): 10.0.0.53
  [FAIL] NRPT split-DNS policy        0 rule(s) — no per-domain policy
  [PASS] Proxy configuration          WinINET direct; WinHTTP direct
```

**The routing line is the one to read first.** It uses `Find-NetRoute` to
ask what the stack would actually do with a packet to the synthetic range.
If no ZCC adapter claims it, Private Access is off or unauthenticated — and
every result you were about to collect would have been a false negative.

**The NRPT line is the Windows-specific one.** ZCC implements split DNS
through the Name Resolution Policy Table. Zero rules on a host that should
be enrolled means names are being resolved by the LAN resolver, not by ZPA,
whatever the client's tray icon says.

ZCC detection distinguishes **installed but not running** from **not
detected**, because the remedy differs: start the service, versus install
the client.

Add `--tenant NAME` once you have saved one, to check credentials too.

---

## 1. One-time setup

### Save a tenant

```bash
py -3 zpa_segment_connectivity.py tenants add model
py -3 zpa_segment_connectivity.py tenants list
```

**Why.** A pilot usually spans a model and a production tenant, and retyping
four OneAPI values per run invites the mistake where you sweep production
believing you are on the model tenant. Saved tenants make the choice explicit
and confirm it twice — the second confirmation for a production tenant
requires typing its name.

The store is `%USERPROFILE%\.zpa-connectivity-tester\tenants.json`, with its ACL
restricted to your account (inheritance stripped) and verified after write. **The client secret is only
written if you opt in**; by default it is prompted each run and never touches
disk. Override the location with `$ZPA_TENANT_STORE`.

### Freeze the inventory

```bash
py -3 zpa_segment_connectivity.py export-targets  --tenant model --out zpa-targets.json
```

**Why.** Three reasons, in order of how much they will bite you:

1. **Comparability.** A pre run and a post run must test the same inventory.
   If an admin adds a segment between them, a live-API post run tests a
   different set and the diff is meaningless rather than obviously wrong.
2. **No credentials needed afterwards.** Every later command takes
   `--targets-file zpa-targets.json` and never touches the API.
3. **Speed.** Fetching a large inventory is the slowest non-probe step.

The file contains internal FQDNs and CIDRs. It is gitignored here; keep it
that way.

---

## 2. The pilot: before, after, and the diff

### Baseline, before ZPA is enabled for the account

```bash
py -3 zpa_segment_connectivity.py test --phase pre  --scope sample --targets-file zpa-targets.json  --synthetic-net 100.64.0.0/16 --report
```

**Why.** Without a baseline you cannot distinguish "ZPA broke this" from
"this was already broken." The run refuses to let you fool yourself: if it
sees synthetic IPs during a `--phase pre` run it returns **BASELINE INVALID**,
because you have captured a post-state and labelled it "pre".

### After ZPA is enabled

```bash
py -3 zpa_segment_connectivity.py test --phase post  --scope sample --targets-file zpa-targets.json  --synthetic-net 100.64.0.0/16 --l7 --flush-dns --report
```

**Why `--flush-dns`.** A negative DNS answer cached during the pre run — when
the name genuinely did not resolve — survives into the post run and masks
steering that is now working. On Windows this runs `ipconfig /flushdns`,
which **needs no elevation**. If it fails, the cause is policy or a stopped
DNS Client service, not a missing admin prompt — so do not go hunting for an
elevated shell.

The run reports honestly whether the flush actually succeeded; do not infer
success from the absence of an error.

ZCC keeps its own cache too. If an enrolled domain still shows `DNS_FAIL`
after a clean flush, restart Client Connector before believing it.

**Why `--l7`.** See [TCP reachable is not an application
pass](#3-verifying-specific-claims). Use it on every post run.

### Diff them

```bash
py -3 zpa_segment_connectivity.py compare  zpa-test-results/pre_sample_HOST_TIMESTAMP.csv  zpa-test-results/post_sample_HOST_TIMESTAMP.csv --html change-report.html
```

**Why.** This is the deliverable. It separates regressions (worked before,
broken now) from fixes, and lists newly ZPA-steered domains — the headline
number for "did the rollout do what it was supposed to."

---

## 3. Verifying specific claims

### Is an application actually serving, or did ZPA just accept the connection?

```bash
py -3 zpa_segment_connectivity.py test --phase post  --targets-file zpa-targets.json --synthetic-net 100.64.0.0/16  --l7 --l7-timeout 15 --report
```

**Why.** Through ZPA the TCP connection is accepted **locally by Client
Connector**, so a port reads `OPEN` whether or not anything behind the App
Connector is serving. A run can report `249/249 TCP REACHABLE`, `0 FAILING
PROBES` and `0 actionable findings` while fewer than half of those probes had
an application on the other end.

`--l7` attempts a TLS handshake, falling back to an HTTP `HEAD`, and the
summary reports the ratio next to the reachability count. Read the outcomes
as:

| result | means |
|---|---|
| `TLS:…` / `HTTP:…` | an application answered — this path works end to end |
| `OPEN_NO_L7_DATA` | accepted, then sent nothing. The signature of a connector with nothing serving behind it |
| `OPEN_NON_HTTP` | a live service this probe cannot speak to — a pass in substance |
| `L7_ERROR:…` | the exchange failed; raise `--l7-timeout` before believing it |

**Why `--l7-timeout`.** The L7 step has its own budget: 4x `--timeout`,
clamped to 5–15s. At this build's default `--timeout 3` that resolves to 12s,
so the flag matters most when you have *lowered* `--timeout`. A ZPA connect completes locally and fast; a TLS handshake has to
traverse the App Connector to the backend, so sharing one budget reports
working applications as L7 timeouts. Raise it explicitly to prove a finding is
real: if the failures do not move, the silence is genuine.

### Is Source IP Anchoring actually anchoring?

```bash
py -3 zpa_segment_connectivity.py sipa-verify  --targets-file zpa-targets.json  --reflector https://ipcheck.internal.example/ip  --expected-anchor 198.51.100.0/24  --baseline-reflector https://api.ipify.org
```

**Why.** A TCP connect cannot prove SIPA. Only the source IP the destination
*actually sees* can. Point `--reflector` at an echo endpoint that is
**enrolled in the SIPA segment** (so it takes the anchored path), and give a
`--baseline-reflector` that is not in ZPA. If observed equals baseline,
traffic is not being anchored — which is the failure this command exists to
catch.

Prefer an internal reflector. A third-party echo service sends your anchor IP
off-network.

---

## 4. Coverage: what exists that ZPA does not cover?

```bash
py -3 zpa_segment_connectivity.py test --phase post  --targets-file zpa-targets.json --synthetic-net 100.64.0.0/16  --dns-csv --dns-ports 443,80,22,135 --report
```

Put `dns_destinations.csv` beside the script; bare `--dns-csv` finds it.

**Why.** The segment inventory says what ZPA is *configured* to steer. A DNS
export says what actually *exists*, and — captured from a DNS-server vantage
with no Client Connector in the path — what each name resolved to before ZPA.
Joining them answers what neither side answers alone:

- **Steering gap** — enrolled in a segment, still resolving to an internal IP.
  Check the access policy covers your account, and that no local resolver or
  hosts-file entry is short-circuiting Client Connector.
- **Enrolment gap** — internal in DNS, in no segment at all. It cannot be
  steered until a segment covers it. This is usually the large number.

**Why those ports, in that order.** `--dns-ports` is a liveness check, not a
port inventory: the walk stops at the first port that answers and moves on,
so whichever port is **first is probed on 100% of destinations** while the
rest only reach what has not already answered.

| port | catches | sweep signature |
|---|---|---|
| 443 | web and application servers — most ZPA segments | negligible |
| 80 | app servers and appliances that never got a certificate | negligible |
| 22 | everything on Linux/Unix, including database and infrastructure hosts | moderate |
| 135 | Windows hosts with no web listener | **high** |

The two harmless ports absorb most of an estate before either noisy one is
reached. Database ports are deliberately absent: a database host answers on
22 or 135 anyway, so they would add signature risk without adding coverage.

**Two things to know before running this at scale.**

1. **A horizontal sweep of 22/111/135/445/3389 is a standard IDS/EDR
   signature** and will be attributed to the account running it. The run
   states the connect volume and names which of your ports are the noisy
   ones. Tell whoever watches it first.
2. **This tool probes TCP only.** Ports whose service is UDP — 123 (NTP),
   161 (SNMP), 514 (syslog) — time out on a perfectly healthy host, and the
   summary reads `TIMEOUT` as "traffic may not be steered". The run warns
   about this and cross-checks each port against the matched segment's own
   `udpPortRange`, but do not put them in the list.

Steering is settled by resolution, so the coverage answer is complete whether
or not a single connect is made. `--dns-ports` is optional.

---

## 5. When something looks wrong

### A domain fails that should work

```bash
py -3 zpa_segment_connectivity.py test --phase post  --targets-file zpa-targets.json --synthetic-net 100.64.0.0/16  --segment "Segment Name" --flush-dns --l7 --report
```

**Why.** Narrow to one segment, flush the cache, and check L7. In that order:
most "failures" are a stale negative cache entry or an application that was
never listening, not ZPA. No elevation is needed for the flush on Windows.

### Wildcard entries were skipped

```bash
--wildcard-probe www
```

**Why.** `*.example.com` is not a hostname; it cannot be resolved. This
substitutes a label to produce a testable name. Skipped wildcards are the
single largest coverage gap in a typical run, and the summary tells you how
many were skipped so it is never silent.

### The run is too slow, or too aggressive

```bash
--workers 400      # the measured sweet spot; see below
--timeout 3        # do not go below ~2.5 — see below
--sample-domains N --cidr-hosts N --max-ports N
--scope full       # exhaustive; see the warning below
```

**Why 400.** Measured on Windows 11 / Python 3.14.6, not guessed: 20 workers
gives ~569 probes/s, 200 ~1,106, 400 ~1,827, and 800 only ~1,888 — three
percent more for double the threads. Windows has no small per-process socket
cap to raise, so there is nothing to tune around; 400 is simply where the
curve flattens.

**Why `--timeout 3` and not lower.** Windows delivers a TCP connection
refusal at ~2.04s. Below ~2.5 a refused port reports `TIMEOUT` instead of
`REFUSED`, and the summary reads those oppositely — a refusal proves the
path works. The run warns if you set it below the threshold.

**Before `--scope full`:** a full-scope run against wide CIDRs and full port
ranges is a port sweep and can plan billions of probes. The tool refuses runs
that cannot realistically finish; `--force-huge-run` overrides that, and you
should notify whoever watches IDS before using it.

---

## 6. Reading the results

Three files land in `zpa-test-results/` per run: the CSV (every probe), a
`.meta.json` (verdict, environment, coverage, statistics), and with
`--report` a self-contained HTML page whose tiles are clickable filters.

```bash
py -3 zpa_segment_connectivity.py report --out report.html  zpa-test-results/pre_sample_HOST_TIMESTAMP.csv  zpa-test-results/post_sample_HOST_TIMESTAMP.csv
```

Useful one-liners over the newest results CSV. `cmd.exe` and PowerShell
both fight multi-line `python -c` quoting, so save each as a `.py` file and
run `py -3 <file>.py` — the bodies below are the file contents:

```bash
# What did L7 actually find? The number that matters most.
py -3 -c "
import csv,collections,glob
r=list(csv.DictReader(open(sorted(glob.glob('zpa-test-results/post_*.csv'))[-1])))
print(collections.Counter(x['l7_result'] for x in r if x['status'].startswith('OPEN')))"

# Which names are in DNS but in no ZPA segment? The enrolment gap.
py -3 -c "
import csv,glob
r=list(csv.DictReader(open(sorted(glob.glob('zpa-test-results/post_*.csv'))[-1])))
print('\n'.join(sorted({x['probe_domain'] for x in r
      if x.get('dns_in_zpa')=='False' and x.get('dns_has_internal')=='True'})))"

# Everything that failed, grouped by status
py -3 -c "
import csv,collections,glob
r=list(csv.DictReader(open(sorted(glob.glob('zpa-test-results/post_*.csv'))[-1])))
print(collections.Counter(x['status'].split(':')[0] for x in r))"
```

### How to read a failure

| status | means |
|---|---|
| `REFUSED` | **the path works.** Something answered and declined — nothing is listening on that port |
| `TIMEOUT` | nothing answered. Traffic may not be steered, or is being dropped |
| `DNS_FAIL:…` | the name did not resolve. Check enrolment, then flush the cache |
| `OPEN_FLAKY` | only succeeded on retry — intermittent connector behaviour, worth investigating |
| `UDP_NOT_PROBED` | listed for completeness; this tool does not probe UDP |
| `WILDCARD_SKIPPED` | see `--wildcard-probe` above |

Conflating `REFUSED` with `TIMEOUT` is the most common misreading. A refusal
is positive evidence that ZPA delivered your traffic.

---

## The one setting that silently invalidates a run

```bash
--synthetic-net 100.64.0.0/16     # YOUR tenant's range
```

Zscaler's documented default is `100.64.0.0/10`, but the range is
tenant-configurable and commonly narrowed. Getting it wrong is not cosmetic:
`100.64.0.0/10` is the RFC 6598 carrier-grade NAT range, so against a `/16`
tenant the assumed range is 64x too wide. On a hotel or mobile-hotspot
network an ISP-assigned CGNAT address falls inside that gap and is reported
as ZPA-steered — a false `ZPA IS STEERING` verdict, which is the headline
conclusion of the entire run.

Store it per tenant so you cannot forget it, or pass it explicitly. It is
accepted before or after the subcommand. Preflight always states the range in
force and flags when it is still the default.

---

## Two caveats that change how results should be read

1. **IP and CIDR segment entries cannot be verified from an endpoint.** They
   produce no synthetic IP, so neither a successful connect nor a timeout
   proves whether ZPA carried the traffic. `zpa_intercepted` is `N/A` and the
   summary groups them separately as UNVERIFIABLE HERE. Confirm those in the
   ZPA admin portal's access logs.
2. **A cached negative DNS answer can fake a post-run failure.** Use
   `--flush-dns` (no elevation needed); if an enrolled domain still fails
   afterwards, restart Client Connector before treating it as real.
3. **`REFUSED` and `TIMEOUT` are not interchangeable on Windows.** A refusal
   takes ~2.04s to arrive, so a `--timeout` below ~2.5 turns "the path works,
   nothing is listening" into "nothing answered". Keep the default.

---

## Output handling

Results contain internal FQDNs, IP addresses and CIDRs. Treat them as
confidential and never commit them to a public repository.
`zpa-test-results/`, `zpa-targets.json` and `*.meta.json` are gitignored
here; if you change `--output-dir`, make sure the new location is ignored
too.
