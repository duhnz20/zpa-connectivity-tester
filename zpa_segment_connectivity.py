#!/usr/bin/env python3
"""
ZPA Application Segment Connectivity Tester
============================================

Validates reachability to application segments defined in a ZPA tenant,
from an endpoint running Zscaler Client Connector (ZCC). Run before ZPA is
enabled for the account and again after, then diff the two runs.

Subcommands
-----------
  preflight       environment + ZCC readiness check, no probing
  export-targets  fetch the segment inventory from the API to a JSON file
  test            probe connectivity, write CSV + run-metadata sidecar
  compare         diff a pre CSV against a post CSV
  report          build a self-contained HTML report from one or more CSVs

Scope (chosen interactively, or with --scope)
  full   — every FQDN, every IP, every usable CIDR host, every port
  sample — N entries/segment, N spread hosts/CIDR, capped ports

Credentials (Zidentity OneAPI client, client_credentials grant)
  ZSCALER_CLIENT_ID       OneAPI API client ID
  ZSCALER_CLIENT_SECRET   OneAPI API client secret (prompted if unset)
  ZSCALER_VANITY_DOMAIN   Zidentity vanity domain (<name>.zslogin.net)
  ZPA_CUSTOMER_ID         ZPA tenant customer ID
The secret is never accepted as a CLI argument (shell history / process
list exposure). Use --targets-file to run with no credentials at all.

Platform support — Windows, macOS, Linux. Standard library only, no pip
install. Python 3.9+.
  Windows:  py -3 zpa_segment_connectivity.py test --phase pre
  macOS:    python3 zpa_segment_connectivity.py test --phase pre

Results are written to ./zpa-test-results/ relative to the working
directory as <phase>_<scope>_<hostname>_<UTC timestamp>.csv, with a
matching .meta.json capturing run context (ZCC state, scope, counts).
The absolute path is printed at the end of every run.

NOTE: result files contain internal FQDNs, IPs, and CIDRs — treat them as
confidential and never commit them to a public repository.

Read-only against the ZPA API (GET). All active testing is outbound DNS +
TCP connect (optionally TLS/HTTP) from the local machine.

Interpreting results — two caveats that follow from how Client Connector
implements ZPA steering:

  1. ZPA steering is FQDN-driven: Client Connector holds a local app-list
     of names, and a match yields a synthetic 100.64.x.x (RFC 6598)
     address. IP- and CIDR-defined entries produce no synthetic IP, so
     `zpa_intercepted` is N/A for them — and a successful post-run connect
     to an IP/CIDR entry does NOT by itself prove the traffic went through
     ZPA rather than direct. Confirm those segments from the ZPA admin
     portal's access logs, not from this script alone.
  2. Negative DNS cache entries created during the pre run can persist and
     mask steering in the post run. Use --flush-dns on post runs; if an
     enrolled domain still fails to resolve, restart ZCC before treating
     it as a real failure.
"""

import argparse
import concurrent.futures
import csv
import getpass
import html
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

SCRIPT_VERSION = "1.4.2"
DEFAULT_API_BASE = "https://api.zsapi.net"
OAUTH_AUDIENCE = "https://api.zscaler.com"
ZPA_SYNTHETIC_NET = ipaddress.ip_network("100.64.0.0/10")
PAGE_SIZE = 500
FULL_CIDR_HOST_CAP = 65536   # hard memory guard even in full scope
CONFIRM_THRESHOLD = 2000     # confirm before runs bigger than this
MAX_RUN_SECONDS = 12 * 3600  # refuse runs whose worst case exceeds this

# Best-effort ZCC process names. These vary by ZCC version and platform —
# absence is a hint, not proof, and is reported as such.
ZCC_PROCESS_HINTS = {
    "Windows": ["ZSATray", "ZSAService", "ZSATunnel", "ZSAUpdater"],
    "Darwin": ["Zscaler", "ZscalerTunnel", "ZscalerService"],
    "Linux": ["Zscaler", "zstunnel"],
}


# --------------------------------------------------------------------------
# Environment / ZCC detection
# --------------------------------------------------------------------------

def detect_zcc():
    """Best-effort Zscaler Client Connector detection.

    Returns a dict recorded in the run metadata. Process names differ
    between ZCC releases, so a negative result is reported as 'unknown'
    rather than 'not running' — the authoritative signal is the empirical
    synthetic-IP evidence gathered during probing.
    """
    system = platform.system()
    info = {"platform": system,
            "platform_release": platform.release(),
            "processes_found": [],
            "state": "unknown"}
    hints = ZCC_PROCESS_HINTS.get(system, [])
    if not hints:
        return info

    try:
        if system == "Windows":
            out = subprocess.run(["tasklist"], capture_output=True,
                                 text=True, timeout=20).stdout
        else:
            out = subprocess.run(["ps", "-A", "-o", "comm"],
                                 capture_output=True, text=True,
                                 timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return info

    lowered = out.lower()
    found = [h for h in hints if h.lower() in lowered]
    info["processes_found"] = found
    info["state"] = "running" if found else "not_detected"
    return info


def flush_dns_cache():
    """Flush the OS resolver cache; returns (ok, detail).

    Matters between phases: a PRE run against not-yet-enrolled internal
    names caches negative answers, and that cache can mask ZPA steering in
    the POST run (synthetic IPs never appear, so the run looks like a
    failure). ZCC keeps its own cache too — if POST still shows NXDOMAIN
    for an enrolled domain, restart ZCC before believing the result.
    """
    system = platform.system()
    cmds = {
        "Windows": [["ipconfig", "/flushdns"]],
        "Darwin": [["dscacheutil", "-flushcache"],
                   ["killall", "-HUP", "mDNSResponder"]],
        "Linux": [["resolvectl", "flush-caches"]],
    }.get(system, [])
    if not cmds:
        return False, f"no known flush command for {system}"
    results = []
    for cmd in cmds:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=20)
            outcome = "ok" if p.returncode == 0 else f"rc{p.returncode}"
        except (OSError, subprocess.SubprocessError) as e:
            outcome = f"failed({type(e).__name__})"
        results.append(f"{cmd[0]}={outcome}")
    ok = all("ok" in r for r in results)
    detail = ", ".join(results)
    if system == "Darwin" and not ok:
        detail += " — macOS flush needs sudo"
    return ok, detail


def preflight_checks(args, need_api=True, need_targets_file=None):
    """Return (all_ok, [(label, ok, detail), ...]) without probing."""
    checks = []

    py_ok = sys.version_info >= (3, 9)
    checks.append(("Python 3.9+",
                   py_ok,
                   f"{platform.python_version()} ({sys.executable})"))

    out_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    try:
        os.makedirs(out_dir, exist_ok=True)
        probe_file = os.path.join(out_dir, ".write-test")
        with open(probe_file, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe_file)
        checks.append(("Output folder writable", True, out_dir))
    except OSError as e:
        checks.append(("Output folder writable", False, f"{out_dir}: {e}"))

    zcc = detect_zcc()
    checks.append(("Zscaler Client Connector",
                   zcc["state"] == "running",
                   f"{zcc['state']}"
                   + (f" ({', '.join(zcc['processes_found'])})"
                      if zcc["processes_found"] else
                      " — process names vary by ZCC version; verify in the"
                      " ZCC UI")))

    # Resolve what the tool actually depends on, not an arbitrary public
    # name. A single hardcoded probe host is a false-failure trap: DNS
    # filtering (homelab blocklists, ZIA policy) commonly NXDOMAINs
    # well-known resolver hostnames, which says nothing about whether DNS
    # works. Any one success is enough.
    socket.setdefaulttimeout(5)
    vanity = args.vanity_domain or os.environ.get("ZSCALER_VANITY_DOMAIN")
    candidates = []
    if vanity:
        candidates.append(f"{vanity}.zslogin.net")
    candidates.append(urllib.parse.urlsplit(
        getattr(args, "api_base", DEFAULT_API_BASE)).hostname
        or "api.zsapi.net")
    candidates += ["github.com", "example.com"]

    resolved, errors = None, []
    for host in candidates:
        try:
            socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            resolved = host
            break
        except OSError as e:
            errors.append(f"{host}: {e}")
    if resolved:
        checks.append(("DNS resolution", True, f"resolved {resolved}"))
    else:
        checks.append(("DNS resolution", False, "; ".join(errors[:3])))

    if need_targets_file:
        ok = os.path.isfile(need_targets_file)
        checks.append(("Targets file readable", ok,
                       os.path.abspath(need_targets_file)))
    elif need_api:
        have = all([args.client_id or os.environ.get("ZSCALER_CLIENT_ID"),
                    args.vanity_domain
                    or os.environ.get("ZSCALER_VANITY_DOMAIN"),
                    args.customer_id or os.environ.get("ZPA_CUSTOMER_ID")])
        checks.append(("OneAPI credentials present", have,
                       "client id / vanity domain / customer id"
                       + ("" if have else " — one or more missing")))

    return all(ok for _, ok, _ in checks), checks


def print_checks(checks):
    print("\nPreflight")
    for label, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label:<28} {detail}")
    print()


# --------------------------------------------------------------------------
# OneAPI client
# --------------------------------------------------------------------------

def build_ssl_context(args):
    if getattr(args, "insecure", False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if getattr(args, "ca_bundle", None):
        return ssl.create_default_context(cafile=args.ca_bundle)
    return ssl.create_default_context()


def http_json(url, ctx, headers=None, data=None, timeout=30, retries=4):
    """GET/POST JSON with backoff on 429, 5xx, and transient network errors.

    The Zscaler APIs rate-limit; a tenant with many segments pages enough
    times to hit it. Honors Retry-After when the server supplies it.

    URLError is retried too: a paginated fetch across a TLS-inspected
    corporate egress is long enough that a single reset or DNS blip would
    otherwise abort the whole inventory pull.
    """
    delay = 2.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            retryable = e.code == 429 or 500 <= e.code < 600
            if not retryable or attempt == retries:
                raise
            wait = delay
            ra = e.headers.get("Retry-After") if e.headers else None
            if ra:
                try:
                    wait = float(ra)
                except ValueError:
                    pass
            print(f"    [!] HTTP {e.code} from API — retrying in "
                  f"{wait:.0f}s ({attempt + 1}/{retries})")
            time.sleep(wait)
            delay = min(delay * 2, 30)
        except urllib.error.URLError as e:
            # HTTPError subclasses URLError, so this is a genuine network
            # failure (DNS, reset, TLS) — retry, then let it surface.
            if attempt == retries:
                raise
            print(f"    [!] {e.reason} — retrying in {delay:.0f}s "
                  f"({attempt + 1}/{retries})")
            time.sleep(delay)
            delay = min(delay * 2, 30)


# --------------------------------------------------------------------------
# Saved tenants
# --------------------------------------------------------------------------
#
# Most pilots run against two tenants — a model/test one and production —
# and retyping four OneAPI values per run invites pasting the wrong set.
# Saving them removes that, but it also means picking the wrong entry now
# silently points every probe at the wrong company's infrastructure, so
# selection is confirmed twice and production tenants are flagged.
#
# The client secret is only stored if explicitly opted into: the tool's
# baseline promise is that the secret never touches disk, and that is worth
# keeping as the default.

TENANT_STORE_ENV = "ZPA_TENANT_STORE"
DEFAULT_TENANT_DIR = "~/.zpa-connectivity-tester"
TENANT_FIELDS = ("client_id", "vanity_domain", "customer_id")

NO_TTY_TENANT = ("ERROR: no interactive terminal to choose a tenant — pass "
                 "--tenant NAME (with --yes to skip confirmation).")


def tenant_store_path():
    override = os.environ.get(TENANT_STORE_ENV)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(
        os.path.abspath(os.path.expanduser(DEFAULT_TENANT_DIR)),
        "tenants.json")


def _warn_if_readable_by_others(path):
    """POSIX only; Windows mode bits do not describe real ACLs."""
    if os.name == "nt":
        return
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        print(f"[!] {path} is readable by other users (mode {mode:o}) — "
              f"run: chmod 600 {path}")


def load_tenant_store():
    path = tenant_store_path()
    if not os.path.isfile(path):
        return {"tenants": []}
    try:
        with open(path, encoding="utf-8-sig") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"ERROR: cannot read tenant store {path}: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("tenants"), list):
        sys.exit(f"ERROR: {path} is not a tenant store — expected a JSON "
                 "object with a 'tenants' list.")
    _warn_if_readable_by_others(path)
    return doc


def save_tenant_store(doc):
    """Write 0600 from creation — never widen-then-narrow."""
    path = tenant_store_path()
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def find_tenant(doc, name):
    for t in doc.get("tenants") or []:
        if str(t.get("name", "")).lower() == str(name).lower():
            return t
    return None


def _describe_tenant(t):
    tag = "  ** PRODUCTION **" if t.get("production") else ""
    secret = "secret saved" if t.get("client_secret") else "secret prompted"
    return (f"{t.get('name', '?')}{tag}\n"
            f"        vanity domain : {t.get('vanity_domain', '?')}\n"
            f"        customer id   : {t.get('customer_id', '?')}\n"
            f"        client id     : {t.get('client_id', '?')}\n"
            f"        {secret}")


def confirm_tenant_choice(t):
    """Confirm before a tenant is used; production demands more.

    Production requires a second confirmation that types the tenant name,
    because a second yes/no gets answered reflexively and the failure being
    guarded against is sweeping production while believing it is the model
    tenant. Non-production is a single y/N on purpose: applying the same
    friction everywhere just trains people to type through it, which would
    weaken the prompt where it actually matters.
    """
    name = str(t.get("name", ""))
    is_prod = bool(t.get("production"))
    kind = "PRODUCTION tenant" if is_prod else "non-production tenant"
    print(f"\n  Selected {kind}:")
    print("    " + _describe_tenant(t).replace("\n", "\n    "))
    first = ask(f"\n  Run against '{name}'? [y/N]: ",
                NO_TTY_TENANT).strip().lower()
    if first not in ("y", "yes"):
        sys.exit("Aborted.")
    if not is_prod:
        return
    second = ask(f"  PRODUCTION — confirm by typing the tenant name exactly "
                 f"('{name}'): ", NO_TTY_TENANT).strip()
    if second != name:
        sys.exit(f"Aborted: '{second}' does not match '{name}'.")


def select_tenant(args):
    """Resolve which saved tenant to use, or None to fall back to env/prompt."""
    doc = load_tenant_store()
    tenants = doc.get("tenants") or []
    wanted = getattr(args, "tenant", None)

    if wanted:
        t = find_tenant(doc, wanted)
        if not t:
            names = ", ".join(str(x.get("name")) for x in tenants) or "none"
            sys.exit(f"ERROR: no saved tenant named '{wanted}'. "
                     f"Configured: {names}\n"
                     "Add one with:  zpa_segment_connectivity.py tenants add")
        # --tenant is an explicit choice; --yes means the caller scripted it
        if not args.yes:
            confirm_tenant_choice(t)
        return t

    if not tenants:
        return None

    print("\nSaved tenants:")
    for i, t in enumerate(tenants, 1):
        print(f"  [{i}] " + _describe_tenant(t).replace("\n", "\n      "))
    print(f"  [0] none of these — enter credentials manually")
    while True:
        raw = ask(f"Select tenant [0-{len(tenants)}]: ",
                  NO_TTY_TENANT).strip()
        if raw == "0":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(tenants):
            chosen = tenants[int(raw) - 1]
            break
        named = find_tenant(doc, raw)
        if named:
            chosen = named
            break
        print(f"  enter 0-{len(tenants)}, or a tenant name")
    confirm_tenant_choice(chosen)
    return chosen


def apply_tenant(args, tenant):
    """Tenant values fill only what an explicit flag has not already set."""
    if not tenant:
        return
    for field in TENANT_FIELDS:
        if not getattr(args, field, None):
            setattr(args, field, tenant.get(field) or None)
    if not getattr(args, "client_secret", None) and tenant.get("client_secret"):
        args.client_secret = tenant["client_secret"]
    args.tenant_name = tenant.get("name")


def run_tenants(args):
    doc = load_tenant_store()
    path = tenant_store_path()

    if args.action == "list":
        tenants = doc.get("tenants") or []
        if not tenants:
            print(f"No saved tenants ({path} does not exist yet).")
            print("Add one with:  zpa_segment_connectivity.py tenants add")
            return
        print(f"Saved tenants ({path}):\n")
        for i, t in enumerate(tenants, 1):
            print(f"  [{i}] " + _describe_tenant(t).replace("\n", "\n      "))
        print()
        return

    if args.action == "remove":
        if not args.name:
            sys.exit("ERROR: tenants remove requires a tenant name.")
        t = find_tenant(doc, args.name)
        if not t:
            sys.exit(f"ERROR: no saved tenant named '{args.name}'.")
        doc["tenants"] = [x for x in doc["tenants"] if x is not t]
        save_tenant_store(doc)
        print(f"Removed tenant '{t.get('name')}' from {path}")
        return

    # add
    name = args.name or ask("  Tenant name (e.g. model, production): ",
                            "ERROR: no terminal — pass a name: "
                            "tenants add <name>").strip()
    if not name:
        sys.exit("ERROR: tenant name is required.")
    existing = find_tenant(doc, name)
    if existing and not args.force:
        sys.exit(f"ERROR: tenant '{name}' already exists. Re-add with "
                 "--force to overwrite, or pick another name.")

    is_prod = ask(f"  Is '{name}' a PRODUCTION tenant? [y/N]: ",
                  "ERROR: no terminal for tenant setup."
                  ).strip().lower() in ("y", "yes")
    client_id = ask("  OneAPI client ID: ", "ERROR: no terminal.").strip()
    vanity = ask("  Zidentity vanity domain (the <name> in "
                 "<name>.zslogin.net): ", "ERROR: no terminal.").strip()
    customer = ask("  ZPA customer ID: ", "ERROR: no terminal.").strip()
    if not all([client_id, vanity, customer]):
        sys.exit("ERROR: client ID, vanity domain and customer ID are all "
                 "required.")

    print("\n  The client secret can be saved too, but it is stored in "
          "PLAINTEXT in\n"
          f"  {path} (permissions 0600). By default this tool never writes\n"
          "  the secret to disk and prompts for it each run instead.")
    save_secret = ask("  Save the client secret as well? [y/N]: ",
                      "ERROR: no terminal.").strip().lower() in ("y", "yes")
    secret = ""
    if save_secret:
        secret = getpass.getpass("  OneAPI client secret (hidden): ").strip()
        if not secret:
            print("  [!] Empty secret — not saving it; you will be prompted "
                  "each run.")

    entry = {"name": name, "production": is_prod, "client_id": client_id,
             "vanity_domain": vanity, "customer_id": customer}
    if secret:
        entry["client_secret"] = secret

    doc.setdefault("tenants", [])
    doc["tenants"] = [x for x in doc["tenants"] if x is not existing]
    doc["tenants"].append(entry)
    save_tenant_store(doc)
    print(f"\nSaved tenant '{name}' to {path} (mode 0600)"
          + ("  [secret stored]" if secret else "  [secret not stored]"))
    if is_prod:
        print("Marked PRODUCTION — selecting it will require confirming "
              "twice.")


def gather_credentials(args):
    """Resolve OneAPI credentials: command-line flag > env var > interactive
    prompt. Lets an end user run the tool with zero environment setup — they
    just paste the four values the ZPA admin gave them when asked. The secret
    is read with hidden input; the other three are not sensitive.

    Values are stored back on `args` (secret as args.client_secret, never in
    os.environ or argv) so the rest of the run reuses them.
    """
    def resolve(current, env_name, label, secret=False):
        val = current or os.environ.get(env_name)
        if val:
            return val
        if not sys.stdin.isatty():
            sys.exit(f"ERROR: {label} not provided and no terminal to prompt. "
                     f"Set {env_name} or pass the flag.")
        try:
            val = (getpass.getpass(f"  {label} (hidden): ") if secret
                   else input(f"  {label}: ").strip())
        except EOFError:
            sys.exit(f"ERROR: {label} not provided.")
        if not val:
            sys.exit(f"ERROR: {label} is required.")
        return val

    # A saved tenant fills in whatever an explicit flag has not already set,
    # and still leaves env vars and the prompt as fallbacks below.
    if not getattr(args, "tenant_name", None):
        apply_tenant(args, select_tenant(args))

    need = not all([
        args.client_id or os.environ.get("ZSCALER_CLIENT_ID"),
        args.vanity_domain or os.environ.get("ZSCALER_VANITY_DOMAIN"),
        args.customer_id or os.environ.get("ZPA_CUSTOMER_ID"),
        getattr(args, "client_secret", None)
        or os.environ.get("ZSCALER_CLIENT_SECRET")])
    if need and sys.stdin.isatty():
        print("\nZscaler OneAPI credentials (from your ZPA administrator) —")
        print("press Enter to accept a value already set in the environment.")

    args.client_id = resolve(args.client_id, "ZSCALER_CLIENT_ID",
                             "OneAPI client ID")
    args.vanity_domain = resolve(
        args.vanity_domain, "ZSCALER_VANITY_DOMAIN",
        "Zidentity vanity domain (the <name> in <name>.zslogin.net)")
    args.customer_id = resolve(args.customer_id, "ZPA_CUSTOMER_ID",
                               "ZPA customer ID")
    args.client_secret = resolve(getattr(args, "client_secret", None),
                                 "ZSCALER_CLIENT_SECRET",
                                 "OneAPI client secret", secret=True)
    return args


def get_token(args, ctx):
    client_id = args.client_id or os.environ.get("ZSCALER_CLIENT_ID")
    vanity = args.vanity_domain or os.environ.get("ZSCALER_VANITY_DOMAIN")
    secret = (getattr(args, "client_secret", None)
              or os.environ.get("ZSCALER_CLIENT_SECRET"))

    if not client_id or not vanity:
        sys.exit("ERROR: client ID and vanity domain are required "
                 "(--client-id/--vanity-domain or ZSCALER_CLIENT_ID/"
                 "ZSCALER_VANITY_DOMAIN).")
    if not secret:
        secret = getpass.getpass("ZSCALER_CLIENT_SECRET (input hidden): ")

    token_url = f"https://{vanity}.zslogin.net/oauth2/v1/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
        "audience": OAUTH_AUDIENCE,
    }).encode("ascii")
    try:
        tok = http_json(token_url, ctx,
                        headers={"Content-Type":
                                 "application/x-www-form-urlencoded"},
                        data=body)
    except urllib.error.HTTPError as e:
        sys.exit(f"ERROR: token request to {token_url} failed: "
                 f"HTTP {e.code} {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError as e:
        sys.exit(f"ERROR: cannot reach {token_url}: {e.reason}\n"
                 "If your ZIA tenant TLS-inspects this destination, pass "
                 "--ca-bundle <corp-root-ca.pem>.")
    return tok["access_token"]


def fetch_app_segments(args, ctx, token):
    customer_id = args.customer_id or os.environ.get("ZPA_CUSTOMER_ID")
    if not customer_id:
        sys.exit("ERROR: ZPA customer ID required "
                 "(--customer-id or ZPA_CUSTOMER_ID).")

    base = args.api_base.rstrip("/")
    # Segments belonging to a microtenant are NOT returned by the default
    # (parent) view — omitting microtenantId silently under-reports them.
    mt = getattr(args, "microtenant_id", None)
    mt_q = f"&microtenantId={urllib.parse.quote(str(mt))}" if mt else ""
    url_tpl = (f"{base}/zpa/mgmtconfig/v1/admin/customers/"
               f"{customer_id}/application"
               f"?page={{page}}&pagesize={PAGE_SIZE}{mt_q}")
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/json"}

    segments, page, total_pages = [], 1, 1
    while page <= total_pages:
        try:
            data = http_json(url_tpl.format(page=page), ctx, headers=headers)
        except urllib.error.HTTPError as e:
            sys.exit(f"ERROR: segment fetch failed (page {page}): "
                     f"HTTP {e.code} {e.read().decode(errors='replace')[:300]}")
        except urllib.error.URLError as e:
            sys.exit(f"ERROR: cannot reach {base} (page {page}): {e.reason}\n"
                     "If your ZIA tenant TLS-inspects this destination, pass "
                     "--ca-bundle <corp-root-ca.pem>.")
        segments.extend(data.get("list", []))
        total_pages = int(data.get("totalPages", 1) or 1)
        page += 1
    return segments


def load_segments(args):
    """Segments from a frozen targets file, or live from the API."""
    if getattr(args, "targets_file", None):
        path = os.path.abspath(args.targets_file)
        prog = os.path.basename(sys.argv[0]) or "zpa_segment_connectivity.py"
        # Reachable even when preflight already flagged the file: preflight
        # failures are overridable (prompt or --yes), so this must fail with
        # a usable message rather than a traceback.
        try:
            with open(args.targets_file, encoding="utf-8-sig") as f:
                doc = json.load(f)
        except FileNotFoundError:
            sys.exit(
                f"ERROR: targets file not found: {path}\n"
                "Create it first, then re-run this command:\n"
                f"    python3 {prog} export-targets --out {args.targets_file}\n"
                "Or drop --targets-file to pull the inventory live from the "
                "API (you will be prompted for credentials).")
        except OSError as e:
            sys.exit(f"ERROR: cannot read targets file {path}: {e}")
        except ValueError as e:
            sys.exit(f"ERROR: {path} is not valid JSON: {e}\n"
                     "Re-create it with export-targets.")
        # Accept both the export-targets envelope and a bare segment array;
        # a list has no .get(), so the shape must be tested before reading.
        if isinstance(doc, list):
            segs, src = doc, f"targets-file {path}"
        elif isinstance(doc, dict):
            segs = doc.get("segments") or []
            src = (f"targets-file {path} "
                   f"(exported {doc.get('exported_utc', 'unknown')})")
        else:
            sys.exit(f"ERROR: {path} is not a ZPA targets file — expected a "
                     "JSON object with a 'segments' key, or a JSON array of "
                     "segments.")
        print(f"[*] Loaded {len(segs)} segments from {src}")
        return segs, "targets-file"
    gather_credentials(args)
    ctx = build_ssl_context(args)
    print("[*] Authenticating to Zscaler OneAPI ...")
    token = get_token(args, ctx)
    print("[*] Fetching application segments ...")
    segs = fetch_app_segments(args, ctx, token)
    print(f"[*] {len(segs)} application segments in tenant")
    return segs, "api"


def run_export_targets(args):
    gather_credentials(args)
    ctx = build_ssl_context(args)
    print("[*] Authenticating to Zscaler OneAPI ...")
    token = get_token(args, ctx)
    print("[*] Fetching application segments ...")
    segments = fetch_app_segments(args, ctx, token)
    doc = {
        "exported_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "script_version": SCRIPT_VERSION,
        "customer_id": args.customer_id or os.environ.get("ZPA_CUSTOMER_ID"),
        "segment_count": len(segments),
        "segments": segments,
    }
    out = os.path.abspath(os.path.expanduser(args.out))
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    print(f"[*] Wrote {len(segments)} segments to {out}")
    print("    Re-run tests against this frozen inventory with "
          "--targets-file (no credentials needed).")
    return out


# --------------------------------------------------------------------------
# Segment parsing
# --------------------------------------------------------------------------

def classify_entry(entry):
    """Classify a domainNames entry: wildcard | cidr | ip | fqdn."""
    if entry.startswith("*"):
        return "wildcard"
    if "/" in entry:
        try:
            ipaddress.ip_network(entry, strict=False)
            return "cidr"
        except ValueError:
            return "fqdn"
    try:
        ipaddress.ip_address(entry)
        return "ip"
    except ValueError:
        return "fqdn"


def port_ranges(seg, key):
    """Normalize a segment's port definition to (lo, hi) tuples.

    ZPA returns ports in two shapes that coexist in the same payload, and
    which one is populated varies by tenant and API version (confirmed
    against zscaler-sdk-python zscaler/zpa/models/application_segment.py):

        tcpPortRange  -> [{"from": "443", "to": "443"}]
        tcpPortRanges -> ["443", "443", "8080", "8090"]   flat from,to pairs

    Both are read and unioned. Reading only one silently yields zero ports,
    which produces a DNS-only run that looks like a pass.
    """
    found = []

    for r in seg.get(key) or []:                      # object form
        if not isinstance(r, dict):
            continue
        try:
            found.append((int(r["from"]), int(r["to"])))
        except (KeyError, TypeError, ValueError):
            continue

    flat = seg.get(key + "s") or []                   # flat pair form
    if isinstance(flat, list):
        for i in range(0, len(flat) - 1, 2):
            try:
                found.append((int(flat[i]), int(flat[i + 1])))
            except (TypeError, ValueError):
                continue

    out = []
    for lo, hi in found:
        if 0 < lo <= hi <= 65535 and (lo, hi) not in out:
            out.append((lo, hi))
    return out


def expand_ports(ranges, max_ports):
    """Expand port ranges; max_ports=None means exhaustive (full scope).

    When capping, the endpoints of EVERY range are queued ahead of every
    range's interior, so a segment defined as a wide range plus a specific
    port (e.g. 1-1000 and 443) still probes 443. Front-loading endpoints
    per-range instead would let the first wide range consume the whole cap
    and silently drop the ports that were called out individually.
    """
    endpoints, interiors = [], []
    for lo, hi in ranges:
        endpoints.append(lo)
        if hi != lo:
            endpoints.append(hi)
        if hi - lo > 1:
            interiors.extend(range(lo + 1, hi))
    seen, ordered = set(), []
    for p in endpoints + interiors:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    if max_ports is None:
        return sorted(ordered), 0
    return ordered[:max_ports], max(0, len(ordered) - max_ports)


def spread_sample(items, n):
    """Pick n items spread evenly across the list, keeping first and last."""
    if n is None or len(items) <= n:
        return list(items)
    if n == 1:
        return [items[0]]
    idx = sorted({round(i * (len(items) - 1) / (n - 1)) for i in range(n)})
    return [items[i] for i in idx]


def cidr_hosts(entry, scope, sample_n):
    """Return (host_ips, truncated_count) for a CIDR entry.

    full   -> every usable host, hard-capped at FULL_CIDR_HOST_CAP
    sample -> sample_n hosts spread across the usable range
    Never materializes huge networks in memory (offsets are computed).
    """
    net = ipaddress.ip_network(entry, strict=False)
    base = int(net.network_address)
    total = net.num_addresses
    if total <= 2:                      # /31, /32
        lo_off, hi_off = 0, total - 1
    else:                               # skip network + broadcast
        lo_off, hi_off = 1, total - 2
    count = hi_off - lo_off + 1

    if scope == "full":
        take = min(count, FULL_CIDR_HOST_CAP)
        offs = range(lo_off, lo_off + take)
        truncated = count - take
    else:
        n = count if sample_n is None else sample_n
        if n <= 0:
            offs = []
        elif count <= n:
            offs = range(lo_off, hi_off + 1)
        elif n == 1:
            # the spread formula divides by (n - 1); mirror spread_sample
            # and take the first usable host
            offs = [lo_off]
        else:
            offs = sorted({lo_off + round(i * (count - 1) / (n - 1))
                           for i in range(n)})
        truncated = 0
    return [str(ipaddress.ip_address(base + o)) for o in offs], truncated


def build_targets(segments, args):
    """Build probe targets from the segment list, applying filters + scope."""
    scope = args.scope_resolved
    max_ports = None if scope == "full" else args.max_ports
    targets, skipped_wildcards = [], []
    stats = {"entries_total": 0, "entries_sampled_out": 0,
             "cidr_hosts_truncated": 0, "ports_truncated": 0,
             "segments_matched": 0,
             "kinds": {"fqdn": 0, "ip": 0, "cidr": 0, "wildcard": 0}}

    for seg in segments:
        if not isinstance(seg, dict):
            continue
        # a hand-written or partial targets file may omit name/id entirely
        seg_name = str(seg.get("name") or f"(unnamed-{seg.get('id', '?')})")
        if args.sipa_only and not seg.get("ipAnchored"):
            continue
        if args.enabled_only and not seg.get("enabled", True):
            continue
        if args.segment and args.segment.lower() not in seg_name.lower():
            continue
        stats["segments_matched"] += 1

        ports, p_trunc = expand_ports(port_ranges(seg, "tcpPortRange"),
                                      max_ports)
        stats["ports_truncated"] += p_trunc
        udp = port_ranges(seg, "udpPortRange")

        entries = [(e.strip().lower(), classify_entry(e.strip().lower()))
                   for e in seg.get("domainNames") or [] if e.strip()]
        stats["entries_total"] += len(entries)
        for _, kind in entries:
            stats["kinds"][kind] += 1

        # sample scope: thin FQDN/IP entries per segment; wildcards and
        # CIDRs are kept (CIDRs are sampled at the host level instead)
        if scope == "sample":
            direct = [e for e in entries if e[1] in ("fqdn", "ip")]
            keep = spread_sample(direct, args.sample_domains)
            stats["entries_sampled_out"] += len(direct) - len(keep)
            entries = keep + [e for e in entries
                              if e[1] in ("cidr", "wildcard")]

        base = {
            "segment": seg_name,
            "segment_id": seg.get("id", ""),
            "enabled": bool(seg.get("enabled", True)),
            "ip_anchored": bool(seg.get("ipAnchored", False)),
            "ports": ports,
            "udp_ranges": udp,
        }
        for entry, kind in entries:
            if kind == "wildcard":
                if args.wildcard_probe:
                    targets.append({**base, "kind": "wildcard",
                                    "domain": entry,
                                    "probe_domain":
                                    args.wildcard_probe + entry.lstrip("*")})
                else:
                    skipped_wildcards.append((seg_name, entry))
            elif kind == "cidr":
                hosts, trunc = cidr_hosts(entry, scope, args.cidr_hosts)
                stats["cidr_hosts_truncated"] += trunc
                for hip in hosts:
                    targets.append({**base, "kind": "cidr", "domain": entry,
                                    "probe_domain": hip})
            else:
                targets.append({**base, "kind": kind, "domain": entry,
                                "probe_domain": entry})
    return targets, skipped_wildcards, stats


def estimate_probes(targets):
    return sum(max(1, len(t["ports"])) for t in targets)


# --------------------------------------------------------------------------
# Scope selection / confirmation
# --------------------------------------------------------------------------

def ask(prompt_text, no_tty_msg):
    """input() that fails cleanly when there is no usable terminal.

    isatty() is not a reliable non-interactive signal on Windows: NUL is a
    character device, so `cmd < NUL` and subprocess DEVNULL both report
    isatty()==True. Reading then hitting EOF is the portable check, so the
    EOFError is caught here and turned into the same guidance message
    rather than an unhandled traceback.
    """
    if not sys.stdin.isatty():
        sys.exit(no_tty_msg)
    try:
        return input(prompt_text)
    except EOFError:
        sys.exit(no_tty_msg)


NO_TTY_SCOPE = ("ERROR: no interactive terminal — pass --scope full|sample "
                "for non-interactive runs.")


def choose_scope(args):
    if args.scope:
        return args.scope
    print("\nTest scope for this run:")
    print("  [1] full   — exhaustive: every domain/IP, every usable CIDR "
          "host, every configured port")
    print("  [2] sample — representative: sampled entries per segment, "
          "spread CIDR hosts, capped ports")
    while True:
        choice = ask("Select scope [1/2]: ", NO_TTY_SCOPE).strip().lower()
        if choice in ("1", "full"):
            return "full"
        if choice in ("2", "sample"):
            return "sample"
        print("  enter 1 or 2")


def format_duration(seconds):
    """Human-scale duration; a raw probe count hides what it actually costs."""
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    if seconds < 63072000:
        return f"{seconds / 86400:,.0f} days"
    return f"{seconds / 31536000:,.0f} years"


def estimate_duration(n_probes, args):
    """(best_s, worst_s) wall clock for n_probes at this concurrency.

    worst = every probe burns the full timeout; best = every probe answers
    immediately. A real run lands between, but the worst case is the number
    that matters when deciding whether to start at all.
    """
    workers = max(1, int(getattr(args, "workers", 20) or 20))
    timeout = float(getattr(args, "timeout", 5.0) or 5.0)
    return n_probes / (workers * 200.0), n_probes * timeout / workers


def confirm_run(n_probes, args):
    best, worst = estimate_duration(n_probes, args)

    # A full-scope run against a real tenant can plan hundreds of billions of
    # probes — 156 CIDRs expanded to every host, times a 1-65535 port range.
    # Confirming that is not enough: it cannot finish, and what it emits is an
    # enormous port sweep against the App Connectors. Deliberately NOT
    # bypassed by --yes, because --yes means "unattended", not "unbounded".
    if worst > MAX_RUN_SECONDS and not getattr(args, "force_huge_run", False):
        sys.exit(
            f"ERROR: this run plans ~{n_probes:,} probes across "
            f"{max(1, int(args.workers))} workers — about "
            f"{format_duration(worst)} at worst case, "
            f"{format_duration(best)} if everything answers instantly.\n"
            "It cannot complete, and at this size it is a large port sweep "
            "against your App Connectors.\n\n"
            "Narrow it first:\n"
            "    --scope sample       representative subset (start here)\n"
            "    --max-ports N        cap TCP ports per segment\n"
            "    --cidr-hosts N       cap hosts probed per CIDR entry\n"
            "    --segment SUBSTR     one segment at a time\n"
            "    --enabled-only       skip disabled segments\n\n"
            "Override only if you genuinely intend it: --force-huge-run")

    if args.yes:
        return
    if args.scope_resolved == "sample" and n_probes <= CONFIRM_THRESHOLD:
        return
    ans = ask(f"About to run ~{n_probes:,} probes from this endpoint "
              f"(~{format_duration(worst)} worst case, "
              f"~{format_duration(best)} best). Proceed? [y/N]: ",
              f"ERROR: {n_probes:,} probes planned but no terminal to "
              "confirm — re-run with --yes to proceed unattended."
              ).strip().lower()
    if ans not in ("y", "yes"):
        sys.exit("Aborted.")


# --------------------------------------------------------------------------
# Probing
# --------------------------------------------------------------------------

def resolve(domain, timeout):
    """Resolve a domain; returns (ip or None, error or None).

    getaddrinfo has no per-call timeout, so the process-wide default is set
    once in run_test() rather than mutated from worker threads.
    """
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        return infos[0][4][0], None
    except socket.gaierror as e:
        return None, str(e)
    except OSError as e:
        return None, str(e)


def tcp_probe(host, port, timeout):
    """Attempt a TCP connect; returns (status, latency_ms)."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "OPEN", round((time.monotonic() - start) * 1000, 1)
    except socket.timeout:
        return "TIMEOUT", None
    except ConnectionRefusedError:
        return "REFUSED", None
    except OSError as e:
        return f"ERROR:{e.strerror or e}", None


def tcp_probe_retry(host, port, timeout, retries):
    """TCP connect with retries on transient failures.

    REFUSED is definitive (something answered) so it is never retried.
    A port that only succeeds on a later attempt is flagged OPEN_FLAKY so
    intermittent connector behaviour is visible rather than averaged away.
    """
    attempts = 0
    status, latency = "TIMEOUT", None
    for i in range(retries + 1):
        attempts += 1
        status, latency = tcp_probe(host, port, timeout)
        if status in ("OPEN", "REFUSED"):
            break
        if i < retries:
            time.sleep(0.2 + random.random() * 0.3)   # jitter
    if status == "OPEN" and attempts > 1:
        status = "OPEN_FLAKY"
    return status, latency, attempts


def l7_probe(host, port, timeout, sni=None):
    """Verify something is actually serving, not just that TCP answered.

    Tries TLS first; falls back to a plaintext HTTP HEAD. Certificates are
    not validated — the goal is proof of an application response, and
    internal PKI/TLS inspection would otherwise produce noise.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                    return f"TLS:{tls.version()}"
            except (ssl.SSLError, OSError):
                pass
        # not TLS — try a plaintext HTTP request on a fresh connection
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: "
                         + (sni or host).encode() + b"\r\n\r\n")
            data = sock.recv(128).decode("latin-1", "replace")
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", data)
        if m:
            return f"HTTP:{m.group(1)}"
        return "OPEN_NO_L7_RESPONSE"
    except (OSError, ssl.SSLError) as e:
        return f"L7_ERROR:{getattr(e, 'strerror', None) or type(e).__name__}"


def probe_target(target, args):
    """Probe one target: DNS (FQDNs only), then each TCP port."""
    rows = []
    base = {
        "segment": target["segment"],
        "enabled": target["enabled"],
        "ip_anchored": target["ip_anchored"],
        "entry_kind": target["kind"],
        "domain": target["domain"],
        "probe_domain": target["probe_domain"],
    }

    if target["kind"] in ("ip", "cidr"):
        ip, zpa_intercepted, sni = target["probe_domain"], "N/A", None
    else:
        ip, dns_err = resolve(target["probe_domain"], args.timeout)
        sni = target["probe_domain"]
        if dns_err:
            rows.append({**base, "resolved_ip": "", "zpa_intercepted": "",
                         "protocol": "dns", "port": "",
                         "status": f"DNS_FAIL:{dns_err}", "attempts": 1,
                         "latency_ms": "", "l7_result": ""})
            return rows
        try:
            zpa_intercepted = ipaddress.ip_address(ip) in ZPA_SYNTHETIC_NET
        except ValueError:
            zpa_intercepted = ""

    if not target["ports"]:
        rows.append({**base, "resolved_ip": ip,
                     "zpa_intercepted": zpa_intercepted,
                     "protocol": "dns" if target["kind"] == "fqdn" else "tcp",
                     "port": "", "status": "NO_TCP_PORTS", "attempts": 0,
                     "latency_ms": "", "l7_result": ""})
    for port in target["ports"]:
        status, latency, attempts = tcp_probe_retry(
            target["probe_domain"], port, args.timeout, args.retries)
        l7 = ""
        if args.l7 and status in ("OPEN", "OPEN_FLAKY"):
            l7 = l7_probe(target["probe_domain"], port, args.timeout, sni)
        rows.append({**base, "resolved_ip": ip,
                     "zpa_intercepted": zpa_intercepted,
                     "protocol": "tcp", "port": port,
                     "status": status, "attempts": attempts,
                     "latency_ms": latency if latency is not None else "",
                     "l7_result": l7})
    for lo, hi in target["udp_ranges"]:
        rows.append({**base, "resolved_ip": ip,
                     "zpa_intercepted": zpa_intercepted,
                     "protocol": "udp",
                     "port": f"{lo}-{hi}" if lo != hi else lo,
                     "status": "UDP_NOT_PROBED", "attempts": 0,
                     "latency_ms": "", "l7_result": ""})
    return rows


CSV_FIELDS = ["segment", "enabled", "ip_anchored", "entry_kind", "domain",
              "probe_domain", "resolved_ip", "zpa_intercepted", "protocol",
              "port", "status", "attempts", "latency_ms", "l7_result"]

OK_STATUSES = ("OPEN", "OPEN_FLAKY")

# Statuses that are not failures: reachable, or deliberately not probed.
NON_FAILURE_STATUSES = OK_STATUSES + ("UDP_NOT_PROBED", "WILDCARD_SKIPPED",
                                      "NO_TCP_PORTS")

# Caveat 1: IP/CIDR entries yield no synthetic IP, so neither a successful
# connect nor a timeout says anything about whether ZPA steered the traffic.
UNVERIFIABLE_KINDS = ("ip", "cidr")

# Console listing cap — the CSV always holds every row. Without this, a
# broadly-broken run replaces the summary with hundreds of lines.
ACTION_LIST_CAP = 25


def triage_failures(rows):
    """Split failing rows into (action_required, unverifiable_here).

    A flat failure list buries the findings that matter: on a real tenant the
    IP/CIDR timeouts vastly outnumber the FQDN failures, and only the latter
    are actionable from the endpoint.
    """
    action, unverifiable = [], []
    for r in rows:
        if str(r.get("status", "")) in NON_FAILURE_STATUSES:
            continue
        (unverifiable if r.get("entry_kind") in UNVERIFIABLE_KINDS
         else action).append(r)
    return action, unverifiable


def coverage_report(stats, args, tcp_probes):
    """Lines describing what the run actually verified, vs what it skipped.

    The headline OPEN ratio is computed over probes that ran, so a heavily
    sampled run can report ~100% reachable while having tested a tiny
    fraction of the inventory. This states that fraction explicitly.
    """
    k = stats["kinds"]
    direct_total = k["fqdn"] + k["ip"]
    direct_probed = max(0, direct_total - stats["entries_sampled_out"])
    ports_total = tcp_probes + stats["ports_truncated"]
    pct = (100.0 * direct_probed / direct_total) if direct_total else 100.0
    port_pct = (100.0 * tcp_probes / ports_total) if ports_total else 100.0

    lines = [f"  fqdn/ip entries:   {direct_probed}/{direct_total} probed "
             f"({pct:.1f}%)"]
    if stats["entries_sampled_out"]:
        lines.append(f"                     {stats['entries_sampled_out']} not "
                     f"probed (--sample-domains {args.sample_domains})")
    if k["cidr"]:
        lines.append(f"  cidr entries:      {k['cidr']} expanded to sampled "
                     f"hosts (--cidr-hosts {args.cidr_hosts})")
    if k["wildcard"]:
        probed_wc = "probed" if args.wildcard_probe else "NOT probed"
        lines.append(f"  wildcard entries:  {k['wildcard']} {probed_wc}"
                     + ("" if args.wildcard_probe
                        else "  (--wildcard-probe LABEL)"))
    lines.append(f"  tcp ports:         {tcp_probes}/{ports_total} probed "
                 f"({port_pct:.1f}%)")
    if stats["ports_truncated"]:
        lines.append(f"                     {stats['ports_truncated']} dropped "
                     f"(--max-ports {args.max_ports}; --scope full for all)")
    return lines


def next_steps(args, stats, action, unverifiable, dns_fail, dns_flush_ok,
               intercepted):
    """Recommendations derived from this run's actual results.

    dns_flush_ok is the boolean from flush_dns_cache(): True fully flushed,
    False attempted-but-incomplete, None not attempted. Do NOT infer this
    from the detail string — macOS reports "dscacheutil=ok, killall=rc1"
    for a FAILED flush, so substring-matching "ok" gets it backwards.
    """
    prog = os.path.basename(sys.argv[0]) or "zpa_segment_connectivity.py"
    steps = []
    if dns_fail and args.phase == "post":
        if dns_flush_ok is False:
            steps.append(
                "The DNS cache flush did not fully succeed, and a stale "
                "negative entry can fake a post-run DNS failure (caveat 2). "
                "Re-run it with sudo before treating these as real:\n"
                f"       sudo python3 {prog} test --phase post --flush-dns ...")
        elif dns_flush_ok is None:
            steps.append(
                "This post run did not flush the DNS cache, so a negative "
                "entry cached during the pre run can mask steering "
                "(caveat 2). Re-run with --flush-dns (sudo on macOS).")
        else:
            steps.append(
                f"{len(dns_fail)} DNS failure(s) with a clean cache flush: "
                "confirm the domain is enrolled and assigned to your account, "
                "then restart ZCC before treating it as real.")
    if unverifiable:
        segs = sorted({r["segment"] for r in unverifiable})
        steps.append(
            f"{len(unverifiable)} probe(s) across {len(segs)} segment(s) were "
            "IP/CIDR entries, which cannot prove steering from an endpoint "
            "(caveat 1). Confirm them in the ZPA admin portal's access logs.")
    if stats["kinds"]["wildcard"] and not args.wildcard_probe:
        steps.append(
            f"{stats['kinds']['wildcard']} wildcard entries were not probed. "
            "Re-run with --wildcard-probe www to cover them.")
    if stats["entries_sampled_out"] or stats["ports_truncated"]:
        steps.append(
            "This was a sampled run — see Coverage above. Use --scope full "
            "(or raise --sample-domains/--max-ports) for final validation; "
            "a full run against wide CIDRs is a port sweep, so notify "
            "whoever watches IDS first.")
    if args.phase == "post" and not intercepted:
        steps.append(
            "No synthetic IPs were observed, so nothing proves ZPA is "
            "steering yet. Check Private Access is ON and authenticated in "
            "ZCC, and that your account is in the access policy.")
    return steps


# --------------------------------------------------------------------------
# Summary rendering
# --------------------------------------------------------------------------
#
# ASCII-only rules and glyphs here on purpose: this prints to a legacy
# Windows console often enough that box-drawing characters are a real risk,
# and a mangled separator is worse than a plain one.

SECTION_WIDTH = 76
INTERCEPT_LIST_CAP = 15
SLOW_SEGMENT_CAP = 5
ROLLUP_CAP = 20

# Failure statuses grouped by what they actually imply. Lumping REFUSED in
# with TIMEOUT is actively misleading: a refusal proves the path works.
FAILURE_CLASSES = [
    ("TIMEOUT", "nothing answered — traffic may not be steered, or is dropped"),
    ("DNS_FAIL", "name did not resolve — check enrollment, then caveat 2"),
    ("REFUSED", "host answered and declined — path works, nothing listening"),
    ("OTHER", "probe/socket errors — see the CSV"),
]


def _section(title):
    """A consistent section rule; long summaries are unscannable without it."""
    bar = "-" * max(4, SECTION_WIDTH - len(title) - 6)
    return f"\n  -- {title} {bar}"


def classify_failure(status):
    s = str(status)
    if s == "TIMEOUT":
        return "TIMEOUT"
    if s == "REFUSED":
        return "REFUSED"
    if s.startswith("DNS_FAIL"):
        return "DNS_FAIL"
    return "OTHER"


def run_verdict(args, intercepted, zcc):
    """One-line answer to the question the run exists to settle.

    The pre-phase branch matters: running --phase pre on a laptop that is
    already enrolled silently captures a post-state labelled "pre", and the
    later compare is then meaningless rather than obviously wrong.
    """
    n = len(intercepted)
    if args.phase == "pre":
        if n:
            return ("BASELINE INVALID",
                    f"{n} domain(s) already steered into ZPA — this is a "
                    "post-state, not a pre-ZPA baseline")
        return ("BASELINE CAPTURED",
                "no synthetic IPs, as expected before ZPA is enabled")
    if n:
        return ("ZPA IS STEERING",
                f"{n} domain(s) resolved into 100.64.0.0/10")
    if zcc.get("state") != "running":
        return ("NO STEERING OBSERVED",
                "no synthetic IPs, and ZCC was not detected running")
    return ("NO STEERING OBSERVED",
            "ZCC is running but nothing resolved into the synthetic range")


def status_histogram(rows):
    """status -> count, collapsing the ':detail' suffix off error statuses."""
    counts = {}
    for r in rows:
        s = str(r.get("status", ""))
        if ":" in s:
            s = s.split(":", 1)[0]
        counts[s] = counts.get(s, 0) + 1
    return counts


def _port_list(ports):
    """Compact, numerically sorted port list for a grouped failure line."""
    nums, others = [], []
    for p in ports:
        try:
            nums.append(int(p))
        except (TypeError, ValueError):
            if str(p):
                others.append(str(p))
    shown = [str(n) for n in sorted(set(nums))] + sorted(set(others))
    if len(shown) > 8:
        return ",".join(shown[:8]) + f",+{len(shown) - 8}"
    return ",".join(shown)


def group_failures(rows):
    """Collapse to (segment, host, class) -> ports.

    Without this, one unreachable host with a wide port range prints one
    line per port and buries every other finding.
    """
    groups = {}
    for r in rows:
        key = (str(r.get("segment", "")), str(r.get("probe_domain", "")),
               classify_failure(r.get("status")))
        g = groups.setdefault(key, {"ports": [], "n": 0})
        g["n"] += 1
        p = r.get("port")
        if p not in ("", None):
            g["ports"].append(p)
    return groups


def latency_stats(rows):
    """Percentiles over successful connects; None when nothing succeeded.

    Already collected per probe and previously discarded — on a ZPA rollout
    "is it slower now" is asked as often as "does it work".
    """
    vals = []
    for r in rows:
        if str(r.get("status", "")) not in OK_STATUSES:
            continue
        try:
            vals.append(float(r.get("latency_ms")))
        except (TypeError, ValueError):
            continue
    if not vals:
        return None
    vals.sort()

    def pct(p):
        if len(vals) == 1:
            return vals[0]
        return vals[min(len(vals) - 1,
                        int(round((p / 100.0) * (len(vals) - 1))))]

    return {"count": len(vals), "median_ms": round(pct(50), 1),
            "p95_ms": round(pct(95), 1), "max_ms": round(vals[-1], 1)}


def slowest_segments(rows, cap=SLOW_SEGMENT_CAP):
    """[(segment, median_ms, n)] worst first — where latency actually lives."""
    per = {}
    for r in rows:
        if str(r.get("status", "")) not in OK_STATUSES:
            continue
        try:
            per.setdefault(str(r.get("segment", "")), []).append(
                float(r.get("latency_ms")))
        except (TypeError, ValueError):
            continue
    out = []
    for seg, vals in per.items():
        vals.sort()
        out.append((seg, round(vals[len(vals) // 2], 1), len(vals)))
    out.sort(key=lambda t: t[1], reverse=True)
    return out[:cap]


def segment_rollup(all_rows):
    """Per-segment probed/open/failed/steered — the reportable view."""
    segs = {}
    for r in all_rows:
        seg = str(r.get("segment", ""))
        d = segs.setdefault(seg, {"probed": 0, "open": 0, "failed": 0,
                                  "dns_fail": 0, "steered": False,
                                  "kinds": set()})
        kind = r.get("entry_kind", "")
        if kind:
            d["kinds"].add(kind)
        st = str(r.get("status", ""))
        if str(r.get("zpa_intercepted")) == "True":
            d["steered"] = True
        if st.startswith("DNS_FAIL"):
            d["dns_fail"] += 1
        elif r.get("protocol") == "tcp" and st != "NO_TCP_PORTS":
            d["probed"] += 1
            if st in OK_STATUSES:
                d["open"] += 1
            else:
                d["failed"] += 1
    return segs


def run_test(args):
    args.scope_resolved = choose_scope(args)

    ok, checks = preflight_checks(
        args, need_api=not args.targets_file,
        need_targets_file=args.targets_file)
    print_checks(checks)
    if not ok and not args.yes:
        if ask("Preflight has failures. Continue anyway? [y/N]: ",
               "ERROR: preflight failed — fix the items above or "
               "re-run with --yes to override.").strip().lower() \
                not in ("y", "yes"):
            sys.exit("Aborted.")

    dns_flush, dns_flush_ok = "not attempted", None
    if args.flush_dns:
        ok_flush, detail = flush_dns_cache()
        dns_flush, dns_flush_ok = detail, ok_flush
        print(f"[*] DNS cache flush: {detail}")
        if not ok_flush:
            print("    [!] Flush incomplete — stale negative cache entries "
                  "can mask ZPA steering in a post run.")

    zcc = detect_zcc()
    segments, source = load_segments(args)

    targets, skipped_wildcards, stats = build_targets(segments, args)
    k = stats["kinds"]
    print(f"[*] Scope: {args.scope_resolved.upper()}")
    if args.sipa_only:
        print("[*] SIPA filter active (ipAnchored=true segments only)")
    print(f"[*] Segments matched: {stats['segments_matched']}")
    print(f"[*] Entries: {stats['entries_total']} total "
          f"({k['fqdn']} fqdn, {k['ip']} ip, {k['cidr']} cidr, "
          f"{k['wildcard']} wildcard)")
    if stats["entries_sampled_out"]:
        print(f"[*] Sampling left out {stats['entries_sampled_out']} "
              f"fqdn/ip entries (increase --sample-domains to widen)")
    if stats["cidr_hosts_truncated"]:
        print(f"[!] {stats['cidr_hosts_truncated']} CIDR hosts beyond the "
              f"{FULL_CIDR_HOST_CAP}-host cap were NOT queued")
    if stats["ports_truncated"]:
        print(f"[*] {stats['ports_truncated']} ports dropped by --max-ports "
              f"cap (use --scope full for all ports)")
    if skipped_wildcards:
        print(f"[!] {len(skipped_wildcards)} wildcard domains skipped "
              f"(re-run with --wildcard-probe <label> to include them)")

    n_probes = estimate_probes(targets)
    print(f"[*] {len(targets)} targets / ~{n_probes} probes planned"
          + (f" (+ up to {args.retries} retry each)" if args.retries else ""))
    confirm_run(n_probes, args)

    # getaddrinfo takes no per-call timeout; set the process default once
    socket.setdefaulttimeout(args.timeout)
    started = datetime.now(timezone.utc)

    all_rows, interrupted, worker_errors = [], False, 0
    pool = concurrent.futures.ThreadPoolExecutor(args.workers)
    try:
        futures = {pool.submit(probe_target, t, args): t for t in targets}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            try:
                all_rows.extend(fut.result())
            except Exception as e:
                # One malformed target must not discard a long run's results.
                # Record it as a row so the failure is visible in the CSV
                # rather than vanishing into a traceback.
                t = futures[fut]
                worker_errors += 1
                all_rows.append({
                    "segment": t.get("segment", ""), "enabled": "",
                    "ip_anchored": "", "entry_kind": t.get("kind", ""),
                    "domain": t.get("domain", ""),
                    "probe_domain": t.get("probe_domain", ""),
                    "resolved_ip": "", "zpa_intercepted": "",
                    "protocol": "", "port": "",
                    "status": f"PROBE_ERROR:{type(e).__name__}",
                    "attempts": 0, "latency_ms": "", "l7_result": ""})
            done += 1
            if done % 25 == 0 or done == len(futures):
                print(f"    probed {done}/{len(futures)} targets")
    except KeyboardInterrupt:
        # long full-scope runs are worth salvaging — keep partial results
        interrupted = True
        print("\n[!] Interrupted — writing partial results collected so far.")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    for seg_name, domain in skipped_wildcards:
        all_rows.append({"segment": seg_name, "enabled": "", "ip_anchored": "",
                         "entry_kind": "wildcard", "domain": domain,
                         "probe_domain": "", "resolved_ip": "",
                         "zpa_intercepted": "", "protocol": "", "port": "",
                         "status": "WILDCARD_SKIPPED", "attempts": 0,
                         "latency_ms": "", "l7_result": ""})

    all_rows.sort(key=lambda r: (r["segment"], r["domain"],
                                 str(r["probe_domain"]),
                                 str(r["protocol"]), str(r["port"])))

    out_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    os.makedirs(out_dir, exist_ok=True)
    ts = started.strftime("%Y%m%dT%H%M%SZ")
    # sanitize: keep the filename portable across platforms
    host = "".join(ch if ch.isalnum() or ch in "-_" else "-"
                   for ch in socket.gethostname().split(".")[0])
    partial = "_PARTIAL" if interrupted else ""
    stem = f"{args.phase}_{args.scope_resolved}_{host}_{ts}{partial}"
    out_path = os.path.join(out_dir, stem + ".csv")
    # Explicit UTF-8: Windows still defaults to the locale code page (cp1252
    # here), so a segment name outside it would raise UnicodeEncodeError at
    # this line — after every probe had already run.
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(all_rows)

    tcp_rows = [r for r in all_rows if r["protocol"] == "tcp"
                and r["status"] != "NO_TCP_PORTS"]
    open_ = [r for r in tcp_rows if r["status"] in OK_STATUSES]
    flaky = [r for r in tcp_rows if r["status"] == "OPEN_FLAKY"]
    dns_fail = [r for r in all_rows if str(r["status"]).startswith("DNS_FAIL")]
    intercepted = {r["domain"] for r in all_rows
                   if r["zpa_intercepted"] is True}

    # Empirical ZPA evidence beats process detection: synthetic IPs mean
    # ZCC is actively steering these segments into ZPA.
    zpa_evidence = ("synthetic IPs observed" if intercepted
                    else "no synthetic IPs observed")
    verdict_label, verdict_detail = run_verdict(args, intercepted, zcc)
    lat = latency_stats(all_rows)

    meta = {
        "script_version": SCRIPT_VERSION,
        "phase": args.phase,
        "scope": args.scope_resolved,
        "hostname": socket.gethostname(),
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_utc": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "interrupted": interrupted,
        "segment_source": source,
        "filters": {"sipa_only": args.sipa_only,
                    "enabled_only": args.enabled_only,
                    "segment_substr": args.segment,
                    "wildcard_probe": args.wildcard_probe},
        "sampling": {"sample_domains": args.sample_domains,
                     "cidr_hosts": args.cidr_hosts,
                     "max_ports": args.max_ports,
                     "retries": args.retries, "l7": args.l7,
                     "timeout_s": args.timeout, "workers": args.workers},
        "zcc": zcc,
        "dns_cache_flush": dns_flush,
        "zpa_evidence": zpa_evidence,
        "verdict": verdict_label,
        "verdict_detail": verdict_detail,
        "stats": stats,
        "results": {"tcp_probes": len(tcp_rows), "open": len(open_),
                    "flaky": len(flaky), "dns_failures": len(dns_fail),
                    "intercepted_domains": len(intercepted),
                    "wildcards_skipped": len(skipped_wildcards),
                    "worker_errors": worker_errors},
        "status_counts": status_histogram(all_rows),
        "latency": lat,
        "slowest_segments": [{"segment": s, "median_ms": m, "probes": n}
                             for s, m, n in slowest_segments(all_rows)],
        "intercepted_domain_list": sorted(intercepted),
    }
    meta_path = os.path.join(out_dir, stem + ".meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print()
    print(f"=== {args.phase.upper()} run summary "
          f"({args.scope_resolved} scope, {host}, {ts}) ===")
    print(f"  VERDICT   {verdict_label}")
    print(f"            {verdict_detail}")
    hist = status_histogram(all_rows)
    order = [s for s in ("OPEN", "OPEN_FLAKY") if s in hist] + sorted(
        (s for s in hist if s not in ("OPEN", "OPEN_FLAKY")),
        key=lambda s: -hist[s])
    print("  RESULTS   " + "  ".join(f"{s} {hist[s]}" for s in order))
    if worker_errors:
        print(f"  [!] {worker_errors} target(s) raised a probe error — see "
              "PROBE_ERROR rows in the CSV")

    print(_section("COVERAGE"))
    for line in coverage_report(stats, args, len(tcp_rows)):
        print(line)

    if lat:
        print(_section("LATENCY (successful connects)"))
        print(f"  median {lat['median_ms']}ms   p95 {lat['p95_ms']}ms   "
              f"max {lat['max_ms']}ms   over {lat['count']} probes")
        slow = slowest_segments(all_rows)
        if len(slow) > 1:
            print("  slowest segments (median):")
            for seg, med, n in slow:
                print(f"    {seg:<44} {med:>8.1f}ms  "
                      f"({n} probe{'' if n == 1 else 's'})")

    if intercepted:
        print(_section("ZPA-STEERED DOMAINS"))
        shown = sorted(intercepted)[:INTERCEPT_LIST_CAP]
        for d in shown:
            print(f"    {d}")
        if len(intercepted) > INTERCEPT_LIST_CAP:
            print(f"    ... +{len(intercepted) - INTERCEPT_LIST_CAP} more "
                  "(zpa_intercepted=True in the CSV)")

    rollup = segment_rollup(all_rows)
    if len(rollup) > 1:
        print(_section("SEGMENT HEALTH"))
        print(f"    {'segment':<40} {'probed':>7} {'open':>6} {'failed':>7} "
              f"{'steered':>8}")
        ranked = sorted(rollup.items(),
                        key=lambda kv: (-kv[1]["failed"] - kv[1]["dns_fail"],
                                        kv[0]))
        for seg, d in ranked[:ROLLUP_CAP]:
            if d["kinds"] and d["kinds"].issubset(set(UNVERIFIABLE_KINDS)):
                steer = "n/a"
            else:
                steer = "yes" if d["steered"] else "no"
            failed = d["failed"] + d["dns_fail"]
            print(f"    {seg[:40]:<40} {d['probed']:>7} {d['open']:>6} "
                  f"{failed:>7} {steer:>8}")
        if len(ranked) > ROLLUP_CAP:
            print(f"    ... +{len(ranked) - ROLLUP_CAP} more segments")

    action, unverifiable = triage_failures(all_rows)
    if args.show_failures:
        print(_section(f"FINDINGS ({len(action)} actionable)"))
        if not action:
            print("    none — every probed entry behaved as expected")
        else:
            groups = group_failures(action)
            shown_rows = 0
            for cls, meaning in FAILURE_CLASSES:
                sel = {k: v for k, v in groups.items() if k[2] == cls}
                if not sel:
                    continue
                total = sum(v["n"] for v in sel.values())
                print(f"\n    {cls}  ({total} probes) — {meaning}")
                for (seg, hostname, _), g in sorted(
                        sel.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
                    if shown_rows >= ACTION_LIST_CAP:
                        break
                    ports = _port_list(g["ports"])
                    print(f"      {seg[:34]:<34} {hostname[:30]:<30} "
                          + (f"tcp/{ports}" if ports else ""))
                    shown_rows += 1
            remaining = len(groups) - shown_rows
            if remaining > 0:
                print(f"\n    ... +{remaining} more grouped finding(s) — full "
                      "list in the CSV, or --report for the HTML view")

        if unverifiable:
            by_seg = {}
            for r in unverifiable:
                by_seg.setdefault(r["segment"], set()).add(
                    str(r["probe_domain"]))
            print(f"\n    UNVERIFIABLE HERE ({len(unverifiable)} probes) — "
                  "IP/CIDR entries; confirm in the ZPA portal (caveat 1)")
            for seg in sorted(by_seg):
                hosts = sorted(by_seg[seg])
                shown = ", ".join(hosts[:4]) + (
                    f", +{len(hosts) - 4} more" if len(hosts) > 4 else "")
                print(f"      {seg[:34]:<34} {shown}")

    steps = next_steps(args, stats, action, unverifiable, dns_fail,
                       dns_flush_ok, intercepted)
    if steps:
        print(_section("NEXT STEPS"))
        for i, s in enumerate(steps, 1):
            print(f"    {i}. {s}")

    print(_section("OUTPUT"))
    print(f"    CSV       {out_path}")
    print(f"    metadata  {meta_path}")

    if args.report:
        html_path = os.path.join(out_dir, stem + ".html")
        write_html_report(html_path, [(out_path, all_rows, meta)])
        print(f"    report    {html_path}")
    return out_path


# --------------------------------------------------------------------------
# Compare
# --------------------------------------------------------------------------

REQUIRED_CSV_COLUMNS = ("segment", "domain", "protocol", "port", "status")


def _check_csv_columns(path, fieldnames):
    missing = [c for c in REQUIRED_CSV_COLUMNS if c not in (fieldnames or [])]
    if missing:
        sys.exit(f"ERROR: {os.path.abspath(path)} is not a results CSV from "
                 f"this tool — missing column(s): {', '.join(missing)}.")


# utf-8-sig on read so a CSV re-saved from Excel (which prepends a BOM)
# still parses; it also reads plain UTF-8 unchanged.
def load_csv(path):
    rows = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        rdr = csv.DictReader(f)
        _check_csv_columns(path, rdr.fieldnames)
        for r in rdr:
            rows[(r["segment"], r["domain"], r.get("probe_domain", ""),
                  r["protocol"], r["port"])] = r
    return rows


def load_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rdr = csv.DictReader(f)
        _check_csv_columns(path, rdr.fieldnames)
        return list(rdr)


def load_meta(csv_path):
    meta_path = re.sub(r"\.csv$", ".meta.json", csv_path)
    try:
        with open(meta_path, encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def diff_runs(pre, post):
    """Return (broken, fixed, changed) status transitions."""
    changed, fixed, broken = [], [], []
    for k in sorted(set(pre) | set(post)):
        p, q = pre.get(k), post.get(k)
        ps = p["status"] if p else "(absent)"
        qs = q["status"] if q else "(absent)"
        if ps == qs:
            continue
        entry = (k, ps, qs)
        if qs in OK_STATUSES:
            fixed.append(entry)
        elif ps in OK_STATUSES:
            broken.append(entry)
        else:
            changed.append(entry)
    return broken, fixed, changed


def run_compare(args):
    pre, post = load_csv(args.pre_csv), load_csv(args.post_csv)
    keys = set(pre) | set(post)
    broken, fixed, changed = diff_runs(pre, post)

    def show(title, entries):
        print(f"\n{title} ({len(entries)}):")
        for (seg, dom, probe, proto, port), ps, qs in entries:
            tgt = probe if probe and probe != dom else dom
            print(f"  {seg:<40} {tgt:<40} {proto}/{port:<6} {ps} -> {qs}")

    print(f"=== Compare: {os.path.basename(args.pre_csv)} vs "
          f"{os.path.basename(args.post_csv)} ===")
    pre_meta, post_meta = load_meta(args.pre_csv), load_meta(args.post_csv)
    if pre_meta and post_meta:
        print(f"  pre : {pre_meta.get('scope')} scope, "
              f"{pre_meta.get('started_utc')}, ZCC "
              f"{pre_meta.get('zcc', {}).get('state')}, "
              f"{pre_meta.get('zpa_evidence')}")
        print(f"  post: {post_meta.get('scope')} scope, "
              f"{post_meta.get('started_utc')}, ZCC "
              f"{post_meta.get('zcc', {}).get('state')}, "
              f"{post_meta.get('zpa_evidence')}")
        if pre_meta.get("scope") != post_meta.get("scope"):
            print("  [!] SCOPE MISMATCH — different entries were tested; "
                  "'(absent)' rows below are an artifact, not a regression.")
    print(f"  {len(keys)} unique (segment, entry, target, proto, port) "
          "tuples")
    if broken:
        show("BROKEN (was OPEN, now failing) — investigate first", broken)
    if fixed:
        show("NOW WORKING (was failing, now OPEN)", fixed)
    if changed:
        show("OTHER STATUS CHANGES", changed)
    if not (broken or fixed or changed):
        print("  No status changes between runs.")

    # ZPA interception delta — the key post-implementation signal
    pre_int = {k[1] for k, r in pre.items() if r["zpa_intercepted"] == "True"}
    post_int = {k[1] for k, r in post.items()
                if r["zpa_intercepted"] == "True"}
    newly, lost = post_int - pre_int, pre_int - post_int
    print("\nZPA interception (synthetic-IP) delta:")
    print(f"  newly intercepted domains: {len(newly)}")
    for d in sorted(newly):
        print(f"    + {d}")
    if lost:
        print(f"  no longer intercepted: {len(lost)}")
        for d in sorted(lost):
            print(f"    - {d}")

    # Latency delta — "is it slower now" is asked as often as "does it work",
    # and pre/post is the only pairing that can actually answer it.
    lat_pre = latency_stats(load_rows(args.pre_csv))
    lat_post = latency_stats(load_rows(args.post_csv))
    if lat_pre and lat_post:
        print("\nLatency (successful connects):")
        print(f"  {'':<8} {'median':>11} {'p95':>11} {'probes':>8}")
        print(f"  {'pre':<8} {lat_pre['median_ms']:>9.1f}ms "
              f"{lat_pre['p95_ms']:>9.1f}ms {lat_pre['count']:>8}")
        print(f"  {'post':<8} {lat_post['median_ms']:>9.1f}ms "
              f"{lat_post['p95_ms']:>9.1f}ms {lat_post['count']:>8}")
        d_med = lat_post["median_ms"] - lat_pre["median_ms"]
        d_p95 = lat_post["p95_ms"] - lat_pre["p95_ms"]
        print(f"  {'delta':<8} {d_med:>+9.1f}ms {d_p95:>+9.1f}ms")
        pct = (100.0 * d_med / lat_pre["median_ms"]
               if lat_pre["median_ms"] else 0.0)
        if abs(d_med) < 0.05 or abs(pct) < 1:
            print("  median is effectively unchanged post-ZPA")
        else:
            print(f"  median is {abs(pct):.0f}% "
                  f"{'slower' if d_med > 0 else 'faster'} post-ZPA")
        # A handful of probes cannot support a performance claim; say so
        # rather than let a 2-probe delta read as a finding.
        if min(lat_pre["count"], lat_post["count"]) < 30:
            print("  (few successful probes — treat this delta as "
                  "indicative only)")
    elif lat_post and not lat_pre:
        print("\nLatency: post-run only (no successful connects in the pre "
              "run to compare against)")

    if args.html:
        out = os.path.abspath(os.path.expanduser(args.html))
        write_html_report(
            out,
            [(args.pre_csv, load_rows(args.pre_csv), pre_meta),
             (args.post_csv, load_rows(args.post_csv), post_meta)],
            diff=(broken, fixed, changed, sorted(newly), sorted(lost)))
        print(f"\nHTML report: {out}")
    sys.exit(1 if broken else 0)


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

HTML_CSS = """
:root { color-scheme: light dark; --bg:#ffffff; --fg:#1a1a1a; --muted:#666;
  --line:#e3e3e3; --card:#f7f7f8; --ok:#1a7f45; --bad:#b3261e;
  --warn:#8a6100; --info:#1c5fa8; }
@media (prefers-color-scheme: dark) { :root { --bg:#15171a; --fg:#e8e8ea;
  --muted:#9aa0a6; --line:#2c2f34; --card:#1d2024; --ok:#5cc98b;
  --bad:#ff8a80; --warn:#e0b34d; --info:#7ab6f5; } }
* { box-sizing:border-box; }
body { margin:0; padding:2rem 1.25rem; background:var(--bg); color:var(--fg);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
  Helvetica,Arial,sans-serif; }
.wrap { max-width:1200px; margin:0 auto; }
h1 { font-size:1.5rem; margin:0 0 .25rem; }
h2 { font-size:1.1rem; margin:2rem 0 .6rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; font-size:.9rem; }
.tiles { display:grid; gap:.75rem;
  grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); margin:1rem 0; }
.tile { background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:.85rem 1rem; }
.tile .n { font-size:1.6rem; font-weight:650; letter-spacing:-.02em; }
.tile[data-tilefilter] { cursor:pointer; -webkit-user-select:none;
  user-select:none; transition:border-color .12s ease, transform .12s ease; }
.tile[data-tilefilter]:hover { border-color:var(--info); }
.tile[data-tilefilter]:focus-visible { outline:2px solid var(--info);
  outline-offset:2px; }
.tile[data-tilefilter].active { border-color:var(--info);
  box-shadow:inset 0 0 0 1px var(--info); }
.filterbar { display:flex; gap:.6rem; align-items:center; }
.filterbar button { font:inherit; font-size:.82rem; cursor:pointer;
  border:1px solid var(--line); background:var(--card); color:var(--fg);
  border-radius:6px; padding:.15rem .5rem; }
.filterbar button:hover { border-color:var(--info); }
td.statuscell { cursor:pointer; }
td.statuscell:hover { text-decoration:underline; }
.tile .l { color:var(--muted); font-size:.78rem; text-transform:uppercase;
  letter-spacing:.06em; margin-top:.15rem; }
.ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
.info{color:var(--info)}
.meta { background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:.85rem 1rem; font-size:.85rem;
  margin-bottom:1rem; }
.meta div { margin:.15rem 0; }
.scroll { overflow-x:auto; border:1px solid var(--line); border-radius:10px; }
table { border-collapse:collapse; width:100%; font-size:.83rem; }
th,td { text-align:left; padding:.45rem .65rem; border-bottom:1px solid
  var(--line); white-space:nowrap; }
th { background:var(--card); position:sticky; top:0; font-weight:600; }
tr:last-child td { border-bottom:none; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:.95em; }
input[type=search]{ width:100%; max-width:340px; padding:.45rem .6rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--fg); margin:.5rem 0; }
.note { color:var(--muted); font-size:.82rem; margin:.4rem 0 0; }
"""

HTML_JS = """
(function(){
  // Predicates mirror the Python that computed each tile's count, reading
  // the row's data-* attributes rather than its rendered text — a text
  // match on "OPEN" would also catch OPEN_FLAKY and any segment name
  // containing "open".
  function ok(s){ return s === 'OPEN' || s === 'OPEN_FLAKY'; }
  function tcp(d){ return d.proto === 'tcp' && d.status !== 'NO_TCP_PORTS'; }
  var PRED = {
    reachable: function(d){ return tcp(d) && ok(d.status); },
    failing:   function(d){ return tcp(d) && !ok(d.status); },
    flaky:     function(d){ return d.proto === 'tcp'
                                   && d.status === 'OPEN_FLAKY'; },
    dnsfail:   function(d){ return d.status.indexOf('DNS_FAIL') === 0; },
    steered:   function(d){ return d.steered === 'True'; }
  };
  var LABEL = {
    reachable: 'TCP reachable', failing: 'failing probes',
    flaky: 'flaky (retry only)', dnsfail: 'DNS failures',
    steered: 'ZPA-steered rows'
  };

  document.querySelectorAll('table[id]').forEach(function(table){
    var sel   = '#' + table.id;
    var tiles = document.querySelector('.tiles[data-target="' + sel + '"]');
    var box   = document.querySelector('input[data-filter="' + sel + '"]');
    var bar   = document.querySelector('.filterbar[data-for="' + sel + '"]');
    var rows  = Array.prototype.slice.call(
                  table.querySelectorAll('tbody tr'));
    var active = null;               // tile filter key, or a {status:...}

    function apply(){
      var q = (box && box.value ? box.value : '').toLowerCase();
      var shown = 0;
      rows.forEach(function(tr){
        var d = { status:  tr.getAttribute('data-status')  || '',
                  proto:   tr.getAttribute('data-proto')   || '',
                  steered: tr.getAttribute('data-steered') || '' };
        var pass = true;
        if (active && active.status !== undefined) {
          pass = d.status === active.status;
        } else if (active && PRED[active]) {
          pass = PRED[active](d);
        }
        if (pass && q) {
          pass = tr.textContent.toLowerCase().indexOf(q) > -1;
        }
        tr.style.display = pass ? '' : 'none';
        if (pass) { shown++; }
      });
      if (tiles) {
        tiles.querySelectorAll('[data-tilefilter]').forEach(function(t){
          t.classList.toggle('active',
            active === t.getAttribute('data-tilefilter'));
        });
      }
      if (bar) {
        if (active) {
          var name = (active.status !== undefined)
            ? 'status = ' + active.status
            : (LABEL[active] || active);
          bar.hidden = false;
          bar.innerHTML = '';
          bar.appendChild(document.createTextNode(
            'Filtered to ' + name + ' \\u2014 showing ' + shown +
            ' of ' + rows.length + ' rows. '));
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.textContent = 'Clear filter';
          btn.addEventListener('click', function(){ active = null; apply(); });
          bar.appendChild(btn);
        } else {
          bar.hidden = true;
          bar.textContent = '';
        }
      }
    }

    function toggle(key){
      var same = (typeof key === 'string')
        ? active === key
        : (active && active.status === key.status);
      active = same ? null : key;
      apply();
    }

    if (tiles) {
      tiles.querySelectorAll('[data-tilefilter]').forEach(function(t){
        var key = t.getAttribute('data-tilefilter');
        t.addEventListener('click', function(){ toggle(key); });
        t.addEventListener('keydown', function(e){
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault(); toggle(key);
          }
        });
      });
    }
    table.querySelectorAll('td.statuscell').forEach(function(td){
      td.addEventListener('click', function(){
        toggle({ status: td.getAttribute('data-statusval') || '' });
      });
    });
    if (box) { box.addEventListener('input', apply); }
  });
})();
"""


def _status_class(status):
    s = str(status)
    if s in OK_STATUSES:
        return "ok" if s == "OPEN" else "warn"
    if s.startswith(("DNS_FAIL", "ERROR", "PROBE_ERROR")) or s in ("TIMEOUT",):
        return "bad"
    if s in ("REFUSED",):
        return "warn"
    return "info"


def _tile(n, label, cls="", filt=None):
    """A stat tile; with filt it also becomes a one-click table filter.

    The counts were previously read-only, so narrowing to "just the
    failures" meant typing into the search box and hoping the substring did
    not also match a segment name.
    """
    attr = f' data-tilefilter="{html.escape(filt)}" tabindex="0"' if filt else ""
    title = ' title="Click to filter the table; click again to clear"' if filt \
        else ""
    return (f'<div class="tile"{attr}{title}>'
            f'<div class="n {cls}">{html.escape(str(n))}</div>'
            f'<div class="l">{html.escape(label)}</div></div>')


def write_html_report(out_path, runs, diff=None):
    """runs: list of (csv_path, rows, meta). diff: optional compare result."""
    parts = []
    parts.append('<div class="wrap">')
    parts.append("<h1>ZPA Application Segment Connectivity</h1>")
    parts.append(f'<p class="sub">Generated {html.escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))} '
                 f'&middot; script v{SCRIPT_VERSION}</p>')

    for csv_path, rows, meta in runs:
        tcp = [r for r in rows if r.get("protocol") == "tcp"
               and r.get("status") != "NO_TCP_PORTS"]
        open_ = [r for r in tcp if r.get("status") in OK_STATUSES]
        flaky = [r for r in tcp if r.get("status") == "OPEN_FLAKY"]
        dns_fail = [r for r in rows
                    if str(r.get("status", "")).startswith("DNS_FAIL")]
        interc = {r["domain"] for r in rows
                  if str(r.get("zpa_intercepted")) == "True"}
        fails = [r for r in tcp if r.get("status") not in OK_STATUSES]

        phase = (meta.get("phase") or "run").upper()
        parts.append(f"<h2>{html.escape(phase)} — "
                     f"{html.escape(os.path.basename(csv_path))}</h2>")
        if meta:
            zcc = meta.get("zcc", {})
            parts.append('<div class="meta">')
            for label, val in [
                ("Host", meta.get("hostname")),
                ("Started (UTC)", meta.get("started_utc")),
                ("Scope", meta.get("scope")),
                ("Segment source", meta.get("segment_source")),
                ("ZCC detection", f"{zcc.get('state')} "
                                  f"{', '.join(zcc.get('processes_found', []))}"),
                ("ZPA evidence", meta.get("zpa_evidence")),
                ("Interrupted", meta.get("interrupted")),
            ]:
                if val not in (None, ""):
                    parts.append(f"<div><b>{html.escape(label)}:</b> "
                                 f"{html.escape(str(val))}</div>")
            parts.append("</div>")

        if meta.get("verdict"):
            vcls = ("ok" if meta["verdict"] in ("ZPA IS STEERING",
                                                "BASELINE CAPTURED")
                    else "bad" if meta["verdict"] == "BASELINE INVALID"
                    else "warn")
            parts.append(
                f'<p class="sub"><b class="{vcls}">'
                f'{html.escape(meta["verdict"])}</b> &mdash; '
                f'{html.escape(str(meta.get("verdict_detail", "")))}</p>')

        # tid first: the tiles need to know which table they drive
        tid = "t" + re.sub(r"\W", "", os.path.basename(csv_path))[:20]

        parts.append(f'<div class="tiles" data-target="#{tid}">')
        parts.append(_tile(f"{len(open_)}/{len(tcp)}", "TCP reachable",
                           "ok" if len(open_) == len(tcp) and tcp else "warn",
                           filt="reachable"))
        parts.append(_tile(len(fails), "failing probes",
                           "bad" if fails else "ok", filt="failing"))
        parts.append(_tile(len(flaky), "flaky (retry only)",
                           "warn" if flaky else "", filt="flaky"))
        parts.append(_tile(len(dns_fail), "DNS failures",
                           "bad" if dns_fail else "ok", filt="dnsfail"))
        parts.append(_tile(len(interc), "ZPA-steered domains", "info",
                           filt="steered"))
        lat_m = (meta.get("latency") or {}).get("median_ms")
        if lat_m is not None:
            # a median is not a row set — deliberately not a filter
            parts.append(_tile(f"{lat_m}ms", "median latency", "info"))
        parts.append("</div>")

        parts.append(f'<input type="search" data-filter="#{tid}" '
                     f'placeholder="Filter rows...">')
        parts.append(f'<p class="note filterbar" data-for="#{tid}" '
                     f'hidden></p>')
        parts.append(f'<div class="scroll"><table id="{tid}"><thead><tr>')
        cols = ["segment", "entry_kind", "domain", "probe_domain",
                "resolved_ip", "zpa_intercepted", "protocol", "port",
                "status", "latency_ms", "l7_result"]
        for c in cols:
            parts.append(f"<th>{html.escape(c)}</th>")
        parts.append("</tr></thead><tbody>")
        for r in rows:
            # machine-readable row state so the tile predicates match the
            # Python that computed the counts, rather than re-deriving it
            # from the rendered text
            st = str(r.get("status", ""))
            parts.append(
                f'<tr data-status="{html.escape(st)}" '
                f'data-proto="{html.escape(str(r.get("protocol", "")))}" '
                f'data-steered="{html.escape(str(r.get("zpa_intercepted", "")))}">')
            for c in cols:
                v = r.get(c, "")
                if c == "status":
                    parts.append(f'<td class="{_status_class(v)} statuscell" '
                                 f'data-statusval="{html.escape(str(v))}" '
                                 f'title="Click to filter on this status">'
                                 f'{html.escape(str(v))}</td>')
                else:
                    parts.append(f"<td>{html.escape(str(v))}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table></div>")

    if diff:
        broken, fixed, changed, newly, lost = diff
        parts.append("<h2>Pre &rarr; Post changes</h2>")
        parts.append('<div class="tiles">')
        parts.append(_tile(len(broken), "regressions",
                           "bad" if broken else "ok"))
        parts.append(_tile(len(fixed), "now working", "ok"))
        parts.append(_tile(len(changed), "other changes", "info"))
        parts.append(_tile(len(newly), "newly ZPA-steered", "info"))
        parts.append("</div>")
        if newly:
            parts.append("<p class=note><b>Newly ZPA-steered domains:</b> "
                         + html.escape(", ".join(newly)) + "</p>")
        if lost:
            parts.append("<p class=note><b>No longer steered:</b> "
                         + html.escape(", ".join(lost)) + "</p>")
        parts.append('<div class="scroll"><table><thead><tr>'
                     "<th>change</th><th>segment</th><th>target</th>"
                     "<th>proto/port</th><th>pre</th><th>post</th>"
                     "</tr></thead><tbody>")
        for label, cls, entries in (("REGRESSION", "bad", broken),
                                    ("FIXED", "ok", fixed),
                                    ("CHANGED", "info", changed)):
            for (seg, dom, probe, proto, port), ps, qs in entries:
                tgt = probe if probe and probe != dom else dom
                parts.append(
                    f'<tr><td class="{cls}">{label}</td>'
                    f"<td>{html.escape(seg)}</td>"
                    f"<td>{html.escape(tgt)}</td>"
                    f"<td>{html.escape(proto)}/{html.escape(str(port))}</td>"
                    f"<td>{html.escape(ps)}</td>"
                    f"<td>{html.escape(qs)}</td></tr>")
        parts.append("</tbody></table></div>")

    parts.append('<p class="note">Contains internal hostnames and addresses '
                 "&mdash; handle as confidential.</p>")
    parts.append("</div>")

    doc = ("<!doctype html><html><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'>"
           "<title>ZPA Connectivity Report</title>"
           f"<style>{HTML_CSS}</style></head><body>"
           + "".join(parts)
           + f"<script>{HTML_JS}</script></body></html>")
    out_path = os.path.abspath(os.path.expanduser(out_path))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def run_report(args):
    runs = []
    for p in args.csv_files:
        runs.append((p, load_rows(p), load_meta(p)))
    diff = None
    if len(args.csv_files) == 2:
        pre, post = load_csv(args.csv_files[0]), load_csv(args.csv_files[1])
        broken, fixed, changed = diff_runs(pre, post)
        pre_int = {k[1] for k, r in pre.items()
                   if r["zpa_intercepted"] == "True"}
        post_int = {k[1] for k, r in post.items()
                    if r["zpa_intercepted"] == "True"}
        diff = (broken, fixed, changed,
                sorted(post_int - pre_int), sorted(pre_int - post_int))
    out = write_html_report(args.out, runs, diff=diff)
    print(f"HTML report: {out}")
    return out


def run_preflight(args):
    ok, checks = preflight_checks(
        args, need_api=not args.targets_file,
        need_targets_file=args.targets_file)
    print_checks(checks)
    print("Preflight " + ("PASSED" if ok else "FAILED"))
    sys.exit(0 if ok else 1)


# --------------------------------------------------------------------------
# SIPA source-IP anchoring verification
# --------------------------------------------------------------------------
#
# A TCP connect proves reachability but NOT that Source IP Anchoring put the
# expected source IP on the wire — anchoring happens in the Zscaler cloud,
# invisible to local sockets. The one thing an endpoint CAN observe is the
# public source IP a destination *sees*. So this mode fetches a source-IP
# "reflector" (an HTTP endpoint that echoes the caller's IP) and compares the
# observed egress IP against the anchor the admin configured.
#
# CRITICAL: the reflection only travels the anchored path if the reflector's
# FQDN is enrolled in the SIPA segment. If it is not, the request egresses via
# the normal path and reports the wrong IP. This mode checks enrollment against
# the segment inventory and warns when a reflector host is not found in any
# SIPA segment, and a --baseline-reflector (deliberately NOT anchored) gives a
# contrast IP so "observed == baseline" flags an un-anchored result outright.

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return s
    except (ValueError, TypeError):
        return None


def http_get_text(url, ctx, timeout):
    """GET a URL and return (body_text, error)."""
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "*/*", "User-Agent": "zpa-sipa-verify"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(65536).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, str(e.reason)
    except (OSError, ssl.SSLError, ValueError) as e:
        return None, str(e)


def extract_ip(text):
    """Pull the caller's public IP from a reflector response.

    Handles plain-text bodies (api.ipify.org, checkip.amazonaws.com) and
    JSON shapes ({"ip":...} / {"origin":...} / {"query":...}). IPv4 only —
    SIPA anchors are IPv4 and this homelab/tenant context is IPv4-only.
    """
    if not text:
        return None
    t = text.strip()
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            for k in ("ip", "origin", "query", "client_ip", "address"):
                v = obj.get(k)
                if isinstance(v, str):
                    m = _IPV4_RE.search(v)
                    if m:
                        return _valid_ip(m.group(0))
    except (ValueError, TypeError):
        pass
    m = _IPV4_RE.search(t)
    return _valid_ip(m.group(0)) if m else None


def anchor_match(ip, expected):
    """True if ip falls within any expected IP or CIDR string."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    for e in expected:
        e = str(e).strip()
        try:
            if "/" in e:
                if addr in ipaddress.ip_network(e, strict=False):
                    return True
            elif addr == ipaddress.ip_address(e):
                return True
        except ValueError:
            continue
    return False


SIPA_CSV_FIELDS = ["reflector", "reflector_host", "sipa_segment",
                   "expected_anchor", "observed_ip", "baseline_ip",
                   "verdict", "detail"]


def _sipa_domain_index(segments):
    """Map SIPA-segment domain (wildcard/host, lowercased) -> segment name."""
    idx = {}
    for s in segments:
        if not s.get("ipAnchored"):
            continue
        for d in s.get("domainNames") or []:
            key = d.strip().lower().lstrip("*.")
            if key:
                idx[key] = s.get("name", "")
    return idx


def _enrolled_segment(host, sipa_index):
    """Return the SIPA segment a reflector host belongs to, matching exact
    host and any parent domain (for wildcard SIPA segments)."""
    host = (host or "").lower()
    if host in sipa_index:
        return sipa_index[host]
    parts = host.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in sipa_index:
            return sipa_index[parent]
    return ""


def run_verify_sipa(args):
    if not args.reflector:
        sys.exit("ERROR: at least one --reflector URL is required — a source-"
                 "IP echo endpoint enrolled in the SIPA segment. Prefer an "
                 "internal/customer-hosted reflector; a third-party echo sends "
                 "your anchor IP off-network. See --help for examples.")

    ctx = build_ssl_context(args)
    global_expected = list(args.expected_anchor or [])
    anchor_map = {}
    if args.anchor_map:
        with open(args.anchor_map, encoding="utf-8-sig") as f:
            anchor_map = json.load(f)

    # Enrollment hints from a frozen inventory (credential-free; no API auth
    # in verify mode — export-targets first if you want live inventory).
    sipa_index = {}
    if args.targets_file:
        segs, _ = load_segments(args)
        sipa_index = _sipa_domain_index(segs)
        print(f"[*] {len(set(sipa_index.values()))} SIPA (ipAnchored) "
              f"segments in inventory")
    else:
        print("[!] No --targets-file — cannot confirm reflector enrollment in "
              "a SIPA segment (results still valid if you know it is enrolled)")

    baseline_ip = ""
    if args.baseline_reflector:
        txt, err = http_get_text(args.baseline_reflector, ctx, args.timeout)
        baseline_ip = extract_ip(txt) or ""
        print(f"[*] Baseline (un-anchored) egress IP: "
              f"{baseline_ip or ('UNREACHABLE (' + str(err) + ')')}")

    rows = []
    for url in args.reflector:
        host = urllib.parse.urlsplit(url).hostname or ""
        seg = _enrolled_segment(host, sipa_index)
        exp = []
        for key in (url, host):
            if key in anchor_map:
                v = anchor_map[key]
                exp = v if isinstance(v, list) else [v]
                break
        if not exp:
            exp = global_expected

        txt, err = http_get_text(url, ctx, args.timeout)
        observed = extract_ip(txt) if txt else None

        if observed is None:
            verdict, detail = "UNREACHABLE", (err or "no IP in response")
        elif not exp:
            verdict, detail = "UNVERIFIED", "no expected anchor provided"
        elif anchor_match(observed, exp):
            verdict, detail = "ANCHORED", "observed egress IP matches expected anchor"
        else:
            verdict = "MISMATCH"
            if baseline_ip and observed == baseline_ip:
                detail = ("observed == un-anchored baseline — traffic is NOT "
                          "being anchored (reflector likely not routed via SIPA)")
            else:
                detail = "observed egress IP is outside the expected anchor"

        if args.targets_file:
            if seg:
                detail += f"; reflector enrolled in SIPA segment '{seg}'"
            else:
                detail += ("; WARNING reflector host not in any SIPA segment "
                           "— it may egress un-anchored, making this result "
                           "meaningless")
        rows.append({
            "reflector": url, "reflector_host": host, "sipa_segment": seg,
            # anchor-map values may be numbers or nested lists in a
            # hand-written file; join defensively rather than TypeError
            "expected_anchor": ",".join(str(x) for x in exp),
            "observed_ip": observed or "",
            "baseline_ip": baseline_ip, "verdict": verdict, "detail": detail,
        })

    out_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hostn = "".join(ch if ch.isalnum() or ch in "-_" else "-"
                    for ch in socket.gethostname().split(".")[0])
    stem = f"sipa-verify_{hostn}_{ts}"
    out_path = os.path.join(out_dir, stem + ".csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SIPA_CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    meta = {
        "script_version": SCRIPT_VERSION, "mode": "sipa-verify",
        "hostname": socket.gethostname(),
        "run_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "baseline_ip": baseline_ip, "zcc": detect_zcc(),
        "reflectors": len(rows), "counts": counts,
    }
    with open(os.path.join(out_dir, stem + ".meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"\n=== SIPA source-IP anchoring verification ({hostn}, {ts}) ===")
    if baseline_ip:
        print(f"  Un-anchored baseline egress: {baseline_ip}")
    for r in rows:
        print(f"  [{r['verdict']:<10}] {r['reflector_host'] or r['reflector']}"
              f"  observed={r['observed_ip'] or '-'}"
              f"  expected={r['expected_anchor'] or '-'}")
        print(f"               {r['detail']}")
    print(f"  Results CSV: {out_path}")
    bad = sum(1 for r in rows if r["verdict"] in ("MISMATCH", "UNREACHABLE"))
    sys.exit(1 if bad else 0)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def add_api_args(p):
    p.add_argument("--tenant", metavar="NAME",
                   help="use a saved tenant (see the 'tenants' subcommand). "
                        "Without it, saved tenants are offered interactively; "
                        "selection is confirmed twice")
    p.add_argument("--client-id", help="OneAPI client ID "
                   "(or env ZSCALER_CLIENT_ID)")
    p.add_argument("--vanity-domain", help="Zidentity vanity domain "
                   "(or env ZSCALER_VANITY_DOMAIN)")
    p.add_argument("--customer-id", help="ZPA customer ID "
                   "(or env ZPA_CUSTOMER_ID)")
    p.add_argument("--api-base", default=DEFAULT_API_BASE,
                   help=f"OneAPI base URL (default {DEFAULT_API_BASE}; "
                        "non-production commercial clouds use "
                        "https://api.<cloud>.zsapi.net, gov uses "
                        "https://api.zscalergov.net/.us)")
    p.add_argument("--microtenant-id", metavar="ID",
                   help="fetch segments belonging to this microtenant; "
                        "without it, microtenant segments are not returned")
    p.add_argument("--ca-bundle", metavar="PEM",
                   help="corporate root CA bundle for TLS-inspected egress")
    p.add_argument("--insecure", action="store_true",
                   help="disable TLS verification for API calls (last resort)")


def main():
    # Windows consoles/redirects can default to a legacy code page; force
    # UTF-8 so the report text never dies on an encoding error.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="ZPA application segment connectivity tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run '<subcommand> --help' for per-command options.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # -- preflight ---------------------------------------------------------
    pf = sub.add_parser("preflight",
                        help="environment + ZCC readiness check, no probing")
    pf.add_argument("--targets-file", metavar="JSON",
                    help="check this frozen inventory instead of API creds")
    pf.add_argument("--output-dir", default="zpa-test-results")
    add_api_args(pf)
    pf.set_defaults(func=run_preflight)

    # -- tenants -----------------------------------------------------------
    tn = sub.add_parser(
        "tenants",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="save and select ZPA tenants (e.g. model and production)",
        epilog="Saves the OneAPI values per tenant so a pilot spanning a "
               "model and a production tenant does not mean retyping four "
               "values per run.\n\n"
               "The store lives at ~/.zpa-connectivity-tester/tenants.json "
               "(mode 0600; override with $ZPA_TENANT_STORE).\n"
               "The client secret is only written if you opt in — by default "
               "it is prompted each run and never touches disk.\n\n"
               "  tenants add [name]     save a tenant interactively\n"
               "  tenants list           show saved tenants\n"
               "  tenants remove NAME    delete one\n\n"
               "Selecting a tenant for a run is confirmed twice, and the "
               "second confirmation requires typing the tenant name.")
    tn.add_argument("action", choices=["add", "list", "remove"])
    tn.add_argument("name", nargs="?", help="tenant name (add/remove)")
    tn.add_argument("--force", action="store_true",
                    help="overwrite an existing tenant of the same name")
    tn.set_defaults(func=run_tenants)

    # -- export-targets ----------------------------------------------------
    ex = sub.add_parser("export-targets",
                        help="fetch the segment inventory to a JSON file")
    ex.add_argument("--out", default="zpa-targets.json",
                    help="output JSON path (default zpa-targets.json)")
    add_api_args(ex)
    ex.set_defaults(func=run_export_targets)

    # -- test --------------------------------------------------------------
    t = sub.add_parser("test", help="probe segment connectivity, write CSV")
    t.add_argument("--phase", choices=["pre", "post"], required=True,
                   help="label for this run (used in the output filename)")
    t.add_argument("--scope", choices=["full", "sample"],
                   help="full = exhaustive test of every entry/CIDR host/"
                        "port; sample = representative subset. Prompted "
                        "interactively if omitted.")
    t.add_argument("--targets-file", metavar="JSON",
                   help="use a frozen inventory from export-targets instead "
                        "of the live API (no credentials required)")
    t.add_argument("--sample-domains", type=int, default=3, metavar="N",
                   help="[sample scope] fqdn/ip entries tested per segment "
                        "(default 3)")
    t.add_argument("--cidr-hosts", type=int, default=5, metavar="N",
                   help="[sample scope] hosts probed per CIDR entry, spread "
                        "across the range (default 5)")
    t.add_argument("--max-ports", type=int, default=10,
                   help="[sample scope] max TCP ports probed per segment "
                        "(default 10; range endpoints are kept first)")
    t.add_argument("--retries", type=int, default=1, metavar="N",
                   help="retries on transient failure (default 1); a port "
                        "that only opens on retry is flagged OPEN_FLAKY")
    t.add_argument("--flush-dns", action="store_true",
                   help="flush the OS resolver cache before probing — "
                        "recommended for post runs, since negative entries "
                        "cached during the pre run can mask ZPA steering "
                        "(macOS needs sudo)")
    t.add_argument("--l7", action="store_true",
                   help="on OPEN ports, verify an app actually responds "
                        "(TLS handshake or HTTP status), not just TCP")
    t.add_argument("--sipa-only", action="store_true",
                   help="only test Source IP Anchoring segments "
                        "(ipAnchored=true) — typical for --phase pre")
    t.add_argument("--enabled-only", action="store_true",
                   help="skip disabled segments")
    t.add_argument("--segment", metavar="SUBSTR",
                   help="only segments whose name contains SUBSTR")
    t.add_argument("--timeout", type=float, default=5.0,
                   help="per-probe timeout seconds (default 5)")
    t.add_argument("--workers", type=int, default=20,
                   help="concurrent probe workers (default 20; keep under "
                        "~200 on macOS, FD limit is 256)")
    t.add_argument("--wildcard-probe", metavar="LABEL",
                   help="substitute LABEL for '*' in wildcard domains "
                        "instead of skipping them")
    t.add_argument("--output-dir", default="zpa-test-results",
                   help="directory for result CSVs")
    t.add_argument("--report", action="store_true",
                   help="also write a self-contained HTML report")
    t.add_argument("--show-failures", action="store_true", default=True,
                   help="list failing probes in console output (default on)")
    t.add_argument("--no-show-failures", dest="show_failures",
                   action="store_false",
                   help="suppress the per-failure console listing (the CSV "
                        "still records every probe)")
    t.add_argument("--yes", action="store_true",
                   help="skip preflight and probe-count confirmations")
    t.add_argument("--force-huge-run", action="store_true",
                   help="override the safety ceiling that refuses runs which "
                        "cannot realistically finish (a full-scope run over "
                        "wide CIDRs and full port ranges can plan billions of "
                        "probes and amounts to a port sweep)")
    add_api_args(t)
    t.set_defaults(func=run_test)

    # -- sipa-verify -------------------------------------------------------
    sv = sub.add_parser(
        "sipa-verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="verify SIPA source-IP anchoring via egress-IP reflection",
        epilog="A TCP connect cannot prove Source IP Anchoring; this checks "
               "the public source IP a destination actually sees. Point "
               "--reflector at a source-IP echo endpoint that is ENROLLED in "
               "the SIPA segment (so it routes the anchored path), give the "
               "--expected-anchor the admin configured, and add a "
               "--baseline-reflector (not in ZPA) for contrast.\n\n"
               "Example:\n"
               "  sipa-verify \\\n"
               "    --targets-file zpa-targets.json \\\n"
               "    --reflector https://ipcheck.corp.example/ip \\\n"
               "    --expected-anchor 198.51.100.0/24 \\\n"
               "    --baseline-reflector https://api.ipify.org")
    sv.add_argument("--reflector", action="append", metavar="URL",
                    help="source-IP echo endpoint enrolled in a SIPA segment "
                         "(repeatable). Prefer an internal reflector — a "
                         "third-party echo sends your anchor IP off-network.")
    sv.add_argument("--expected-anchor", action="append", metavar="IP_OR_CIDR",
                    help="expected anchored egress IP or CIDR (repeatable)")
    sv.add_argument("--anchor-map", metavar="JSON",
                    help="JSON mapping reflector URL or host -> expected "
                         "anchor IP/CIDR (string or list); overrides "
                         "--expected-anchor per reflector")
    sv.add_argument("--baseline-reflector", metavar="URL",
                    help="a reflector NOT in any ZPA segment, to capture the "
                         "un-anchored egress IP; 'observed == baseline' then "
                         "proves traffic is not being anchored")
    sv.add_argument("--targets-file", metavar="JSON",
                    help="frozen inventory (export-targets) used to confirm "
                         "each reflector host is enrolled in a SIPA segment")
    sv.add_argument("--timeout", type=float, default=8.0,
                    help="per-request timeout seconds (default 8)")
    sv.add_argument("--output-dir", default="zpa-test-results",
                    help="directory for the results CSV")
    sv.add_argument("--ca-bundle", metavar="PEM",
                    help="corporate root CA bundle for TLS-inspected egress")
    sv.add_argument("--insecure", action="store_true",
                    help="disable TLS verification for reflector calls")
    sv.set_defaults(func=run_verify_sipa)

    # -- compare -----------------------------------------------------------
    c = sub.add_parser("compare", help="diff a pre CSV against a post CSV")
    c.add_argument("pre_csv")
    c.add_argument("post_csv")
    c.add_argument("--html", metavar="OUT.html",
                   help="also write a self-contained HTML report")
    c.set_defaults(func=run_compare)

    # -- report ------------------------------------------------------------
    r = sub.add_parser("report",
                       help="build an HTML report from one or more CSVs")
    r.add_argument("--out", default="zpa-report.html",
                   help="output HTML path (default zpa-report.html)")
    r.add_argument("csv_files", nargs="+",
                   help="one CSV, or exactly two (pre post) to include a "
                        "change summary")
    r.set_defaults(func=run_report)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
