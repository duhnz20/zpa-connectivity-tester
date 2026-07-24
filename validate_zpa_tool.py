#!/usr/bin/env python3
"""Validation suite for zpa_segment_connectivity.py.

Runs everything that can be verified WITHOUT a live ZPA tenant: parsing,
scope/sampling maths, probe semantics, CSV/metadata/HTML output, and the
compare/report subcommands. Intended to be run on the actual endpoint OS
so Python-version and platform behaviour are covered too.

Usage:  python3 validate_zpa_tool.py [path_to_zpa_segment_connectivity.py]
"""

import csv
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

PASS, FAIL = [], []

# The tool does this inside main(); the suite imports the module instead of
# invoking it, so it must reconfigure its own console. Without this, printing
# a non-ASCII segment name dies on a cp1252 Windows console — the assertion
# passes and the reporting of it is what crashes.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))
    return cond


def load(path):
    spec = importlib.util.spec_from_file_location("zpatool", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Args:
    """Minimal args object matching what the tool's functions expect."""
    def __init__(self, **kw):
        defaults = dict(
            scope_resolved="sample", phase="pre", sample_domains=3,
            cidr_hosts=5, max_ports=10, sipa_only=False, enabled_only=False,
            segment=None, wildcard_probe=None, timeout=2.0, workers=8,
            output_dir="out", show_failures=False, yes=True, insecure=False,
            ca_bundle=None, client_id=None, vanity_domain=None,
            customer_id=None, api_base="https://api.zsapi.net",
            targets_file=None, retries=0, l7=False, flush_dns=False,
            report=False, microtenant_id=None)
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)


SEGMENTS = [
    {"name": "Obj-Port-Form", "id": "1", "enabled": True, "ipAnchored": True,
     "domainNames": ["a.corp.local", "b.corp.local", "c.corp.local",
                     "d.corp.local"],
     "tcpPortRange": [{"from": "443", "to": "443"},
                      {"from": "8000", "to": "8100"}],
     "udpPortRange": [{"from": "53", "to": "53"}]},
    {"name": "Flat-Port-Form", "id": "2", "enabled": True, "ipAnchored": False,
     "domainNames": ["10.20.0.0/24", "10.30.1.5", "*.wild.corp"],
     "tcpPortRanges": ["443", "443", "8080", "8090"]},
    {"name": "Disabled-Seg", "id": "3", "enabled": False, "ipAnchored": False,
     "domainNames": ["off.corp.local"],
     "tcpPortRange": [{"from": "80", "to": "80"}]},
]


def main():
    tool_path = (sys.argv[1] if len(sys.argv) > 1
                 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "zpa_segment_connectivity.py"))
    m = load(tool_path)
    print(f"\nValidating {tool_path}")
    print(f"Python {platform.python_version()} on {platform.system()} "
          f"{platform.release()}\n")

    # ---------------------------------------------------------------- parsing
    print("Entry classification")
    check("fqdn", m.classify_entry("app.corp.local") == "fqdn")
    check("bare ip", m.classify_entry("10.1.2.3") == "ip")
    check("cidr", m.classify_entry("10.1.0.0/24") == "cidr")
    check("wildcard", m.classify_entry("*.corp.local") == "wildcard")
    check("bad cidr falls back to fqdn",
          m.classify_entry("not/a/cidr") == "fqdn")

    print("\nPort shapes (the dual-form trap)")
    obj = {"tcpPortRange": [{"from": "443", "to": "443"}]}
    flat = {"tcpPortRanges": ["443", "443", "8080", "8090"]}
    both = {"tcpPortRange": [{"from": "443", "to": "443"}],
            "tcpPortRanges": ["443", "443", "22", "22"]}
    check("object form", m.port_ranges(obj, "tcpPortRange") == [(443, 443)])
    check("flat form", m.port_ranges(flat, "tcpPortRange")
          == [(443, 443), (8080, 8090)])
    check("union + dedupe", m.port_ranges(both, "tcpPortRange")
          == [(443, 443), (22, 22)])
    check("odd-length flat ignored",
          m.port_ranges({"tcpPortRanges": ["80", "80", "999"]},
                        "tcpPortRange") == [(80, 80)])
    check("malformed ignored",
          m.port_ranges({"tcpPortRange": [{"from": "x", "to": "y"}, "junk"]},
                        "tcpPortRange") == [])
    check("out-of-range rejected",
          m.port_ranges({"tcpPortRanges": ["0", "70000"]},
                        "tcpPortRange") == [])
    check("udp uses same logic",
          m.port_ranges({"udpPortRanges": ["53", "53"]},
                        "udpPortRange") == [(53, 53)])

    print("\nCIDR expansion")
    h, t = m.cidr_hosts("10.1.0.0/24", "sample", 5)
    check("/24 sample = 5 spread hosts, first/last usable",
          h[0] == "10.1.0.1" and h[-1] == "10.1.0.254" and len(h) == 5, str(h))
    h, _ = m.cidr_hosts("192.168.1.0/29", "full", 5)
    check("/29 full = 6 usable (no network/broadcast)",
          h == ["192.168.1.%d" % i for i in range(1, 7)])
    h, _ = m.cidr_hosts("10.9.9.9/32", "sample", 5)
    check("/32 = single host", h == ["10.9.9.9"])
    h, _ = m.cidr_hosts("10.9.9.8/31", "sample", 5)
    check("/31 = both addresses", len(h) == 2)
    h, t = m.cidr_hosts("10.0.0.0/15", "full", 5)
    check("/15 full capped at FULL_CIDR_HOST_CAP",
          len(h) == m.FULL_CIDR_HOST_CAP and t > 0, f"truncated={t}")
    # regression: the spread formula divides by (n-1), so n==1 used to raise
    # ZeroDivisionError — --cidr-hosts 1 is a legitimate setting
    h, _ = m.cidr_hosts("10.1.0.0/24", "sample", 1)
    check("--cidr-hosts 1 yields one host (no ZeroDivisionError)",
          h == ["10.1.0.1"], str(h))
    h, _ = m.cidr_hosts("10.1.0.0/24", "sample", 0)
    check("--cidr-hosts 0 yields nothing rather than crashing", h == [])

    print("\nPort expansion / sampling")
    p, t = m.expand_ports([(443, 443), (8000, 8100)], 10)
    check("cap keeps range endpoints first",
          443 in p and 8000 in p and 8100 in p and len(p) == 10 and t > 0)
    p, t = m.expand_ports([(1, 65535)], None)
    check("full scope expands everything", len(p) == 65535 and t == 0)
    # regression: a wide range must not consume the cap and drop a
    # separately-defined single port from a LATER range
    p, t = m.expand_ports([(1, 1000), (443, 443)], 10)
    check("cap keeps endpoints of every range, not just the first",
          443 in p and 1 in p and 1000 in p and len(p) == 10, str(p))
    p, t = m.expand_ports([(80, 80), (443, 443), (8080, 8080)], 2)
    check("cap truncation is counted", len(p) == 2 and t == 1, f"trunc={t}")
    check("spread_sample keeps first+last",
          m.spread_sample(list(range(10)), 3)[0] == 0
          and m.spread_sample(list(range(10)), 3)[-1] == 9)
    check("spread_sample no-op when n>=len",
          m.spread_sample([1, 2], 5) == [1, 2])

    # ------------------------------------------------------------ target build
    print("\nTarget building / filters")
    tg, wild, st = m.build_targets(SEGMENTS, Args(scope_resolved="sample",
                                                  sample_domains=2,
                                                  cidr_hosts=3))
    kinds = [x["kind"] for x in tg]
    check("wildcard skipped when no --wildcard-probe",
          wild == [("Flat-Port-Form", "*.wild.corp")])
    check("cidr sampled to 3 hosts", kinds.count("cidr") == 3)
    check("fqdn entries sampled down", st["entries_sampled_out"] == 2)
    check("flat-form segment got ports",
          any(x["segment"] == "Flat-Port-Form" and x["ports"] for x in tg))

    tg2, _, _ = m.build_targets(SEGMENTS, Args(scope_resolved="full"))
    # 4 from Obj-Port-Form + 1 from Disabled-Seg (no --enabled-only here)
    check("full scope keeps all fqdn",
          sum(1 for x in tg2 if x["kind"] == "fqdn") == 5)
    check("full scope expands /24 to 254",
          sum(1 for x in tg2 if x["kind"] == "cidr") == 254)

    tg3, _, st3 = m.build_targets(SEGMENTS, Args(sipa_only=True))
    check("--sipa-only filters to ipAnchored", st3["segments_matched"] == 1)
    tg4, _, st4 = m.build_targets(SEGMENTS, Args(enabled_only=True))
    check("--enabled-only drops disabled", st4["segments_matched"] == 2)
    tg5, _, st5 = m.build_targets(SEGMENTS, Args(segment="flat"))
    check("--segment substring filter", st5["segments_matched"] == 1)
    tg6, wild6, _ = m.build_targets(SEGMENTS, Args(wildcard_probe="www"))
    check("--wildcard-probe substitutes label",
          not wild6 and any(x["probe_domain"] == "www.wild.corp"
                            for x in tg6))

    print("\nMalformed-input tolerance")
    # regression: a hand-written or partial targets file may omit 'name',
    # which used to raise KeyError and kill the whole run
    tg7, _, st7 = m.build_targets(
        [{"id": "77", "domainNames": ["a.corp"], "tcpPortRanges": ["443", "443"]},
         "not-a-dict",
         {"name": None, "domainNames": ["b.corp"]}], Args())
    check("segment without 'name' does not raise",
          st7["segments_matched"] == 2, f"matched={st7['segments_matched']}")
    check("unnamed segment gets a placeholder label",
          any("unnamed" in x["segment"] for x in tg7),
          str({x["segment"] for x in tg7}))
    check("non-dict entry in segment list is skipped",
          all(isinstance(x["segment"], str) for x in tg7))
    # --segment filter must still work when a name is missing
    _, _, st8 = m.build_targets(
        [{"id": "9", "domainNames": ["a.corp"]}], Args(segment="nomatch"))
    check("--segment filter tolerates missing name",
          st8["segments_matched"] == 0)

    # ------------------------------------------------------------ probe layer
    print("\nSIPA anchoring verification")
    # extract_ip across reflector response shapes
    check("extract_ip plain text", m.extract_ip("198.51.100.7\n") == "198.51.100.7")
    check("extract_ip ipify json", m.extract_ip('{"ip":"198.51.100.7"}') == "198.51.100.7")
    check("extract_ip httpbin origin", m.extract_ip('{"origin":"198.51.100.7"}') == "198.51.100.7")
    check("extract_ip junk -> None", m.extract_ip("no address here") is None)
    check("extract_ip rejects bad octets", m.extract_ip("999.1.1.1") is None)
    # anchor_match on IP and CIDR
    check("anchor_match exact ip", m.anchor_match("198.51.100.7", ["198.51.100.7"]))
    check("anchor_match cidr", m.anchor_match("198.51.100.7", ["198.51.100.0/24"]))
    check("anchor_match outside cidr", not m.anchor_match("203.0.113.5", ["198.51.100.0/24"]))
    check("anchor_match bad ip", not m.anchor_match("nope", ["198.51.100.0/24"]))
    # enrollment index + parent-domain (wildcard) matching
    segs_sipa = [{"name":"SIPA-SaaS","ipAnchored":True,
                  "domainNames":["ipcheck.corp.example","*.saas.example"]},
                 {"name":"Plain","ipAnchored":False,"domainNames":["x.corp"]}]
    idx = m._sipa_domain_index(segs_sipa)
    check("sipa index excludes non-SIPA", "x.corp" not in idx)
    check("enrolled exact host", m._enrolled_segment("ipcheck.corp.example", idx) == "SIPA-SaaS")
    check("enrolled via wildcard parent", m._enrolled_segment("app.saas.example", idx) == "SIPA-SaaS")
    check("not enrolled", m._enrolled_segment("random.other", idx) == "")
    # end-to-end run_verify_sipa with fetch monkeypatched
    _orig = m.http_get_text
    def fake_fetch(url, ctx, timeout):
        table = {"https://ipcheck.corp.example/ip": ('{"ip":"198.51.100.7"}', None),
                 "https://wrong.corp.example/ip": ("203.0.113.9", None),
                 "https://api.ipify.org": ("203.0.113.9", None)}
        return table.get(url, (None, "unreachable"))
    m.http_get_text = fake_fetch
    try:
        tf2 = os.path.join(tempfile.gettempdir(), "sipa-targets.json")
        with open(tf2, "w") as f:
            json.dump({"segments": segs_sipa}, f)
        outd = tempfile.mkdtemp(prefix="sipa-")
        sa = Args(reflector=["https://ipcheck.corp.example/ip"],
                  expected_anchor=["198.51.100.0/24"], anchor_map=None,
                  baseline_reflector="https://api.ipify.org",
                  targets_file=tf2, output_dir=outd)
        try:
            m.run_verify_sipa(sa)
        except SystemExit as e:
            check("anchored run exits 0", e.code == 0, f"exit={e.code}")
        rows = list(csv.DictReader(open(sorted(
            [os.path.join(outd, x) for x in os.listdir(outd) if x.endswith(".csv")])[0])))
        check("verdict ANCHORED", rows[0]["verdict"] == "ANCHORED", rows[0]["verdict"])
        check("records enrolled segment", rows[0]["sipa_segment"] == "SIPA-SaaS")
        # mismatch case: observed == baseline -> flagged un-anchored, exit 1
        sa2 = Args(reflector=["https://wrong.corp.example/ip"],
                   expected_anchor=["198.51.100.0/24"], anchor_map=None,
                   baseline_reflector="https://api.ipify.org",
                   targets_file=tf2, output_dir=outd)
        try:
            m.run_verify_sipa(sa2)
        except SystemExit as e:
            check("mismatch run exits 1", e.code == 1, f"exit={e.code}")
        rows2 = list(csv.DictReader(open(sorted(
            [os.path.join(outd, x) for x in os.listdir(outd) if x.endswith(".csv")],
            key=lambda p: os.path.getmtime(p))[-1])))
        check("verdict MISMATCH on wrong egress", rows2[0]["verdict"] == "MISMATCH", rows2[0]["verdict"])
        check("mismatch detail flags baseline match",
              "NOT being anchored" in rows2[0]["detail"], rows2[0]["detail"][:40])
    finally:
        m.http_get_text = _orig

    print("\nTargets-file shapes")
    _tdir = tempfile.mkdtemp(prefix="zpa-targets-")
    try:
        seg_min = [{"name": "Bare", "domainNames": ["a.corp"],
                    "tcpPortRanges": ["443", "443"]}]
        # regression: a bare JSON array is an advertised shape, but .get()
        # was called on it before the type was tested -> AttributeError
        p_list = os.path.join(_tdir, "bare.json")
        with open(p_list, "w", encoding="utf-8") as f:
            json.dump(seg_min, f)
        segs, src = m.load_segments(Args(targets_file=p_list))
        check("bare JSON array targets file loads", len(segs) == 1
              and src == "targets-file", f"{len(segs)} segs")

        p_env = os.path.join(_tdir, "env.json")
        with open(p_env, "w", encoding="utf-8") as f:
            json.dump({"exported_utc": "2026-07-24T00:00:00Z",
                       "segments": seg_min}, f)
        segs2, _ = m.load_segments(Args(targets_file=p_env))
        check("envelope targets file still loads", len(segs2) == 1)

        # regression: a MISSING targets file must exit with guidance, not a
        # FileNotFoundError traceback. Reachable in normal use because a
        # failed preflight is overridable via the prompt or --yes.
        try:
            m.load_segments(Args(targets_file=os.path.join(_tdir, "nope.json")))
            check("missing targets file exits cleanly", False, "no exit")
        except SystemExit as e:
            msg = str(e.code)
            check("missing targets file exits cleanly", True)
            check("missing-targets error names export-targets as the fix",
                  "export-targets" in msg, msg.splitlines()[0][:60])
        except FileNotFoundError:
            check("missing targets file exits cleanly", False,
                  "raised FileNotFoundError traceback")

        # unreadable file (permission denied) must also be clean
        p_noperm = os.path.join(_tdir, "noperm.json")
        with open(p_noperm, "w", encoding="utf-8") as f:
            json.dump(seg_min, f)
        try:
            os.chmod(p_noperm, 0)
            m.load_segments(Args(targets_file=p_noperm))
            check("unreadable targets file exits cleanly", False, "no exit")
        except SystemExit:
            check("unreadable targets file exits cleanly", True)
        except OSError:
            check("unreadable targets file exits cleanly", False, "raised OSError")
        finally:
            os.chmod(p_noperm, 0o644)

        # a JSON scalar is neither shape -> clean exit, not a traceback
        p_bad = os.path.join(_tdir, "bad.json")
        with open(p_bad, "w", encoding="utf-8") as f:
            json.dump("just a string", f)
        try:
            m.load_segments(Args(targets_file=p_bad))
            check("malformed targets file exits cleanly", False, "no exit")
        except SystemExit:
            check("malformed targets file exits cleanly", True)

        # regression: non-ASCII segment names crash on any platform whose
        # locale codec is not UTF-8 (Windows cp1252) unless encoding is set
        p_uni = os.path.join(_tdir, "unicode.json")
        with open(p_uni, "w", encoding="utf-8") as f:
            json.dump([{"name": "東京-Bürö", "domainNames": ["a.corp"]}], f,
                      ensure_ascii=False)
        segs3, _ = m.load_segments(Args(targets_file=p_uni))
        check("non-ASCII targets file reads regardless of locale codec",
              segs3[0]["name"] == "東京-Bürö", segs3[0]["name"])
    finally:
        shutil.rmtree(_tdir, ignore_errors=True)

    print("\nCredential gathering")
    _saved = {k: os.environ.get(k) for k in
              ("ZSCALER_CLIENT_ID", "ZSCALER_VANITY_DOMAIN",
               "ZPA_CUSTOMER_ID", "ZSCALER_CLIENT_SECRET")}
    try:
        os.environ.update({"ZSCALER_CLIENT_ID": "cid",
                           "ZSCALER_VANITY_DOMAIN": "van",
                           "ZPA_CUSTOMER_ID": "cust",
                           "ZSCALER_CLIENT_SECRET": "sec"})
        ac = Args()
        ac.client_id = None; ac.vanity_domain = None; ac.customer_id = None
        m.gather_credentials(ac)
        check("credentials resolve from env",
              ac.client_id == "cid" and ac.customer_id == "cust"
              and ac.client_secret == "sec")
        ac2 = Args(); ac2.client_id = "override"
        ac2.vanity_domain = None; ac2.customer_id = None
        m.gather_credentials(ac2)
        check("command-line flag overrides env", ac2.client_id == "override")
        for k in _saved:
            os.environ.pop(k, None)
        ac3 = Args()
        ac3.client_id = None; ac3.vanity_domain = None; ac3.customer_id = None
        # stdin here is not a TTY, so a missing credential must exit cleanly,
        # never block on input()
        try:
            m.gather_credentials(ac3)
            check("non-TTY missing creds exits cleanly", False, "no exit")
        except SystemExit:
            check("non-TTY missing creds exits cleanly", True)
    finally:
        for k, v in _saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    print("\nProbe semantics")
    # Windows delivers ConnectionRefusedError ~2s after connect (TCP
    # retransmit behaviour) vs instantly on Unix, so a short timeout turns
    # REFUSED into TIMEOUT. Use a timeout above that threshold.
    refuse_timeout = 5.0 if platform.system() == "Windows" else 1.0
    s, lat, att = m.tcp_probe_retry("127.0.0.1", 1, refuse_timeout, 2)
    check("REFUSED is definitive, not retried", s == "REFUSED" and att == 1,
          f"status={s} attempts={att} timeout={refuse_timeout}s")
    ip, err = m.resolve("localhost", 2.0)
    check("resolve() returns ip for localhost", ip is not None and err is None,
          str(ip))
    ip, err = m.resolve("no-such-host.invalid", 2.0)
    check("resolve() returns error for bogus name", ip is None and err)

    zcc = m.detect_zcc()
    check("detect_zcc returns structured state",
          isinstance(zcc, dict) and "state" in zcc and "platform" in zcc,
          f"state={zcc.get('state')} platform={zcc.get('platform')}")
    ok, detail = m.flush_dns_cache()
    check("flush_dns_cache reports honestly (no crash)",
          isinstance(ok, bool) and isinstance(detail, str), detail)

    # --------------------------------------------------------- end-to-end run
    print("\nEnd-to-end run + outputs")
    workdir = tempfile.mkdtemp(prefix="zpa-validate-")
    try:
        tf = os.path.join(workdir, "targets.json")
        with open(tf, "w") as f:
            json.dump({"exported_utc": "2026-07-23T00:00:00Z",
                       "segments": [
                           {"name": "Local", "id": "9", "enabled": True,
                            "ipAnchored": True,
                            "domainNames": ["localhost", "127.0.0.0/30",
                                            "*.skip.me"],
                            "tcpPortRanges": ["22", "22"],
                            "udpPortRange": [{"from": "53", "to": "53"}]}]}, f)

        out = os.path.join(workdir, "out")
        a = Args(targets_file=tf, output_dir=out, report=True, retries=1,
                 l7=True, cidr_hosts=2, scope_resolved="sample")
        a.scope = "sample"
        csv_path = m.run_test(a)

        check("CSV written to absolute path", os.path.isabs(csv_path)
              and os.path.isfile(csv_path))
        rows = list(csv.DictReader(open(csv_path)))
        check("rows produced", len(rows) > 0, f"{len(rows)} rows")
        check("all CSV fields present",
              set(m.CSV_FIELDS).issubset(rows[0].keys()))
        kinds = {r["entry_kind"] for r in rows}
        check("fqdn+cidr+wildcard all represented",
              {"fqdn", "cidr", "wildcard"}.issubset(kinds), str(sorted(kinds)))
        check("ip/cidr rows marked zpa_intercepted=N/A",
              all(r["zpa_intercepted"] == "N/A"
                  for r in rows if r["entry_kind"] == "cidr"))
        check("flat-form ports produced tcp rows",
              any(r["protocol"] == "tcp" and r["port"] == "22" for r in rows))
        check("udp listed but not probed",
              any(r["status"] == "UDP_NOT_PROBED" for r in rows))
        check("wildcard recorded as skipped",
              any(r["status"] == "WILDCARD_SKIPPED" for r in rows))

        meta_path = csv_path.replace(".csv", ".meta.json")
        meta = json.load(open(meta_path))
        check("meta sidecar written", os.path.isfile(meta_path))
        check("meta records zcc + scope + source",
              meta.get("zcc") and meta.get("scope") == "sample"
              and meta.get("segment_source") == "targets-file")
        check("meta records sampling config",
              meta["sampling"]["retries"] == 1 and meta["sampling"]["l7"])

        html_path = csv_path.replace(".csv", ".html")
        doc = open(html_path, encoding="utf-8").read()
        check("HTML report written", os.path.isfile(html_path))
        check("HTML is self-contained (no external refs)",
              "src=\"http" not in doc and "href=\"http" not in doc
              and "cdn" not in doc.lower())
        check("HTML has dark-mode support",
              "prefers-color-scheme" in doc)

        # compare: same file against itself = no changes
        pre = m.load_csv(csv_path)
        broken, fixed, changed = m.diff_runs(pre, pre)
        check("self-compare reports no changes",
              not broken and not fixed and not changed)

        # Deterministic diff test: synthesize a known-OPEN baseline row so
        # the assertion does not depend on whether a live port answered.
        key = ("Synth", "syn.corp.local", "syn.corp.local", "tcp", "443")
        base_row = {"segment": "Synth", "domain": "syn.corp.local",
                    "probe_domain": "syn.corp.local", "protocol": "tcp",
                    "port": "443", "status": "OPEN", "zpa_intercepted": ""}
        pre_s = dict(pre); pre_s[key] = base_row
        post_s = {k: dict(v) for k, v in pre_s.items()}
        post_s[key]["status"] = "TIMEOUT"
        broken, fixed, changed = m.diff_runs(pre_s, post_s)
        check("regression (OPEN->TIMEOUT) detected",
              len(broken) == 1 and broken[0][1] == "OPEN"
              and broken[0][2] == "TIMEOUT", f"broken={len(broken)}")

        post_s[key]["status"] = "OPEN"
        pre_s2 = {k: dict(v) for k, v in pre_s.items()}
        pre_s2[key]["status"] = "TIMEOUT"
        broken2, fixed2, _ = m.diff_runs(pre_s2, post_s)
        check("recovery (TIMEOUT->OPEN) counted as fixed, not broken",
              len(fixed2) == 1 and not broken2)

        check("OPEN_FLAKY treated as reachable",
              "OPEN_FLAKY" in m.OK_STATUSES)

        merged = os.path.join(workdir, "merged.html")
        m.write_html_report(merged,
                            [(csv_path, rows, meta)],
                            diff=(broken, fixed, changed, ["new.corp"], []))
        mdoc = open(merged, encoding="utf-8").read()
        check("merged HTML includes diff section",
              "Pre &rarr; Post changes" in mdoc and "new.corp" in mdoc)

        # regression: a non-ASCII segment name must survive the full write
        # path on a cp1252 machine (this is where v1.2.1 died on Windows,
        # after every probe had already run)
        tf_u = os.path.join(workdir, "targets-unicode.json")
        with open(tf_u, "w", encoding="utf-8") as f:
            json.dump({"segments": [
                {"name": "東京-Bürö-Segment", "id": "u1", "enabled": True,
                 "ipAnchored": False, "domainNames": ["localhost"],
                 "tcpPortRanges": ["22", "22"]}]}, f, ensure_ascii=False)
        au = Args(targets_file=tf_u, output_dir=os.path.join(workdir, "outu"),
                  scope_resolved="sample", report=True)
        au.scope = "sample"
        csv_u = m.run_test(au)
        check("non-ASCII segment name survives CSV write", os.path.isfile(csv_u))
        rows_u = m.load_rows(csv_u)
        check("non-ASCII segment name round-trips through the CSV",
              any(r["segment"] == "東京-Bürö-Segment" for r in rows_u),
              rows_u[0]["segment"] if rows_u else "no rows")
        meta_u = json.load(open(csv_u.replace(".csv", ".meta.json"),
                                encoding="utf-8"))
        check("meta sidecar records no worker errors",
              meta_u["results"].get("worker_errors") == 0)

        # regression: one raising worker used to discard every row collected
        # so far, because fut.result() was called outside a try
        _orig_pt = m.probe_target
        _seen = {"n": 0}
        def exploding(t, a):
            _seen["n"] += 1
            if _seen["n"] == 1:
                raise RuntimeError("simulated worker crash")
            return _orig_pt(t, a)
        m.probe_target = exploding
        try:
            ae = Args(targets_file=tf, output_dir=os.path.join(workdir, "oute"),
                      scope_resolved="sample", cidr_hosts=2)
            ae.scope = "sample"
            csv_e = m.run_test(ae)
            rows_e = m.load_rows(csv_e)
            check("worker crash does not abort the run", os.path.isfile(csv_e))
            check("worker crash is recorded as a PROBE_ERROR row",
                  any(r["status"].startswith("PROBE_ERROR") for r in rows_e),
                  str({r["status"] for r in rows_e}))
            check("rows from healthy workers are still written",
                  len([r for r in rows_e
                       if not r["status"].startswith("PROBE_ERROR")]) > 0)
            meta_e = json.load(open(csv_e.replace(".csv", ".meta.json"),
                                    encoding="utf-8"))
            check("meta counts worker errors",
                  meta_e["results"].get("worker_errors") == 1,
                  str(meta_e["results"].get("worker_errors")))
        finally:
            m.probe_target = _orig_pt

        # compare/report must reject a CSV that is not ours, with a message
        notours = os.path.join(workdir, "notours.csv")
        with open(notours, "w", newline="", encoding="utf-8") as f:
            f.write("a,b\n1,2\n")
        try:
            m.load_csv(notours)
            check("non-results CSV rejected cleanly", False, "no exit")
        except SystemExit:
            check("non-results CSV rejected cleanly", True)

        # non-interactive guard
        r = subprocess.run([sys.executable, tool_path, "test", "--phase",
                            "pre", "--targets-file", tf],
                           capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        check("no-scope non-interactive run refuses cleanly",
              r.returncode != 0 and "no interactive terminal" in
              (r.stdout + r.stderr))

        r = subprocess.run([sys.executable, tool_path, "test", "--phase",
                            "pre", "--scope", "sample", "--targets-file", tf,
                            "--output-dir", os.path.join(workdir, "outn"),
                            "--no-show-failures", "--yes"],
                           capture_output=True, text=True, timeout=120,
                           stdin=subprocess.DEVNULL)
        check("--no-show-failures is accepted and suppresses the listing",
              r.returncode == 0 and "Failures:" not in r.stdout,
              f"rc={r.returncode}")

        for sub in ("preflight", "export-targets", "test", "sipa-verify",
                    "compare", "report"):
            r = subprocess.run([sys.executable, tool_path, sub, "--help"],
                               capture_output=True, text=True, timeout=30)
            check(f"`{sub} --help` works", r.returncode == 0)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n{'=' * 60}")
    print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("Failed:")
        for f in FAIL:
            print(f"  - {f}")
    print("=" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
