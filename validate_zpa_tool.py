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
import re
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

        # An unopenable path must exit cleanly too. Use a directory rather
        # than chmod 0: Windows ignores POSIX mode bits for read access, so
        # the chmod approach cannot create the condition there at all.
        # open(<dir>) raises IsADirectoryError on POSIX and PermissionError
        # on Windows — both OSError, both the branch under test.
        p_dir = os.path.join(_tdir, "a-directory.json")
        os.makedirs(p_dir, exist_ok=True)
        try:
            m.load_segments(Args(targets_file=p_dir))
            check("unopenable targets path exits cleanly", False, "no exit")
        except SystemExit:
            check("unopenable targets path exits cleanly", True)
        except OSError as e:
            check("unopenable targets path exits cleanly", False,
                  f"raised {type(e).__name__}")

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

    print("\nResult triage / coverage")
    trows = [
        {"entry_kind": "fqdn", "status": "OPEN", "segment": "A",
         "probe_domain": "a.corp", "domain": "a.corp"},
        {"entry_kind": "fqdn", "status": "DNS_FAIL:x", "segment": "A",
         "probe_domain": "b.corp", "domain": "b.corp"},
        {"entry_kind": "cidr", "status": "TIMEOUT", "segment": "B",
         "probe_domain": "10.1.0.1", "domain": "10.1.0.0/24"},
        {"entry_kind": "ip", "status": "TIMEOUT", "segment": "B",
         "probe_domain": "10.2.0.5", "domain": "10.2.0.5"},
        {"entry_kind": "wildcard", "status": "WILDCARD_SKIPPED", "segment": "C",
         "probe_domain": "", "domain": "*.c.corp"},
        {"entry_kind": "fqdn", "status": "UDP_NOT_PROBED", "segment": "A",
         "probe_domain": "a.corp", "domain": "a.corp"},
    ]
    act, unv = m.triage_failures(trows)
    check("triage: only real fqdn failures are action-required",
          len(act) == 1 and act[0]["probe_domain"] == "b.corp", str(len(act)))
    check("triage: ip/cidr failures are unverifiable, not action-required",
          len(unv) == 2 and all(r["entry_kind"] in ("ip", "cidr") for r in unv))
    check("triage: OPEN / skipped / not-probed are not failures",
          len(act) + len(unv) == 3)

    cstats = {"entries_sampled_out": 3008, "ports_truncated": 21780,
              "kinds": {"fqdn": 3000, "ip": 74, "cidr": 6, "wildcard": 462}}
    cov = "\n".join(m.coverage_report(cstats, Args(wildcard_probe=None), 380))
    check("coverage: reports probed/total entries honestly",
          "66/3074" in cov, cov.splitlines()[0].strip())
    check("coverage: reports the port fraction",
          "380/22160" in cov)
    check("coverage: flags wildcards as NOT probed",
          "462 NOT probed" in cov)
    cov2 = "\n".join(m.coverage_report(cstats, Args(wildcard_probe="www"), 380))
    check("coverage: wildcards counted as probed when --wildcard-probe set",
          "462 probed" in cov2)

    steps = m.next_steps(Args(phase="post", wildcard_probe=None), cstats,
                         act, unv, [{"status": "DNS_FAIL:x"}],
                         False, set())
    joined = " ".join(steps)
    check("next steps: flags an incomplete DNS flush before blaming DNS",
          any("sudo" in s for s in steps), str(len(steps)) + " steps")
    check("next steps: points ip/cidr findings at the portal",
          "access logs" in joined)
    check("next steps: recommends --wildcard-probe when wildcards skipped",
          "--wildcard-probe" in joined)
    check("next steps: warns when no synthetic IPs were seen post-run",
          "Private Access" in joined)
    steps_ok = m.next_steps(Args(phase="post", wildcard_probe="www"),
                            {"entries_sampled_out": 0, "ports_truncated": 0,
                             "kinds": {"fqdn": 1, "ip": 0, "cidr": 0,
                                       "wildcard": 0}},
                            [], [], [], "ok", {"a.corp"})
    check("next steps: silent when a run is clean and complete",
          steps_ok == [], str(steps_ok))
    # regression: macOS reports "dscacheutil=ok, killall=rc1" for a FAILED
    # flush, so this must key off the boolean, not the detail string
    s_none = " ".join(m.next_steps(Args(phase="post", wildcard_probe="www"),
                      {"entries_sampled_out": 0, "ports_truncated": 0,
                       "kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0}},
                      [], [], [{"status": "DNS_FAIL:x"}], None, {"a"}))
    check("next steps: distinguishes flush-not-attempted from flush-failed",
          "--flush-dns" in s_none and "sudo python3" not in s_none, s_none[:60])
    s_ok = " ".join(m.next_steps(Args(phase="post", wildcard_probe="www"),
                    {"entries_sampled_out": 0, "ports_truncated": 0,
                     "kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0}},
                    [], [], [{"status": "DNS_FAIL:x"}], True, {"a"}))
    check("next steps: clean flush + DNS failure blames enrollment, not cache",
          "enrolled" in s_ok and "sudo" not in s_ok, s_ok[:60])

    print("\nSaved tenants")
    _tstore = os.path.join(tempfile.mkdtemp(prefix="zpa-tenants-"),
                           "tenants.json")
    _prev_store = os.environ.get("ZPA_TENANT_STORE")
    os.environ["ZPA_TENANT_STORE"] = _tstore
    _orig_ask = m.ask
    try:
        check("store path honours ZPA_TENANT_STORE",
              m.tenant_store_path() == _tstore)
        check("missing store reads as empty, not an error",
              m.load_tenant_store() == {"tenants": []})

        doc = {"tenants": [
            {"name": "model", "production": False, "client_id": "mid",
             "vanity_domain": "acme-model", "customer_id": "1111"},
            {"name": "production", "production": True, "client_id": "pid",
             "vanity_domain": "acme", "customer_id": "9999",
             "client_secret": "s3cret"}]}
        m.save_tenant_store(doc)
        check("store round-trips", m.load_tenant_store() == doc)
        if os.name != "nt":
            mode = os.stat(_tstore).st_mode & 0o777
            check("store is written 0600, not widened later", mode == 0o600,
                  oct(mode))
        check("find_tenant is case-insensitive",
              m.find_tenant(doc, "PRODUCTION")["client_id"] == "pid")
        check("find_tenant returns None for unknown",
              m.find_tenant(doc, "staging") is None)

        # tenant values must not clobber an explicit flag
        a = Args(client_id="from-flag", vanity_domain=None, customer_id=None)
        m.apply_tenant(a, m.find_tenant(doc, "model"))
        check("explicit --client-id wins over the saved tenant",
              a.client_id == "from-flag")
        check("unset fields are filled from the tenant",
              a.vanity_domain == "acme-model" and a.customer_id == "1111")
        check("tenant name recorded on args", a.tenant_name == "model")
        a2 = Args(client_id=None, vanity_domain=None, customer_id=None)
        m.apply_tenant(a2, m.find_tenant(doc, "production"))
        check("saved secret is applied when present",
              a2.client_secret == "s3cret")

        # --- confirmation: name-typing is scoped to PRODUCTION only ---
        answers, asked = [], []

        def _fake_ask(prompt, msg):
            asked.append(prompt)
            return answers.pop(0)
        m.ask = _fake_ask
        prod = m.find_tenant(doc, "production")
        model = m.find_tenant(doc, "model")

        answers[:] = ["y", "production"]; asked[:] = []
        try:
            m.confirm_tenant_choice(prod)
            check("production: correct name at the 2nd prompt proceeds", True)
        except SystemExit as e:
            check("production: correct name at the 2nd prompt proceeds",
                  False, str(e.code))
        check("production asks twice", len(asked) == 2, f"{len(asked)} prompts")

        answers[:] = ["y", "model"]
        try:
            m.confirm_tenant_choice(prod)
            check("production: wrong name aborts", False, "proceeded")
        except SystemExit as e:
            check("production: wrong name aborts", True)
            check("abort message names both values",
                  "model" in str(e.code) and "production" in str(e.code))

        answers[:] = ["y", "y"]
        try:
            m.confirm_tenant_choice(prod)
            check("production: a second bare 'y' is not accepted", False,
                  "proceeded")
        except SystemExit:
            check("production: a second bare 'y' is not accepted", True)

        answers[:] = ["n"]
        try:
            m.confirm_tenant_choice(prod)
            check("production: declining the 1st prompt aborts", False,
                  "proceeded")
        except SystemExit:
            check("production: declining the 1st prompt aborts", True)

        # non-production is a single y/N — the same friction everywhere just
        # trains people to type through it
        answers[:] = ["y"]; asked[:] = []
        try:
            m.confirm_tenant_choice(model)
            check("non-production: a single 'y' proceeds", True)
        except SystemExit as e:
            check("non-production: a single 'y' proceeds", False, str(e.code))
        check("non-production asks exactly once", len(asked) == 1,
              f"{len(asked)} prompts")
        check("non-production prompt does not demand the name",
              "typing the tenant name" not in "".join(asked))

        answers[:] = ["n"]
        try:
            m.confirm_tenant_choice(model)
            check("non-production: 'n' still aborts", False, "proceeded")
        except SystemExit:
            check("non-production: 'n' still aborts", True)

        # --tenant NAME resolution
        answers[:] = ["y", "production"]
        sel = m.select_tenant(Args(tenant="production", yes=False))
        check("--tenant selects and confirms", sel["client_id"] == "pid")
        sel = m.select_tenant(Args(tenant="model", yes=True))
        check("--tenant with --yes skips confirmation (scripted intent)",
              sel["client_id"] == "mid")
        # regression: only `test` defines --yes, so select_tenant reading
        # args.yes directly raised AttributeError on export-targets and
        # sipa-verify — exactly the commands --tenant exists to serve
        class _NoYes:
            tenant = "model"
        _ny = _NoYes()
        answers[:] = ["y"]
        try:
            sel = m.select_tenant(_ny)
            check("--tenant works on a subcommand without --yes",
                  sel is not None and sel.get("client_id") == "mid")
        except AttributeError as e:
            check("--tenant works on a subcommand without --yes", False,
                  f"AttributeError: {e}")

        try:
            m.select_tenant(Args(tenant="staging", yes=True))
            check("unknown --tenant exits", False, "no exit")
        except SystemExit as e:
            check("unknown --tenant exits", True)
            check("unknown-tenant error lists configured names",
                  "model" in str(e.code) and "production" in str(e.code))
        # interactive selection is the default path when --tenant is absent
        answers[:] = ["2", "y", "production"]
        sel = m.select_tenant(Args(tenant=None, yes=False))
        check("interactive pick + double confirm selects production",
              sel["client_id"] == "pid", str(sel and sel.get("name")))
        answers[:] = ["0"]
        check("choice 0 opts out to manual credential entry",
              m.select_tenant(Args(tenant=None, yes=False)) is None)
        # non-production needs only the single y/N, so two answers suffice
        answers[:] = ["model", "y"]
        sel = m.select_tenant(Args(tenant=None, yes=False))
        check("tenant can be chosen by name at the menu",
              sel["client_id"] == "mid")
        check("no leftover answers — non-production consumed exactly one "
              "confirmation", not answers, str(answers))

        # an empty store must fall through to env/prompt, not show a menu
        _empty_dir = tempfile.mkdtemp(prefix="zpa-empty-")
        os.environ["ZPA_TENANT_STORE"] = os.path.join(_empty_dir, "t.json")
        try:
            check("empty store -> None, so env/prompt still works",
                  m.select_tenant(Args(tenant=None, yes=False)) is None)
        finally:
            os.environ["ZPA_TENANT_STORE"] = _tstore
            shutil.rmtree(_empty_dir, ignore_errors=True)
    finally:
        m.ask = _orig_ask
        if _prev_store is None:
            os.environ.pop("ZPA_TENANT_STORE", None)
        else:
            os.environ["ZPA_TENANT_STORE"] = _prev_store
        shutil.rmtree(os.path.dirname(_tstore), ignore_errors=True)

    print("\nSynthetic IP range (tenant-configurable)")
    # 100.64.0.0/10 is the RFC 6598 CGNAT range. A tenant that narrows its
    # synthetic range and a tool that assumes /10 disagree over 4.1M
    # addresses — and on a CGNAT network (hotel, mobile hotspot) an
    # ISP-assigned address inside /10 would be reported as ZPA-steered,
    # producing a false "ZPA IS STEERING" verdict.
    import ipaddress as _ip
    check("default matches Zscaler's documented range",
          m.DEFAULT_SYNTHETIC_NET == "100.64.0.0/10")

    class _N:
        def __init__(self, v=None):
            self.synthetic_net = v

    d10 = m.synthetic_net_for(_N())
    d16 = m.synthetic_net_for(_N("100.64.0.0/16"))
    check("default resolves to /10", str(d10) == "100.64.0.0/10")
    check("tenant override resolves to /16", str(d16) == "100.64.0.0/16")
    check("a CGNAT address inside /10 is NOT steered under a /16 tenant",
          _ip.ip_address("100.90.4.7") in d10
          and _ip.ip_address("100.90.4.7") not in d16)
    check("an address inside the narrowed range is still steered",
          _ip.ip_address("100.64.0.5") in d16)
    _a = _N("100.64.0.0/16")
    _first = m.synthetic_net_for(_a)
    check("resolution is cached on args", m.synthetic_net_for(_a) is _first)
    for bad in ("not-a-cidr", "999.0.0.0/8", "::1/128"):
        try:
            m.parse_synthetic_net(bad)
            check(f"invalid range {bad!r} rejected", False, "accepted")
        except SystemExit as e:
            check(f"invalid range {bad!r} rejected", True,
                  str(e.code).splitlines()[0][:44])
    v, det = m.run_verdict(Args(phase="post"), {"a.corp"},
                           {"state": "running"}, d16)
    check("verdict names the tenant's range, not the default",
          "100.64.0.0/16" in det and "100.64.0.0/10" not in det, det[:70])
    check("synthetic_net is a stored tenant field",
          "synthetic_net" in m.TENANT_FIELDS)

    print("\nRun-size safety ceiling")
    # Real numbers from a --scope full run against a 22-segment tenant:
    # 6,958,550 targets / ~456 billion probes. The tool merely *asked* for
    # confirmation, and the run could never have finished.
    HUGE = 456_009_725_001
    best, worst = m.estimate_duration(HUGE, Args(workers=20, timeout=5.0))
    check("worst case for a real full-scope run is measured in years",
          worst / 31_536_000 > 1000, m.format_duration(worst))
    check("even the best case is impractical",
          best / 86_400 > 100, m.format_duration(best))
    try:
        m.confirm_run(HUGE, Args(scope_resolved="full", workers=20,
                                 timeout=5.0, yes=False))
        check("absurd run is refused", False, "not refused")
    except SystemExit as e:
        msg = str(e.code)
        check("absurd run is refused outright", True)
        check("refusal names the narrowing options",
              "--scope sample" in msg and "--max-ports" in msg)
        check("refusal explains the port-sweep implication",
              "port sweep" in msg)
    # --yes means unattended, not unbounded: it must NOT bypass the ceiling
    try:
        m.confirm_run(HUGE, Args(scope_resolved="full", workers=20,
                                 timeout=5.0, yes=True))
        check("--yes does not bypass the ceiling", False, "bypassed")
    except SystemExit:
        check("--yes does not bypass the ceiling", True)
    # explicit override still works for someone who means it
    try:
        m.confirm_run(HUGE, Args(scope_resolved="full", workers=20,
                                 timeout=5.0, yes=True, force_huge_run=True))
        check("--force-huge-run overrides the ceiling", True)
    except SystemExit as e:
        check("--force-huge-run overrides the ceiling", False, str(e.code)[:40])
    # a normal sampled run is unaffected
    try:
        m.confirm_run(500, Args(scope_resolved="sample", workers=20,
                                timeout=5.0, yes=False))
        check("ordinary sampled run passes without prompting", True)
    except SystemExit as e:
        check("ordinary sampled run passes without prompting", False,
              str(e.code)[:40])
    check("format_duration scales to years",
          m.format_duration(3.15e9).endswith("years"),
          m.format_duration(3.15e9))
    check("format_duration handles seconds",
          m.format_duration(45) == "45s", m.format_duration(45))

    print("\nSummary rendering (actionability)")
    # 1 — verdict resolves the question the run exists to answer
    v, d = m.run_verdict(Args(phase="post"), {"a.corp"}, {"state": "running"})
    check("post + synthetic IPs -> steering verdict", v == "ZPA IS STEERING", v)
    v, d = m.run_verdict(Args(phase="post"), set(), {"state": "running"})
    check("post + none -> no-steering verdict", v == "NO STEERING OBSERVED", v)
    v, d = m.run_verdict(Args(phase="pre"), set(), {"state": "not_detected"})
    check("pre + none -> valid baseline", v == "BASELINE CAPTURED", v)
    # the trap: a 'pre' run on an already-enrolled endpoint is not a baseline
    v, d = m.run_verdict(Args(phase="pre"), {"a.corp"}, {"state": "running"})
    check("pre + already steered -> BASELINE INVALID",
          v == "BASELINE INVALID", v)

    # 3 — failure classes are distinguished by what they imply
    check("TIMEOUT classified", m.classify_failure("TIMEOUT") == "TIMEOUT")
    check("REFUSED classified separately from TIMEOUT",
          m.classify_failure("REFUSED") == "REFUSED")
    check("DNS_FAIL:detail classified", m.classify_failure(
        "DNS_FAIL:[Errno 8] nodename nor servname") == "DNS_FAIL")
    check("unknown status -> OTHER",
          m.classify_failure("ERROR:whatever") == "OTHER")

    # 2 — grouping collapses one-line-per-port into one line per host+class
    frows = [{"segment": "S", "probe_domain": "h1", "status": "TIMEOUT",
              "port": p, "entry_kind": "fqdn"} for p in (1, 2, 3, 22, 1000)]
    frows.append({"segment": "S", "probe_domain": "h1", "status": "REFUSED",
                  "port": 443, "entry_kind": "fqdn"})
    g = m.group_failures(frows)
    check("6 rows collapse to 2 groups (one per status class)", len(g) == 2,
          str(sorted(k[2] for k in g)))
    tkey = ("S", "h1", "TIMEOUT")
    check("group records every port", g[tkey]["n"] == 5)
    check("port list is numerically sorted and compact",
          m._port_list(g[tkey]["ports"]) == "1,2,3,22,1000",
          m._port_list(g[tkey]["ports"]))
    check("long port lists are truncated with a count",
          m._port_list(list(range(1, 30))).endswith(",+21"),
          m._port_list(list(range(1, 30))))

    # 7 — status histogram + section headers
    h = m.status_histogram([{"status": "OPEN"}, {"status": "OPEN"},
                            {"status": "TIMEOUT"},
                            {"status": "DNS_FAIL:[Errno 8] boom"}])
    check("histogram counts by status", h.get("OPEN") == 2
          and h.get("TIMEOUT") == 1)
    check("histogram collapses ':detail' suffixes", h.get("DNS_FAIL") == 1,
          str(h))
    check("section header is ASCII-only (legacy Windows console safe)",
          all(ord(c) < 128 for c in m._section("COVERAGE")),
          m._section("COVERAGE").strip())

    # 4 — latency is summarized rather than discarded
    lrows = [{"status": "OPEN", "latency_ms": v, "segment": "A"}
             for v in (10, 20, 30, 40, 100)]
    lrows.append({"status": "TIMEOUT", "latency_ms": "", "segment": "A"})
    st = m.latency_stats(lrows)
    check("latency median computed over successes only",
          st["count"] == 5 and st["median_ms"] == 30, str(st))
    check("latency p95 and max reported",
          st["p95_ms"] == 100 and st["max_ms"] == 100, str(st))
    check("latency_stats returns None when nothing succeeded",
          m.latency_stats([{"status": "TIMEOUT", "latency_ms": ""}]) is None)
    slow = m.slowest_segments(
        lrows + [{"status": "OPEN", "latency_ms": 500, "segment": "B"}])
    check("slowest segment ranked first", slow[0][0] == "B", str(slow))

    # 5 — per-segment rollup
    rr = [{"segment": "A", "protocol": "tcp", "status": "OPEN",
           "entry_kind": "fqdn", "zpa_intercepted": "True"},
          {"segment": "A", "protocol": "tcp", "status": "TIMEOUT",
           "entry_kind": "fqdn", "zpa_intercepted": "True"},
          {"segment": "B", "protocol": "tcp", "status": "TIMEOUT",
           "entry_kind": "cidr", "zpa_intercepted": "N/A"},
          {"segment": "A", "protocol": "dns", "status": "DNS_FAIL:x",
           "entry_kind": "fqdn", "zpa_intercepted": ""}]
    ru = m.segment_rollup(rr)
    check("rollup counts probed/open/failed per segment",
          ru["A"]["probed"] == 2 and ru["A"]["open"] == 1
          and ru["A"]["failed"] == 1, str(ru["A"]))
    check("rollup counts dns failures separately",
          ru["A"]["dns_fail"] == 1)
    check("rollup marks steered segments", ru["A"]["steered"] is True)
    check("ip/cidr-only segment is not marked steered",
          ru["B"]["steered"] is False
          and ru["B"]["kinds"].issubset(set(m.UNVERIFIABLE_KINDS)))

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

        # --- clickable tile filters ---
        # Tile counts come from Python; the click-to-filter predicates are
        # JavaScript. If they drift, a tile reads "4 failing probes" and
        # clicking it shows a different number, silently. Mirror the JS here
        # and assert each tile selects exactly what it claims.
        _h = open(csv_path.replace(".csv", ".html"), encoding="utf-8").read()
        _rows = [{"status": g[0], "proto": g[1], "steered": g[2]}
                 for g in re.findall(
                     r'<tr data-status="([^"]*)" data-proto="([^"]*)" '
                     r'data-steered="([^"]*)"', _h)]
        _tiles = dict(re.findall(
            r'<div class="tile" data-tilefilter="([a-z]+)"[^>]*>'
            r'<div class="n [^"]*">([^<]*)</div>', _h))
        check("every row carries machine-readable state",
              len(_rows) == len(rows), f"{len(_rows)} of {len(rows)}")
        check("all five filterable tiles are present",
              set(_tiles) == {"reachable", "failing", "flaky", "dnsfail",
                              "steered"}, str(sorted(_tiles)))

        def _ok(s):
            return s in ("OPEN", "OPEN_FLAKY")

        def _tcp(d):
            return d["proto"] == "tcp" and d["status"] != "NO_TCP_PORTS"

        _pred = {
            "reachable": lambda d: _tcp(d) and _ok(d["status"]),
            "failing": lambda d: _tcp(d) and not _ok(d["status"]),
            "flaky": lambda d: d["proto"] == "tcp"
            and d["status"] == "OPEN_FLAKY",
            "dnsfail": lambda d: d["status"].startswith("DNS_FAIL"),
            "steered": lambda d: d["steered"] == "True",
        }
        for _k in sorted(_pred):
            _sel = sum(1 for d in _rows if _pred[_k](d))
            _claim = _tiles.get(_k, "0")
            _want = int(str(_claim).split("/")[0])
            # the steered tile counts unique domains; rows may exceed it
            _agree = (_sel >= _want) if _k == "steered" else (_sel == _want)
            check(f"tile '{_k}' filter selects what the tile claims", _agree,
                  f"tile={_claim} selects={_sel}")

        check("median-latency tile is not clickable (a median is not rows)",
              'data-tilefilter="latency"' not in _h)
        check("status cells are clickable",
              _h.count("statuscell") >= len(_rows), str(_h.count("statuscell")))
        check("tiles are bound to their table",
              'class="tiles" data-target="#' in _h)
        check("tile filters are keyboard reachable", 'tabindex="0"' in _h)

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
        # patch probe_port, not probe_target: run_test now submits one pool
        # task per (target, port), so patching the whole-target helper would
        # leave this assertion testing nothing
        _orig_pt = m.probe_port
        _seen = {"n": 0}
        def exploding(t, p, r, a):
            _seen["n"] += 1
            if _seen["n"] == 1:
                raise RuntimeError("simulated worker crash")
            return _orig_pt(t, p, r, a)
        m.probe_port = exploding
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
            m.probe_port = _orig_pt

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
