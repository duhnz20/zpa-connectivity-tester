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
import socket
import subprocess
import sys
import tempfile
import threading
import time

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
            targets_file=None, retries=0, l7=False, l7_timeout=None,
            dns_csv=None, dns_sample=0, dns_ports=None,
            flush_dns=False,
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
    check("bare ip", m.classify_entry("192.0.2.30") == "ip")
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

    # ------------------------------------------------------ DNS destinations
    # The export is pre-ZPA ground truth: what each name resolves to with no
    # Client Connector in the path. It answers the question the segment
    # inventory cannot — which internal names are NOT enrolled in ZPA.
    #
    # The load-bearing property is that this mode invents no ports. An
    # enterprise-wide record list spans every server role, so a fixed port
    # set would report a steered database host as TIMEOUT (which the summary
    # reads as "traffic may not be steered" — the opposite of the truth) and
    # would amount to a horizontal scan from a managed endpoint.
    print("\nDNS destinations CSV")
    _dwork = tempfile.mkdtemp(prefix="zpa-validate-dns-")
    try:
        _dhdr = ["SourceFile", "SourceRowNumber", "Name", "ViewName",
                 "ZoneName", "TTL", "Class", "RecordType", "RDATA",
                 "IsWildcard", "TerminalName", "CNameHopCount", "CNameChain",
                 "ChainComplete", "ChainStopReason", "LookupStatus",
                 "IpCount", "ResolvedIPs", "OnlyExternalIPs",
                 "HasAnyExternalIP", "HasAnyInternalIP", "ListedIPsFromRDATA",
                 "ListedIpCountFromRDATA", "ListedOnlyExternalIPs",
                 "ErrorMessage"]

        def _drec(name, rtype="CNAME", ips="192.0.2.10", ext="FALSE",
                  internal="TRUE", wild="FALSE", lookup="OK"):
            d = dict.fromkeys(_dhdr, "")
            d.update({"SourceFile": "cname-records.csv",
                      "SourceRowNumber": 1, "Name": name, "TTL": 3600,
                      "Class": "IN", "RecordType": rtype,
                      "IsWildcard": wild, "TerminalName": "t-" + name,
                      "CNameHopCount": 1, "ChainComplete": "TRUE",
                      "LookupStatus": lookup, "ResolvedIPs": ips,
                      "OnlyExternalIPs": ext, "HasAnyInternalIP": internal})
            return d

        _drows = [_drec("in-seg.corp.local"), _drec("gap.corp.local"),
                  _drec("orphan.corp.local"),
                  _drec("ext.corp.local", ips="203.0.113.9", ext="TRUE",
                        internal="FALSE"),
                  _drec("app.wild.corp", ips="192.0.2.30"),
                  _drec("*.skip.corp.local", wild="TRUE"),
                  _drec("txt.corp.local", rtype="TXT"),
                  _drec("bad.corp.local", lookup="NXDOMAIN"),
                  _drec("in-seg.corp.local")]
        _dcsv = os.path.join(_dwork, "dns_destinations.csv")
        # utf-8-sig: Excel writes a BOM, and an unstripped BOM becomes part
        # of the first header name and breaks every column lookup.
        with open(_dcsv, "w", newline="", encoding="utf-8-sig") as _f:
            _w = csv.DictWriter(_f, fieldnames=_dhdr)
            _w.writeheader()
            _w.writerows(_drows)

        _da = Args(dns_csv=_dcsv, dns_sample=0)
        _dby, _dst = m.load_dns_csv(_dcsv, _da)
        check("Excel BOM stripped, Name column resolves",
              "in-seg.corp.local" in _dby, str(sorted(_dby))[:160])
        check("non-A/CNAME records skipped", _dst["skipped_type"] == 1,
              _dst["skipped_type"])
        check("LookupStatus != OK skipped", _dst["skipped_lookup"] == 1)
        check("wildcards skipped without --wildcard-probe",
              _dst["skipped_wildcard"] == 1)
        check("duplicate names collapsed", _dst["duplicates"] == 1)
        check("wildcard substituted with --wildcard-probe",
              "www.skip.corp.local" in
              m.load_dns_csv(_dcsv, Args(wildcard_probe="www"))[0])
        # Excel on Windows writes cp1252; one smart quote in an
        # enterprise-wide export must not abort the run.
        _cp = os.path.join(_dwork, "cp1252.csv")
        with open(_cp, "w", newline="", encoding="cp1252") as _f:
            _w2 = csv.DictWriter(_f, fieldnames=_dhdr)
            _w2.writeheader()
            _r = _drec("caf\u00e9.corp.local")
            _r["ZoneName"] = "caf\u00e9 \u2014 zone"
            _w2.writerow(_r)
        _cpby, _ = m.load_dns_csv(_cp, _da)
        check("a cp1252 export loads instead of crashing",
              "caf\u00e9.corp.local" in _cpby, str(sorted(_cpby)))

        check("booleans parsed from the export",
              _dby["ext.corp.local"]["only_external"] is True
              and _dby["gap.corp.local"]["has_internal"] is True)
        try:
            _bp = os.path.join(_dwork, "notdns.csv")
            open(_bp, "w").write("a,b\n1,2\n")
            m.load_dns_csv(_bp, _da)
            check("a CSV without a Name column is rejected", False, "no exit")
        except SystemExit as _e:
            check("a CSV without a Name column is rejected",
                  "no 'Name' column" in str(_e), str(_e)[:100])
        try:
            m.load_dns_csv(os.path.join(_dwork, "absent.csv"), _da)
            check("a missing export is rejected", False, "no exit")
        except SystemExit as _e:
            check("a missing export is rejected", "not found" in str(_e))

        _dsegs = [{"name": "Seg-A", "id": "1", "enabled": True,
                   "ipAnchored": True,
                   "domainNames": ["in-seg.corp.local", "gap.corp.local",
                                   "ext.corp.local"],
                   "tcpPortRange": [{"from": "443", "to": "443"},
                                    {"from": "8000", "to": "8100"}]},
                  {"name": "Seg-Wild", "id": "2", "enabled": True,
                   "ipAnchored": True, "domainNames": ["*.wild.corp"],
                   "tcpPortRanges": ["443", "443"]}]
        _ex, _wd = m.segment_domain_index(_dsegs, _da)
        check("exact FQDN matches its segment",
              m.match_segment("in-seg.corp.local", _ex, _wd)[0] == "Seg-A")
        check("wildcard parent matches a subdomain",
              m.match_segment("app.wild.corp", _ex, _wd)[0] == "Seg-Wild")
        check("a name in no segment matches nothing",
              m.match_segment("orphan.corp.local", _ex, _wd) == (None, None))

        _dtg, _dbs = m.build_dns_targets(_dby, _dsegs, _da)
        _dbn = {t["probe_domain"]: t for t in _dtg}
        check("names in no segment are given NO ports",
              _dbn["orphan.corp.local"]["ports"] == [],
              str(_dbn["orphan.corp.local"]["ports"]))
        check("no target invents a port",
              all(t["ports"] == [] or t["dns_in_zpa"] for t in _dtg))
        check("matched names inherit their segment's ports",
              443 in _dbn["in-seg.corp.local"]["ports"])
        check("a wide segment range is capped in this mode",
              len(_dbn["in-seg.corp.local"]["ports"]) <= m.DNS_CSV_PORT_CAP,
              str(_dbn["in-seg.corp.local"]["ports"]))
        check("the cap reports what it dropped", _dbs["ports_truncated"] > 0)
        check("--scope does not thin the export",
              len(m.build_dns_targets(_dby, _dsegs,
                                      Args(dns_csv=_dcsv, dns_sample=0,
                                           scope_resolved="sample"))[0])
              == len(_dby))
        check("--dns-sample caps and reports",
              m.build_dns_targets(_dby, _dsegs,
                                  Args(dns_csv=_dcsv,
                                       dns_sample=2))[1]["names_sampled_out"]
              == len(_dby) - 2)
        check("with no segments at all, nothing is probed",
              all(t["ports"] == [] for t in
                  m.build_dns_targets(_dby, [], _da)[0]))

        # The real-world shape: most records match no segment explicitly
        # and are caught by a wildcard segment with a broad port range. A
        # wide range says nothing about what one host listens on, so it
        # must not become a probe list — expand_ports keeps endpoints
        # first, so 1-65535 would yield ports 1, 65535, 2, 3.
        check("discrete ports kept, wide ranges dropped",
              m.dns_specific_ports(
                  {"tcpPortRange": [{"from": "443", "to": "443"},
                                    {"from": "8000", "to": "8100"}]},
                  4)[0] == [443])
        check("a segment of only wide ranges yields no ports",
              m.dns_specific_ports(
                  {"tcpPortRange": [{"from": "1", "to": "65535"}]},
                  4)[0] == [])
        check("dropped ports are counted, not silent",
              m.dns_specific_ports(
                  {"tcpPortRange": [{"from": "8000", "to": "8100"}]},
                  4)[1] == 101)
        _broad = [{"name": "Wild-Broad", "id": "9", "enabled": True,
                   "ipAnchored": True, "domainNames": ["*.corp.local"],
                   "tcpPortRange": [{"from": "1", "to": "65535"}]}]
        _btg, _bbs = m.build_dns_targets(_dby, _broad, _da)
        check("a broad wildcard match is NOT probed",
              all(t["ports"] == [] for t in _btg) and _bbs["probed"] == 0,
              f"probed={_bbs['probed']}")
        check("broad matches are counted and attributed to their segment",
              _bbs["broad_segments"].get("Wild-Broad") == _bbs["matched"],
              str(_bbs["broad_segments"]))
        check("wildcard vs exact matches are counted separately",
              _bbs["matched_wildcard"] == _bbs["matched"]
              and _bbs["matched_exact"] == 0)
        _narrow = [{"name": "Wild-Web", "id": "8", "enabled": True,
                    "ipAnchored": True, "domainNames": ["*.corp.local"],
                    "tcpPortRanges": ["443", "443", "8443", "8443"]}]
        _ntg, _nbs = m.build_dns_targets(_dby, _narrow, _da)
        check("a NARROW wildcard match is still probed",
              _nbs["probed"] == _nbs["matched"] and _nbs["broad_ports"] == 0,
              f"probed={_nbs['probed']} broad={_nbs['broad_ports']}")
        check("range width decides, not whether the match was a wildcard",
              443 in {p for t in _ntg for p in t["ports"]})

        # --dns-ports: an explicit fallback for names the segments cannot
        # supply a port for. The load-bearing warning is that a TCP probe to
        # a UDP service times out on a healthy host, and this tool reads
        # TIMEOUT as "traffic may not be steered".
        check("--dns-ports parses a list",
              m.parse_dns_ports("111,123,161") == [111, 123, 161])
        check("--dns-ports dedupes and tolerates spaces",
              m.parse_dns_ports(" 111, 111 ,123 ") == [111, 123])
        check("--dns-ports empty means none",
              m.parse_dns_ports(None) == [] and m.parse_dns_ports("") == [])
        for _bad, _why in (("111,abc", "non-numeric"), ("0", "zero"),
                           ("70000", "out of range")):
            try:
                m.parse_dns_ports(_bad)
                check(f"--dns-ports rejects {_why}", False, "no exit")
            except SystemExit as _e:
                check(f"--dns-ports rejects {_why}", "--dns-ports" in str(_e))
        check("UDP-primary services are recognised",
              m.udp_primary_in([111, 123, 161])
              == [(123, "NTP"), (161, "SNMP")],
              str(m.udp_primary_in([111, 123, 161])))
        check("111 is not flagged UDP-primary (rpcbind serves TCP too)",
              111 not in m.UDP_PRIMARY_PORTS)
        check("53 is not flagged UDP-primary (DNS serves TCP too)",
              53 not in m.UDP_PRIMARY_PORTS)

        _fb = Args(dns_csv=_dcsv, dns_sample=0, dns_ports="111,123,161")
        _ftg, _fbs = m.build_dns_targets(_dby, _dsegs, _fb)
        _fbn = {t["probe_domain"]: t for t in _ftg}
        check("an unmatched name takes the fallback ports",
              _fbn["orphan.corp.local"]["ports"] == [111, 123, 161],
              str(_fbn["orphan.corp.local"]["ports"]))
        check("a segment with discrete ports is never overridden",
              _fbn["in-seg.corp.local"]["ports"] == [443],
              str(_fbn["in-seg.corp.local"]["ports"]))
        check("fallback usage is counted", _fbs["fallback_used"] >= 1)
        _budp = [{"name": "Wild-Broad", "id": "9", "enabled": True,
                  "ipAnchored": True, "domainNames": ["*.corp.local"],
                  "tcpPortRange": [{"from": "1", "to": "65535"}],
                  "udpPortRange": [{"from": "123", "to": "123"},
                                   {"from": "161", "to": "161"}]}]
        _utg, _ubs = m.build_dns_targets(_dby, _budp, _fb)
        check("a broad match falls back to --dns-ports",
              all(t["ports"] == [111, 123, 161] for t in _utg))
        check("ZPA's own udpPortRange confirms which fallbacks are UDP",
              sorted(_ubs["udp_confirmed"]) == [123, 161],
              str(_ubs["udp_confirmed"]))
        check("without --dns-ports a broad match stays unprobed",
              all(t["ports"] == [] for t in
                  m.build_dns_targets(_dby, _budp, _da)[0]))
        _ust = {"kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0},
                "entries_sampled_out": 0, "ports_truncated": 0}
        _uw = " ".join(m.next_steps(_fb, _ust, [], [], [], None, {"a"},
                                    None, None))
        check("NEXT STEPS warns 123/161 are UDP services",
              "123/tcp (NTP)" in _uw and "161/tcp (SNMP)" in _uw, _uw[:160])
        check("NEXT STEPS says to read those as not-tested",
              "not as failures" in _uw)
        check("no UDP warning for a TCP-only --dns-ports",
              "run over UDP" not in " ".join(m.next_steps(
                  Args(dns_csv=_dcsv, dns_ports="111,443"), _ust, [], [], [],
                  None, {"a"}, None, None)))

        # A general guard for a bug class that has now recurred three
        # times: a summary helper reading args.<newflag> directly, which
        # explodes for any caller that built its namespace before the flag
        # existed. Assert the whole family survives a bare namespace.
        class _Bare:
            phase = "post"
            wildcard_probe = None
            sample_domains = 3
            cidr_hosts = 5
            max_ports = 10
            timeout = 2.0

        _bst = {"kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0},
                "entries_sampled_out": 0, "ports_truncated": 1}
        try:
            m.next_steps(_Bare(), _bst, [], [], [], None, set())
            m.coverage_report(_bst, _Bare(), 1)
            check("summary helpers tolerate a namespace without the new "
                  "flags", True)
        except AttributeError as _e:
            check("summary helpers tolerate a namespace without the new "
                  "flags", False, str(_e))

        check("steered verdict",
              m.dns_verdict_for({"status": "OPEN"}, _dby["in-seg.corp.local"],
                                True) == "STEERED")
        check("enrolled but internal is a gap",
              m.dns_verdict_for({"status": "OPEN"}, _dby["gap.corp.local"],
                                False) == "NOT_STEERED_INTERNAL")
        check("external-only is expected, not a gap",
              m.dns_verdict_for({"status": "OPEN"}, _dby["ext.corp.local"],
                                False) == "NOT_STEERED_EXTERNAL")
        check("a DNS failure outranks every other verdict",
              m.dns_verdict_for({"status": "DNS_FAIL:x"},
                                _dby["gap.corp.local"], True) == "DNS_FAIL")
        check("every verdict has a documented meaning",
              set(m.DNS_VERDICTS) == {"STEERED", "NOT_STEERED_INTERNAL",
                                      "NOT_STEERED_EXTERNAL",
                                      "NOT_STEERED_UNKNOWN", "DNS_FAIL"})

        # run_test must tolerate a namespace built before these flags existed
        # — the failure mode that broke --tenant on export-targets in v1.8.1.
        check("run_test tolerates args without the dns flags",
              not hasattr(Args(), "dns_csv")
              or getattr(Args(), "dns_csv", "missing") is None)

        _drows2 = [{"segment": "Seg-A", "domain": "gap.corp.local",
                    "probe_domain": "gap.corp.local", "protocol": "tcp",
                    "status": "OPEN", "zpa_intercepted": False,
                    "resolved_ip": "192.0.2.10"},
                   {"segment": "Seg-A", "domain": "gap.corp.local",
                    "probe_domain": "gap.corp.local", "protocol": "tcp",
                    "status": "OPEN", "zpa_intercepted": False,
                    "resolved_ip": "192.0.2.10"},
                   {"segment": "(not in any ZPA segment)",
                    "domain": "orphan.corp.local",
                    "probe_domain": "orphan.corp.local", "protocol": "tcp",
                    "status": "NO_TCP_PORTS", "zpa_intercepted": False,
                    "resolved_ip": "192.0.2.99"},
                   {"segment": "Seg-A", "domain": "in-seg.corp.local",
                    "probe_domain": "in-seg.corp.local", "protocol": "tcp",
                    "status": "OPEN", "zpa_intercepted": True,
                    "resolved_ip": "100.64.1.5"}]
        m.annotate_dns_rows(_drows2, _dtg)
        _dx = m.dns_stats(_drows2)
        check("cross-reference counts names, not probes", _dx["names"] == 3,
              _dx["names"])
        check("the steering gap is identified",
              _dx["steering_gap"] == ["gap.corp.local"],
              str(_dx["steering_gap"]))
        check("the enrolment gap is identified",
              _dx["enrolment_gap"] == ["orphan.corp.local"],
              str(_dx["enrolment_gap"]))
        check("dns_stats is None without the export",
              m.dns_stats([{"status": "OPEN"}]) is None)

        _dhtml = os.path.join(_dwork, "d.html")
        m.write_html_report(_dhtml, [("post_sample_d.csv", _drows2,
                                      {"phase": "post", "hostname": "h",
                                       "zcc": {"state": "running",
                                               "processes_found": []}})])
        _dh = open(_dhtml, encoding="utf-8").read()
        check("report renders the DNS tiles",
              'data-tilefilter="dnssteered"' in _dh
              and 'data-tilefilter="dnsgap"' in _dh
              and 'data-tilefilter="dnsnotinzpa"' in _dh)
        check("report rows carry the DNS predicates' attributes",
              'data-dnsv="STEERED"' in _dh and "data-dnszpa=" in _dh)
        check("report JS reads data-dnsv",
              "tr.getAttribute('data-dnsv')" in _dh)
        check("DNS columns appear in the report table",
              ">dns_verdict<" in _dh)
        _plain = os.path.join(_dwork, "p.html")
        m.write_html_report(_plain, [("post_sample_p.csv",
                                      [{"segment": "S", "domain": "d.corp",
                                        "probe_domain": "d.corp",
                                        "status": "OPEN",
                                        "protocol": "tcp"}], {})])
        check("no DNS tiles or columns on a non-DNS run",
              'data-tilefilter="dnssteered"'
              not in open(_plain, encoding="utf-8").read()
              and ">dns_verdict<" not in open(_plain, encoding="utf-8").read())

        _dsteps = " ".join(m.next_steps(
            Args(phase="post"),
            {"kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0},
             "entries_sampled_out": 0, "ports_truncated": 0},
            [], [], [], None, {"a"}, None, _dx))
        check("NEXT STEPS raises the steering gap",
              "enrolled in a ZPA segment" in _dsteps, _dsteps[:160])
        check("NEXT STEPS raises the enrolment gap",
              "in no ZPA segment" in _dsteps)
        check("no DNS steps when the export was not used",
              "ZPA segment but resolved" not in " ".join(m.next_steps(
                  Args(phase="post"),
                  {"kinds": {"fqdn": 1, "ip": 0, "cidr": 0, "wildcard": 0},
                   "entries_sampled_out": 0, "ports_truncated": 0},
                  [], [], [], None, {"a"}, None, None)))

        # the cap message must name the cap that actually bound
        _cov = " ".join(m.coverage_report(
            {"kinds": {"fqdn": 2, "ip": 0, "cidr": 0, "wildcard": 0},
             "entries_sampled_out": 0, "ports_truncated": 90},
            Args(dns_csv=_dcsv), 10))
        check("the DNS port cap is named honestly in coverage",
              "--dns-csv caps ports" in _cov and "--scope full" not in _cov,
              _cov[-140:])
        _cov2 = " ".join(m.coverage_report(
            {"kinds": {"fqdn": 2, "ip": 0, "cidr": 0, "wildcard": 0},
             "entries_sampled_out": 0, "ports_truncated": 90},
            Args(dns_csv=None), 10))
        check("a normal run still points at --max-ports",
              "--max-ports" in _cov2, _cov2[-140:])
    finally:
        shutil.rmtree(_dwork, ignore_errors=True)

    # ------------------------------------------------------- L7 verification
    # A run can report "249/249 TCP REACHABLE, 0 FAILING PROBES" while most
    # of those probes had no application on the other end: through ZPA the
    # connection is accepted locally by Client Connector. These assert the
    # L7 result is measured with its own budget, classified honestly, and
    # actually reaches the summary.
    print("\nL7 verification")
    check("verified prefixes are TLS/HTTP only",
          m.l7_verified("TLS:TLSv1.3") and m.l7_verified("HTTP:301")
          and not m.l7_verified("OPEN_NO_L7_DATA")
          and not m.l7_verified("OPEN_NON_HTTP")
          and not m.l7_verified("L7_ERROR:TimeoutError")
          and not m.l7_verified(""))
    check("the two silent outcomes are separate statuses",
          "OPEN_NO_L7_DATA" in m.L7_MEANINGS
          and "OPEN_NON_HTTP" in m.L7_MEANINGS)

    _a = Args(timeout=2.0, l7_timeout=None)
    check("l7 budget defaults to a multiple of --timeout",
          m.l7_timeout_for(_a) == min(m.L7_TIMEOUT_CEILING,
                                      max(m.L7_TIMEOUT_FLOOR,
                                          2.0 * m.L7_TIMEOUT_FACTOR)),
          str(m.l7_timeout_for(_a)))
    check("derived l7 budget is capped",
          m.l7_timeout_for(Args(timeout=60.0, l7_timeout=None))
          == m.L7_TIMEOUT_CEILING)
    check("an explicit l7 budget is not capped",
          m.l7_timeout_for(Args(timeout=2.0, l7_timeout=45.0)) == 45.0)
    check("l7 budget exceeds the connect budget",
          m.l7_timeout_for(Args(timeout=2.0, l7_timeout=None)) > 2.0)
    check("l7 budget has a floor",
          m.l7_timeout_for(Args(timeout=0.2, l7_timeout=None))
          == m.L7_TIMEOUT_FLOOR)
    check("explicit --l7-timeout wins",
          m.l7_timeout_for(Args(timeout=2.0, l7_timeout=30.0)) == 30.0)
    _a = Args(timeout=2.0, l7_timeout=None)
    m.l7_timeout_for(_a)
    _a.timeout = 99.0
    check("l7 budget is resolved once and cached", m.l7_timeout_for(_a) == 8.0)
    try:
        m.l7_timeout_for(Args(timeout=2.0, l7_timeout=0))
        check("non-positive --l7-timeout rejected", False, "no exit")
    except SystemExit as e:
        check("non-positive --l7-timeout rejected",
              "greater than 0" in str(e), str(e))

    def _l7row(seg, l7, status="OPEN"):
        return {"segment": seg, "status": status, "l7_result": l7,
                "protocol": "tcp", "port": 443, "entry_kind": "fqdn",
                "domain": "d.corp.local", "probe_domain": "d.corp.local",
                "resolved_ip": "100.64.1.1", "zpa_intercepted": True,
                "enabled": True, "ip_anchored": True, "attempts": 1,
                "latency_ms": 150.0}

    _rows7 = ([_l7row("A", "TLS:TLSv1.3")] * 47
              + [_l7row("A", "HTTP:301")] * 45
              + [_l7row("B", "TLS:TLSv1.2")] * 15
              + [_l7row("A", "OPEN_NO_L7_DATA")] * 112
              + [_l7row("B", "L7_ERROR:TimeoutError")] * 30)
    _s7 = m.l7_stats(_rows7)
    check("l7_stats counts probes that ran", _s7["probed"] == 249)
    check("l7_stats counts verified", _s7["verified"] == 107)
    check("l7_stats counts unverified", _s7["unverified"] == 142)
    check("l7_stats percentage", _s7["pct_verified"] == 43.0)
    check("l7_stats breakdown sums to probed",
          sum(_s7["breakdown"].values()) == 249)
    check("l7_stats collapses L7_ERROR detail",
          _s7["breakdown"].get("L7_ERROR") == 30, str(_s7["breakdown"]))
    check("l7_stats attributes unverified per segment",
          dict((k, v) for k, v, _ in _s7["unverified_by_segment"])
          == {"A": 112, "B": 30}, str(_s7["unverified_by_segment"]))
    check("l7_stats is None when --l7 was off",
          m.l7_stats([_l7row("A", "")]) is None)
    check("failed probes are outside the L7 denominator",
          m.l7_stats(_rows7 + [_l7row("A", "", "TIMEOUT")])["probed"] == 249)

    _st = {"kinds": {"fqdn": 3, "ip": 0, "cidr": 0, "wildcard": 0},
           "entries_sampled_out": 0, "ports_truncated": 0}
    _steps = " ".join(m.next_steps(Args(phase="post", l7=True), _st, [], [],
                                   [], None, {"a"}, _s7))
    check("NEXT STEPS reports the unverified ratio", "142 of 249" in _steps,
          _steps[:200])
    check("NEXT STEPS explains OPEN is established locally",
          "Client Connector locally" in _steps)
    check("NEXT STEPS points at --l7-timeout for L7 errors",
          "--l7-timeout" in _steps and "30 of them" in _steps, _steps[:300])
    check("no L7 step when everything verified",
          "application response" not in " ".join(m.next_steps(
              Args(phase="post", l7=True), _st, [], [], [], None, {"a"},
              m.l7_stats([_l7row("A", "TLS:TLSv1.3")]))))
    check("no L7 step when --l7 was off",
          "application response" not in " ".join(m.next_steps(
              Args(phase="post"), _st, [], [], [], None, {"a"}, None)))

    # The L7 result was already in the CSV before this; what was missing was
    # any path from it to a headline. Assert it reaches the report.
    _hdir = tempfile.mkdtemp(prefix="zpa-validate-l7-")
    try:
        _hp = os.path.join(_hdir, "l7.html")
        m.write_html_report(_hp, [("post_sample_h.csv", _rows7,
                                   {"phase": "post", "hostname": "h",
                                    "zcc": {"state": "running",
                                            "processes_found": []}})])
        _hh = open(_hp, encoding="utf-8").read()
        check("report renders an L7 verified tile",
              ">107/249<" in _hh and 'data-tilefilter="l7verified"' in _hh)
        check("report renders a no-app-response tile",
              'data-tilefilter="l7unverified"' in _hh
              and '<div class="n bad">142</div>' in _hh)
        check("report rows carry data-l7",
              'data-l7="OPEN_NO_L7_DATA"' in _hh
              and 'data-l7="TLS:TLSv1.3"' in _hh)
        check("report JS reads data-l7",
              "tr.getAttribute('data-l7')" in _hh
              and "l7unverified: function" in _hh)
    finally:
        shutil.rmtree(_hdir, ignore_errors=True)

    # -------------------------------------------------- latency measurement
    # socket.create_connection() resolves inside the region it times, so DNS
    # latency was reported as connect latency and --timeout bounded only the
    # connect half of the call.
    print("\nLatency measurement")
    _srv = socket.socket()
    _srv.bind(("127.0.0.1", 0))
    _srv.listen(64)
    _lport = _srv.getsockname()[1]

    def _drain():
        while True:
            try:
                _c, _ = _srv.accept()
            except OSError:
                return
            _c.close()

    threading.Thread(target=_drain, daemon=True).start()
    _real_gai = socket.getaddrinfo

    def _slow_gai(host, port, *a, **k):
        if host == "slow.validate.test":
            time.sleep(1.0)
            return _real_gai("127.0.0.1", port, *a, **k)
        return _real_gai(host, port, *a, **k)

    socket.getaddrinfo = _slow_gai
    try:
        _t0 = time.monotonic()
        _stat, _lat = m.tcp_probe("slow.validate.test", _lport, 2.0)
        _wall = (time.monotonic() - _t0) * 1000
    finally:
        socket.getaddrinfo = _real_gai
    check("connect through a slow resolver still OPEN", _stat == "OPEN", _stat)
    check("the slow resolve really ran", _wall > 900, f"{_wall:.0f}ms")
    check("reported latency excludes resolution",
          _lat is not None and _lat < 200,
          f"latency={_lat}ms wall={_wall:.0f}ms")
    check("plain connect still OPEN",
          m.tcp_probe("127.0.0.1", _lport, 2.0)[0] == "OPEN")
    _cl = socket.socket()
    _cl.bind(("127.0.0.1", 0))
    _cport = _cl.getsockname()[1]
    _cl.close()
    check("refusal still REFUSED",
          m.tcp_probe("127.0.0.1", _cport, 1.0)[0] == "REFUSED")
    check("resolution failure reported as ERROR:",
          m.tcp_probe("no-such-host.invalid", 443, 1.0)[0].startswith("ERROR:"))
    check("failures carry no latency",
          m.tcp_probe("127.0.0.1", _cport, 1.0)[1] is None)
    if os.path.isdir("/proc/self/fd"):
        time.sleep(0.2)
        _b = len(os.listdir("/proc/self/fd"))
        for _ in range(40):
            m.tcp_probe("127.0.0.1", _lport, 1.0)
        time.sleep(0.2)
        check("no descriptor leak across 40 probes",
              len(os.listdir("/proc/self/fd")) - _b <= 2,
              f"{_b} -> {len(os.listdir('/proc/self/fd'))}")
    _srv.close()

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
        # Attributes are parsed generically rather than matched in a fixed
        # order: pinning the order meant adding one data-* attribute to the
        # renderer silently reduced this to zero rows, and every predicate
        # check below then compared 0 against 0 and passed.
        _rows = [dict(re.findall(r'data-([a-z0-9]+)="([^"]*)"', _tag))
                 for _tag in re.findall(r"<tr ([^>]*)>", _h)]
        _tiles = dict(re.findall(
            r'<div class="tile" data-tilefilter="([a-z0-9]+)"[^>]*>'
            r'<div class="n [^"]*">([^<]*)</div>', _h))
        check("every row carries machine-readable state",
              len(_rows) == len(rows), f"{len(_rows)} of {len(rows)}")
        check("every row exposes status/proto/steered/l7",
              all({"status", "proto", "steered", "l7"} <= set(d)
                  for d in _rows),
              str(sorted(_rows[0])) if _rows else "no rows")
        # The L7 pair renders only when the L7 step produced results, so
        # which set is expected depends on this run. Asserting the pair
        # unconditionally would fail on any run whose probes never opened.
        _l7_seen = any(d.get("l7") for d in _rows)
        _want_tiles = {"reachable", "failing", "flaky", "dnsfail", "steered"}
        if _l7_seen:
            _want_tiles |= {"l7verified", "l7unverified"}
        check("exactly the applicable filterable tiles are present",
              set(_tiles) == _want_tiles,
              f"got {sorted(_tiles)} want {sorted(_want_tiles)}")
        check("L7 tiles are omitted when the L7 step produced nothing",
              _l7_seen or not ({"l7verified", "l7unverified"} & set(_tiles)))

        def _ok(s):
            return s in ("OPEN", "OPEN_FLAKY")

        def _tcp(d):
            return d["proto"] == "tcp" and d["status"] != "NO_TCP_PORTS"

        def _l7ran(d):
            return _ok(d["status"]) and d.get("l7", "") != ""

        def _l7ok(d):
            return d.get("l7", "").startswith(("TLS:", "HTTP:"))

        _pred = {
            "reachable": lambda d: _tcp(d) and _ok(d["status"]),
            "failing": lambda d: _tcp(d) and not _ok(d["status"]),
            "flaky": lambda d: d["proto"] == "tcp"
            and d["status"] == "OPEN_FLAKY",
            "dnsfail": lambda d: d["status"].startswith("DNS_FAIL"),
            "steered": lambda d: d["steered"] == "True",
            "l7verified": lambda d: _l7ran(d) and _l7ok(d),
            "l7unverified": lambda d: _l7ran(d) and not _l7ok(d),
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
