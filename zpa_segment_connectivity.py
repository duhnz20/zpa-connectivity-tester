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

Windows only. Standard library only, no pip
install. Python 3.9+.
  Windows:  py -3 zpa_segment_connectivity.py test --phase pre
  Windows:  py -3 zpa_segment_connectivity.py test --phase pre

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

  1. ZPA steering is FQDN-driven: Client Connector holds a
     local app-list of names, and a match yields an address inside the
     tenant's synthetic range (Zscaler's default is 100.64.0.0/10, but it
     is configurable and often narrowed — set --synthetic-net). IP- and CIDR-defined entries produce no synthetic
     IP, so `zpa_intercepted` is N/A for them — and a successful post-run
     connect to an IP/CIDR entry does NOT by itself prove the traffic went
     through ZPA rather than direct. Confirm those segments from the ZPA
     admin portal's access logs, not from this script alone.
  2. Negative DNS cache entries created during the pre run can persist and
     mask steering in the post run. Use --flush-dns on post runs; if an
     enrolled domain still fails to resolve, restart ZCC before treating
     it as a real failure.
"""

import argparse
import concurrent.futures
import csv
import ctypes
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
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
# Guarded so the module still IMPORTS off Windows: main() must be reached to
# print the clean "this tool requires Windows" message, and it cannot be
# reached if the import itself dies with ModuleNotFoundError.
try:
    import winreg
    from ctypes import wintypes
except (ImportError, ValueError):
    winreg = None
    wintypes = None
from datetime import datetime, timezone

SCRIPT_VERSION = "2.1.0-windows"
DEFAULT_API_BASE = "https://api.zsapi.net"
OAUTH_AUDIENCE = "https://api.zscaler.com"
# Zscaler's documented default synthetic range. It is TENANT-CONFIGURABLE:
# deployments commonly narrow it (e.g. 100.64.0.0/16), so this is only a
# fallback — set --synthetic-net, or store it per tenant.
#
# Getting this wrong is not cosmetic. 100.64.0.0/10 is the RFC 6598
# carrier-grade NAT range, so on a hotel or mobile network an ISP-assigned
# CGNAT address falls inside the default and would be reported as
# ZPA-steered — a false "ZPA IS STEERING" verdict, which is the headline
# conclusion of the whole run.
DEFAULT_SYNTHETIC_NET = "100.64.0.0/10"
ZPA_SYNTHETIC_NET = ipaddress.ip_network(DEFAULT_SYNTHETIC_NET)


def parse_synthetic_net(value):
    """Validate a synthetic-range CIDR, or exit with a usable message."""
    try:
        net = ipaddress.ip_network(str(value), strict=False)
    except ValueError as e:
        sys.exit(f"ERROR: --synthetic-net {value!r} is not a valid CIDR: {e}")
    if net.version != 4:
        sys.exit("ERROR: --synthetic-net must be IPv4; ZPA synthetic "
                 "addresses are IPv4.")
    return net


def synthetic_net_for(args):
    """The tenant's synthetic range, resolved once and cached on args."""
    cached = getattr(args, "synthetic_net_resolved", None)
    if cached is not None:
        return cached
    raw = getattr(args, "synthetic_net", None) or DEFAULT_SYNTHETIC_NET
    net = parse_synthetic_net(raw)
    args.synthetic_net_resolved = net
    return net


# The L7 step gets its own, larger budget than --timeout. See l7_timeout_for.
# The ceiling bounds only the *derived* default — an explicit --l7-timeout is
# honoured above it — so a generous --timeout cannot extrapolate into a
# per-probe wait long enough to dominate the run.
L7_TIMEOUT_FACTOR = 4
L7_TIMEOUT_FLOOR = 5.0
L7_TIMEOUT_CEILING = 15.0

# Floor for the plaintext attempt once the TLS attempt has eaten into the
# shared budget. Kept generous: a peer that fails TLS fast but answers HTTP
# slowly must not be flipped from HTTP:xxx to L7_ERROR by a stingy
# remainder. --l7-timeout is the remedy when it is not enough.
L7_MIN_SECOND_ATTEMPT = 1.0

# An L7 result that proves an application answered. Everything else on an
# OPEN port — no data, non-HTTP bytes, or an L7 error — means TCP reachability
# was established without demonstrating that anything is serving.
L7_VERIFIED_PREFIXES = ("TLS:", "HTTP:")

# What each non-verifying L7 outcome actually implies, for the summary.
L7_MEANINGS = {
    "OPEN_NO_L7_DATA": "accepted the connection then sent nothing — "
                       "typically nothing serving behind the App Connector",
    "OPEN_NON_HTTP": "sent bytes that are neither TLS nor HTTP — a live "
                     "service this probe cannot speak to",
}
L7_ERROR_MEANING = ("the L7 exchange failed outright — raise --l7-timeout "
                    "before reading these as application faults")

PAGE_SIZE = 500
FULL_CIDR_HOST_CAP = 65536   # hard memory guard even in full scope
CONFIRM_THRESHOLD = 2000     # confirm before runs bigger than this
MAX_RUN_SECONDS = 12 * 3600  # refuse runs whose worst case exceeds this

# --------------------------------------------------------------------------
# Windows environment
# --------------------------------------------------------------------------
#
# Everything here asks Windows directly rather than inferring. Four
# independent signals, because any one of them can mislead on its own:
#
#   services + processes  -> is Client Connector installed, and running?
#   Find-NetRoute         -> does a path into the ZPA synthetic range exist
#                            at the OS level, and through which adapter?
#   NRPT policy           -> is split DNS in force? ZCC drives per-domain
#                            resolution through the Name Resolution Policy
#                            Table, the signal that a name will be resolved
#                            by ZPA rather than by the LAN resolver.
#   WinHTTP / WinINET     -> a proxy in the path changes what a connect means
#
# The routing signal is the one that pays for itself: it is available before
# a single probe runs, so a run can say "Private Access is off" instead of
# collecting a directory of false negatives and calling them failures.

# --------------------------------------------------------------------------
# Native Windows bindings
# --------------------------------------------------------------------------
#
# Everything below asks Windows through winreg and ctypes rather than by
# spawning PowerShell. That is not a micro-optimisation: measured on this
# build, the four environment probes cost 3,587ms via PowerShell and 32ms
# natively, because each `powershell -NoProfile -Command` costs ~175ms of
# process startup before it does any work, and the probes made nine of them.
#
# Every binding below declares argtypes and restype. This is mandatory, not
# tidiness: without them ctypes assumes a 32-bit int return and truncates
# 64-bit HANDLEs, which fails silently or raises OverflowError. That exact
# bug has now been hit three times in this codebase, so it is asserted in
# the validator rather than left to discipline.

# Loaded only on Windows so the module stays importable elsewhere; every
# caller is reached only after main()'s platform guard has passed.
if wintypes is not None:
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)
    _iph = ctypes.WinDLL("iphlpapi", use_last_error=True)

    SC_MANAGER_CONNECT = 0x0001
    SERVICE_QUERY_STATUS = 0x0004
    SC_STATUS_PROCESS_INFO = 0
    TH32CS_SNAPPROCESS = 0x00000002
    SERVICE_STATES = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
                      4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING",
                      7: "PAUSED"}


    class _SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [("dwServiceType", wintypes.DWORD),
                    ("dwCurrentState", wintypes.DWORD),
                    ("dwControlsAccepted", wintypes.DWORD),
                    ("dwWin32ExitCode", wintypes.DWORD),
                    ("dwServiceSpecificExitCode", wintypes.DWORD),
                    ("dwCheckPoint", wintypes.DWORD),
                    ("dwWaitHint", wintypes.DWORD),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwServiceFlags", wintypes.DWORD)]


    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]


    class _MIB_IPFORWARDROW(ctypes.Structure):
        """Every field is a DWORD; only NextHop and IfIndex are read."""
        _fields_ = [(n, wintypes.DWORD) for n in (
            "dwForwardDest", "dwForwardMask", "dwForwardPolicy",
            "dwForwardNextHop", "dwForwardIfIndex", "dwForwardType",
            "dwForwardProto", "dwForwardAge", "dwForwardNextHopAS",
            "dwForwardMetric1", "dwForwardMetric2", "dwForwardMetric3",
            "dwForwardMetric4", "dwForwardMetric5")]


    class _NET_LUID(ctypes.Structure):
        _fields_ = [("Value", ctypes.c_ulonglong)]


    class _WINHTTP_PROXY_INFO(ctypes.Structure):
        _fields_ = [("dwAccessType", wintypes.DWORD),
                    ("lpszProxy", wintypes.LPWSTR),
                    ("lpszProxyBypass", wintypes.LPWSTR)]


    _adv.OpenSCManagerW.restype = wintypes.HANDLE
    _adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    wintypes.DWORD]
    _adv.OpenServiceW.restype = wintypes.HANDLE
    _adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                  wintypes.DWORD]
    _adv.QueryServiceStatusEx.restype = wintypes.BOOL
    _adv.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                          ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
    _adv.CloseServiceHandle.restype = wintypes.BOOL
    _adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]

    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.Process32FirstW.restype = wintypes.BOOL
    _k32.Process32FirstW.argtypes = [wintypes.HANDLE,
                                     ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.Process32NextW.restype = wintypes.BOOL
    _k32.Process32NextW.argtypes = [wintypes.HANDLE,
                                    ctypes.POINTER(_PROCESSENTRY32W)]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    _iph.GetBestRoute.restype = wintypes.DWORD
    _iph.GetBestRoute.argtypes = [wintypes.DWORD, wintypes.DWORD,
                                  ctypes.POINTER(_MIB_IPFORWARDROW)]
    _iph.ConvertInterfaceIndexToLuid.restype = wintypes.ULONG
    _iph.ConvertInterfaceIndexToLuid.argtypes = [wintypes.ULONG,
                                                 ctypes.POINTER(_NET_LUID)]
    _iph.ConvertInterfaceLuidToAlias.restype = wintypes.ULONG
    _iph.ConvertInterfaceLuidToAlias.argtypes = [ctypes.POINTER(_NET_LUID),
                                                 ctypes.c_wchar_p,
                                                 ctypes.c_size_t]


def _reg_values(root, path, wanted, view64=False):
    """{name: value} for `wanted` under one key; missing names are omitted."""
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else 0)
    out = {}
    try:
        key = winreg.OpenKey(root, path, 0, access)
    except OSError:
        return out
    try:
        for name in wanted:
            try:
                out[name] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                pass
    finally:
        key.Close()
    return out


def _reg_subkeys(root, path, view64=False):
    """Subkey names under a path, or [] if the path does not exist.

    view64 forces the 64-bit view. Without it a 32-bit Python is redirected
    into Wow6432Node and a 64-bit-installed ZCC is invisible.
    """
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else 0)
    try:
        key = winreg.OpenKey(root, path, 0, access)
    except OSError:
        return []
    try:
        return [winreg.EnumKey(key, i)
                for i in range(winreg.QueryInfoKey(key)[0])]
    except OSError:
        return []
    finally:
        key.Close()


def service_state(name):
    """(exists, state) for a Windows service. Needs no elevation.

    SC_MANAGER_CONNECT + SERVICE_QUERY_STATUS are read-only rights granted
    to ordinary users, so this works from an unprivileged shell. 'exists'
    is reported separately from 'state' because an installed-but-stopped
    service and an absent one call for different remedies.
    """
    scm = _adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return (False, "")
    try:
        handle = _adv.OpenServiceW(scm, name, SERVICE_QUERY_STATUS)
        if not handle:
            return (False, "")
        try:
            status = _SERVICE_STATUS_PROCESS()
            needed = wintypes.DWORD()
            if not _adv.QueryServiceStatusEx(
                    handle, SC_STATUS_PROCESS_INFO, ctypes.byref(status),
                    ctypes.sizeof(status), ctypes.byref(needed)):
                return (True, "unknown")
            return (True, SERVICE_STATES.get(status.dwCurrentState,
                                             str(status.dwCurrentState)))
        finally:
            _adv.CloseServiceHandle(handle)
    finally:
        _adv.CloseServiceHandle(scm)


def running_processes(substrings):
    """Process image names matching any substring, case-insensitively."""
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value or not snap:
        return []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        found = set()
        if not _k32.Process32FirstW(snap, ctypes.byref(entry)):
            return []
        subs = [x.lower() for x in substrings]
        while True:
            name = entry.szExeFile
            low = name.lower()
            if any(x in low for x in subs):
                found.add(name)
            if not _k32.Process32NextW(snap, ctypes.byref(entry)):
                break
        return sorted(found)
    finally:
        _k32.CloseHandle(snap)


def best_route(dest_ip):
    """(if_index, next_hop, alias) the stack would use for dest_ip.

    GetBestRoute resolves what would actually happen to a packet, which is
    the same question `route print` answers but without parsing text. It is
    IPv4-only, which matches the tool: ZPA synthetic addresses are IPv4.
    Returns (0, "", "") when no route exists.
    """
    try:
        dest = struct.unpack("<L", socket.inet_aton(dest_ip))[0]
    except (OSError, struct.error):
        return (0, "", "")
    row = _MIB_IPFORWARDROW()
    if _iph.GetBestRoute(dest, 0, ctypes.byref(row)) != 0:
        return (0, "", "")
    idx = int(row.dwForwardIfIndex)
    nh = socket.inet_ntoa(struct.pack("<L", row.dwForwardNextHop))
    alias = ""
    luid = _NET_LUID()
    if _iph.ConvertInterfaceIndexToLuid(idx, ctypes.byref(luid)) == 0:
        buf = ctypes.create_unicode_buffer(256)
        if _iph.ConvertInterfaceLuidToAlias(ctypes.byref(luid), buf, 256) == 0:
            alias = buf.value
    return (idx, nh, alias)


WIN_CMD_TIMEOUT = 25

# Service names, not just process names. A service can be installed and
# stopped, which is a different state from absent — and the difference is
# exactly what the operator needs to be told.
ZCC_SERVICE_HINTS = ["ZSAService", "ZSATunnel", "ZSAUpdater", "ZSAMonitor"]
ZCC_PROCESS_HINTS = ["ZSATray", "ZSAService", "ZSATunnel", "ZSAUpdater"]

# ZCC's virtual adapter. Its description varies by release, so match loosely
# and treat the routing interface, not the name, as the real evidence.
ZCC_ADAPTER_HINTS = ["zscaler", "zsatunnel"]

_ENV_CACHE = {}


def _env(key, producer, refresh=False):
    """Memoize an environment probe for the life of the run.

    preflight and the run summary ask the same questions; without this the
    answers could differ between them, which is worse than either answer.
    """
    if refresh or key not in _ENV_CACHE:
        _ENV_CACHE[key] = producer()
    return _ENV_CACHE[key]


def _detect_zcc_uncached():
    """Client Connector state from the service registry, the SCM and the
    process table — no subprocess.

    'installed but not running' is reported distinctly from 'not detected',
    because the remedy differs: start the service versus install the client.
    """
    info = {"platform": "Windows",
            "platform_release": platform.release(),
            "services": [], "services_running": [],
            "processes_found": [], "installed_version": "",
            "signals": [], "state": "not_detected"}

    # Service names come from the registry (which lists every installed
    # service regardless of state); live state comes from the SCM.
    names = [n for n in _reg_subkeys(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        if "zsa" in n.lower() or "zscaler" in n.lower()]
    for name in sorted(names):
        exists, state = service_state(name)
        if not exists:
            continue
        info["services"].append(f"{name}={state}")
        if state == "RUNNING":
            info["services_running"].append(name)
    if info["services"]:
        info["signals"].append("service")

    info["processes_found"] = running_processes(ZCC_PROCESS_HINTS)
    if info["processes_found"]:
        info["signals"].append("process")

    for hive in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows"
                 r"\CurrentVersion\Uninstall"):
        for sub_name in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, hive,
                                     view64=True):
            vals = _reg_values(winreg.HKEY_LOCAL_MACHINE,
                               hive + "\\" + sub_name,
                               ("DisplayName", "DisplayVersion"), view64=True)
            if "zscaler" in str(vals.get("DisplayName", "")).lower():
                info["installed_version"] = str(vals.get("DisplayVersion", ""))
                info["signals"].append("registry")
                break
        if info["installed_version"]:
            break

    if info["services_running"] or info["processes_found"]:
        info["state"] = "running"
    elif info["services"] or info["installed_version"]:
        info["state"] = "installed_not_running"
    return info


def _windows_steering_path_uncached(net=None):
    """Ask the routing table whether a path into the synthetic range exists.

    GetBestRoute resolves what the stack would actually do with a packet to
    that address, rather than guessing from the adapter list. Keeping this
    independent of the synthetic-IP observation lets a negative result say
    *why*: no adapter claims the range at all, versus one does but no name
    resolved into it.
    """
    net = net or ZPA_SYNTHETIC_NET
    probe_ip = str(next(net.hosts()))
    # No adapter_description key: the previous implementation declared one
    # and never populated it, so every consumer read an empty string that
    # looked like an answer.
    info = {"checked": False, "probe_ip": probe_ip, "interface": "",
            "interface_index": "", "next_hop": "", "via_tunnel": None}
    idx, next_hop, alias = best_route(probe_ip)
    if not idx:
        return info
    info["checked"] = True
    info["interface_index"] = str(idx)
    info["interface"] = alias
    # 0.0.0.0 as a next hop means on-link, which is not a useful thing to
    # print, so it is normalised away rather than shown as an address.
    info["next_hop"] = "" if next_hop == "0.0.0.0" else next_hop
    blob = alias.lower()
    info["via_tunnel"] = any(h in blob for h in ZCC_ADAPTER_HINTS)
    return info


def _windows_dns_config_uncached():
    """Resolvers plus NRPT rules — the Windows split-DNS signal.

    ZCC drives per-domain resolution through the Name Resolution Policy
    Table, so NRPT rules are the authoritative signal for whether a name
    will be resolved by ZPA, and their absence on an enrolled host is worth
    seeing. Both live in the registry, so neither needs a subprocess.

    The policy lives under two possible keys: Group Policy writes the
    Policies hive, while a locally-applied policy (which is how ZCC applies
    it) writes the Dnscache one. Both are read.
    """
    info = {"resolvers": 0, "servers": [], "nrpt_rules": 0,
            "nrpt_namespaces": []}

    servers = []
    base = (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            r"\Interfaces")
    # Only interfaces that currently hold an address are reported. The
    # registry keeps a key for every adapter the machine has ever had, so
    # scraping all of them surfaces resolvers from disconnected VPNs and
    # removed NICs as if they were live.
    for guid in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
        vals = _reg_values(winreg.HKEY_LOCAL_MACHINE, base + "\\" + guid,
                           ("NameServer", "DhcpNameServer", "IPAddress",
                            "DhcpIPAddress"))
        addrs = vals.get("IPAddress") or vals.get("DhcpIPAddress") or ""
        live = [a for a in (addrs if isinstance(addrs, (list, tuple))
                            else [addrs]) if a and str(a) != "0.0.0.0"]
        if not live:
            continue
        for key in ("NameServer", "DhcpNameServer"):
            raw = vals.get(key)
            if raw:
                servers.extend(str(raw).replace(",", " ").split())
    info["servers"] = sorted(set(servers))
    info["resolvers"] = len(info["servers"])

    seen = []
    for policy in (r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                   r"\DnsPolicyConfig",
                   r"SYSTEM\CurrentControlSet\Services\Dnscache"
                   r"\Parameters\DnsPolicyConfig"):
        for rule in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, policy):
            vals = _reg_values(winreg.HKEY_LOCAL_MACHINE,
                               policy + "\\" + rule, ("Name",))
            raw = vals.get("Name")
            if raw is None:
                continue
            seen.append(rule)
            for ns in (raw if isinstance(raw, (list, tuple)) else [raw]):
                if ns and ns not in info["nrpt_namespaces"]:
                    info["nrpt_namespaces"].append(str(ns))
    info["nrpt_rules"] = len(seen)
    info["nrpt_namespaces"] = info["nrpt_namespaces"][:8]
    return info


def _windows_proxy_config_uncached():
    """WinINET (per-user) and WinHTTP (system) proxy settings.

    A proxy in the path changes what a successful connect means, so both
    are recorded rather than assuming direct egress. WinINET is a registry
    read; WinHTTP is read through its own API rather than by parsing the
    REG_BINARY blob that backs it, which has no documented layout.
    """
    info = {"proxy_enabled": False, "proxy_server": "", "autoconfig_url": "",
            "winhttp": ""}
    vals = _reg_values(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ("ProxyEnable", "ProxyServer", "AutoConfigURL"))
    info["proxy_enabled"] = bool(vals.get("ProxyEnable"))
    info["proxy_server"] = str(vals.get("ProxyServer") or "")
    info["autoconfig_url"] = str(vals.get("AutoConfigURL") or "")

    try:
        winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
        winhttp.WinHttpGetDefaultProxyConfiguration.restype = wintypes.BOOL
        winhttp.WinHttpGetDefaultProxyConfiguration.argtypes = [
            ctypes.POINTER(_WINHTTP_PROXY_INFO)]
        cfg = _WINHTTP_PROXY_INFO()
        if winhttp.WinHttpGetDefaultProxyConfiguration(ctypes.byref(cfg)):
            if cfg.dwAccessType == 3 and cfg.lpszProxy:
                info["winhttp"] = f"proxy {cfg.lpszProxy}"
            else:
                info["winhttp"] = "direct access (no proxy server)"
    except (OSError, AttributeError, ValueError):
        info["winhttp"] = "unavailable"
    return info


def detect_zcc(refresh=False):
    return _env("zcc", _detect_zcc_uncached, refresh)


def windows_steering_path(net=None, refresh=False):
    # Keyed by range: a cached answer computed for a different synthetic
    # range would silently answer the wrong question.
    return _env(f"steer:{net or ZPA_SYNTHETIC_NET}",
                lambda: _windows_steering_path_uncached(net), refresh)


def windows_dns_config(refresh=False):
    return _env("dns", _windows_dns_config_uncached, refresh)


def windows_proxy_config(refresh=False):
    return _env("proxy", _windows_proxy_config_uncached, refresh)


# Windows power-request flags. A long run can outlast the idle-sleep timer,
# and sleeping mid-run fails every in-flight probe — which this tool would
# then report as unreachability. A thread execution state is held for the
# process so the machine stays awake until the run finishes.
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001


class SleepBlocker:
    """Keep the system awake for the probe phase; always released.

    Deliberately does NOT set ES_DISPLAY_REQUIRED: keeping the screen on is
    not needed to finish a run, and is rude on a laptop.
    """

    def __init__(self):
        self.detail = "sleep suppression not attempted"
        self._set = False

    def __enter__(self):
        try:
            import ctypes
            flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            if ctypes.windll.kernel32.SetThreadExecutionState(flags):
                self._set = True
                self.detail = "idle sleep blocked (SetThreadExecutionState)"
            else:
                self.detail = "sleep suppression refused by the OS"
        except (ImportError, AttributeError, OSError) as e:
            self.detail = f"sleep suppression unavailable ({type(e).__name__})"
        return self

    def __exit__(self, *exc):
        if not self._set:
            return False
        try:
            import ctypes
            # Clearing means ES_CONTINUOUS alone — anything else would
            # re-assert the request being released.
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        except (ImportError, AttributeError, OSError):
            pass
        self._set = False
        return False


def flush_dns_cache():
    """Flush the Windows resolver cache; returns (ok, detail).

    Matters between phases: a PRE run against not-yet-enrolled internal
    names caches negative answers, and that cache can mask ZPA steering in
    the POST run (synthetic IPs never appear, so the run looks like a
    failure). ZCC keeps its own cache too — if POST still shows NXDOMAIN
    for an enrolled domain, restart Client Connector before believing it.

    This needs no elevation. A failure means policy or a stopped DNS
    Client service, not a missing administrator prompt.
    """
    try:
        p = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           text=True, timeout=WIN_CMD_TIMEOUT)
        ok = p.returncode == 0
        return ok, ("ipconfig /flushdns=ok" if ok
                    else f"ipconfig /flushdns=rc{p.returncode}")
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return False, f"ipconfig /flushdns failed ({type(e).__name__})"


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

    # State the range explicitly. Two reasons: it is the setting most likely
    # to be wrong (it is tenant-specific and the default is 64x wider than a
    # common /16), and parsing it here rejects an invalid value on EVERY
    # subcommand rather than only where it happens to be used.
    _net = synthetic_net_for(args)
    checks.append((
        "ZPA synthetic range", True,
        f"{_net} ({_net.num_addresses:,} addresses)"
        + ("  — Zscaler's default; set --synthetic-net if your tenant "
           "narrows it" if str(_net) == DEFAULT_SYNTHETIC_NET else
           "  — tenant-specific")))

    zcc = detect_zcc()
    zcc_detail = zcc["state"]
    if zcc["signals"]:
        zcc_detail += f" (via {', '.join(zcc['signals'])})"
    if zcc["installed_version"]:
        zcc_detail += f", version {zcc['installed_version']}"
    if zcc["state"] == "installed_not_running":
        zcc_detail += " — installed but its service is not running"
    elif zcc["state"] == "not_detected":
        zcc_detail += " — no Zscaler service, process or install record found"
    checks.append(("Zscaler Client Connector",
                   zcc["state"] == "running", zcc_detail))

    # Routing evidence, available before any probe: if the synthetic range
    # routes into ZCC's adapter, a ZPA path exists at the OS level. This is
    # independent of the synthetic-IP observation made during probing.
    steer = windows_steering_path(synthetic_net_for(args))
    if steer["checked"]:
        _n = synthetic_net_for(args)
        if steer["via_tunnel"]:
            steer_detail = (f"{steer['probe_ip']} ({_n}) routes via "
                            f"{steer['interface']} — ZCC adapter present")
        else:
            steer_detail = (f"{steer['probe_ip']} ({_n}) routes via "
                            f"{steer['interface'] or '?'}"
                            + (f" (next hop {steer['next_hop']})"
                               if steer.get("next_hop") else "")
                            + " — no ZCC adapter claims this range")
    else:
        steer_detail = "Find-NetRoute unavailable"
    checks.append(("ZPA synthetic-range route",
                   bool(steer["via_tunnel"]), steer_detail))

    dnscfg = windows_dns_config()
    checks.append(("DNS resolvers", dnscfg["resolvers"] > 0,
                   f"{dnscfg['resolvers']} server(s): "
                   f"{', '.join(dnscfg['servers'][:4])}"))
    # NRPT is how ZCC implements split DNS on Windows. Zero rules on an
    # enrolled host means names are resolving through the LAN resolver.
    checks.append(("NRPT split-DNS policy", dnscfg["nrpt_rules"] > 0,
                   f"{dnscfg['nrpt_rules']} rule(s)"
                   + (f": {', '.join(dnscfg['nrpt_namespaces'][:4])}"
                      if dnscfg["nrpt_namespaces"] else
                      " — no per-domain policy in force")))

    proxy = windows_proxy_config()
    checks.append(("Proxy configuration", True,
                   (f"WinINET {proxy['proxy_server']}"
                    if proxy["proxy_enabled"] else "WinINET direct")
                   + (f", PAC {proxy['autoconfig_url']}"
                      if proxy["autoconfig_url"] else "")
                   + (f"; {proxy['winhttp']}" if proxy["winhttp"] else "")))

    # Resolve what the tool actually depends on, not an arbitrary public
    # name. A single hardcoded probe host is a false-failure trap: DNS
    # filtering (DNS blocklists, ZIA policy) commonly NXDOMAINs
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
TENANT_FIELDS = ("client_id", "vanity_domain", "customer_id",
                 "synthetic_net")

NO_TTY_TENANT = ("ERROR: no interactive terminal to choose a tenant — pass "
                 "--tenant NAME (with --yes to skip confirmation).")


def tenant_store_path():
    override = os.environ.get(TENANT_STORE_ENV)
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(
        os.path.abspath(os.path.expanduser(DEFAULT_TENANT_DIR)),
        "tenants.json")


# Principals that may legitimately appear on the tenant store's ACL. Anything
# else means another account can read a file that may hold a client secret.
# No allow-list of principal names: see _warn_if_readable_by_others. A name
# list would have to be localized, and the restricted state is a single ACE
# anyway.


def _current_user():
    """The principal name Windows itself uses.

    Not %USERDOMAIN%\\%USERNAME%: on a machine that is not domain-joined
    USERDOMAIN is "WORKGROUP" while the real principal is
    COMPUTERNAME\\user, and icacls rejects the former with rc1332, "no
    mapping between account names and security IDs". whoami reports the
    form icacls actually accepts, so ask it rather than assemble one.
    """
    try:
        p = subprocess.run(["whoami"], capture_output=True, text=True, errors="replace",
                           timeout=WIN_CMD_TIMEOUT)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    host = os.environ.get("COMPUTERNAME", "")
    usr = os.environ.get("USERNAME") or getpass.getuser()
    return f"{host}\\{usr}" if host else usr


def _secure_acl(path):
    """Restrict a path to the current user; returns (ok, detail).

    A file inherits whatever its parent directory grants, which in a
    profile directory is typically the user, SYSTEM and Administrators.
    This build offers to store an OAuth client secret, so inheriting is not
    good enough: the ACL is set explicitly with inheritance removed, then
    read back and verified.
    """
    try:
        p = subprocess.run(["icacls", path, "/inheritance:r",
                            "/grant:r", f"{_current_user()}:(F)"],
                           capture_output=True, text=True, errors="replace",
                           timeout=WIN_CMD_TIMEOUT)
        if p.returncode != 0:
            return False, f"icacls rc{p.returncode}"
        return True, f"ACL restricted to {_current_user()}"
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return False, f"icacls failed ({type(e).__name__})"


def _warn_if_readable_by_others(path):
    """Read the real ACL back and warn if anyone else can read the file."""
    try:
        p = subprocess.run(["icacls", path], capture_output=True, text=True, errors="replace",
                           timeout=WIN_CMD_TIMEOUT)
    except (OSError, ValueError, subprocess.SubprocessError):
        return
    if p.returncode != 0:
        return
    # Locale-independent by construction: _secure_acl grants exactly one
    # principal and strips inheritance, so the expected steady state is a
    # single ACE. Anything else means someone else can read the file,
    # whatever language Windows names them in — the previous version
    # compared against the English strings "NT AUTHORITY\\SYSTEM" and
    # "BUILTIN\\Administrators" and so mis-warned on localized Windows.
    me = _current_user().lower()
    allowed = {me}
    others = []
    first = True
    for line in (p.stdout or "").splitlines():
        # Every ACE line is "PRINCIPAL:(flags)"; the first is prefixed with
        # the path. Splitting on ":" alone captured the drive letter as a
        # principal and matched nothing real — split on the ACE marker.
        if ":(" not in line:
            continue
        entry = line
        if first:
            if entry.startswith(path):
                entry = entry[len(path):]
            first = False
        principal = entry.split(":(")[0].strip()
        if principal and principal.lower() not in allowed:
            others.append(principal)
    if others:
        print(f"[!] {path} is readable by: {', '.join(sorted(set(others)))}")
        print(f"    It can hold a client secret. To restrict it:")
        print(f"    icacls \"{path}\" /inheritance:r "
              f"/grant:r \"{_current_user()}:(F)\"")


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
    """Write the store, restrict its ACL, and return (path, restricted).

    The file must exist before it can be ACL'd, so for a brief moment its
    contents — which may include a client secret the operator opted into
    storing — sit under the inherited ACL. In a user profile that means
    user + SYSTEM + Administrators, not world-readable, but it is not the
    restricted state either. The window is reported honestly rather than
    papered over, and the ACL is read back so the caller can say what is
    actually true instead of asserting a numeric file mode, which describes
    nothing on NTFS.
    """
    path = tenant_store_path()
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    ok, detail = _secure_acl(path)
    if not ok:
        print(f"[!] Could not restrict {path}: {detail}")
        print("    Anyone who can read your profile can read this file.")
    else:
        # The docstring used to claim the ACL was read back; it was not.
        # Make the claim true rather than quietly dropping it.
        _warn_if_readable_by_others(path)
    return path, ok


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
            f"        synthetic net : "
            f"{t.get('synthetic_net') or DEFAULT_SYNTHETIC_NET}\n"
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
        # --tenant is an explicit choice; --yes means the caller scripted it.
        # getattr, not args.yes: only `test` defines --yes, so a bare
        # attribute access raised AttributeError on export-targets and
        # sipa-verify — the very commands --tenant exists to serve.
        if not getattr(args, "yes", False):
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
    synth_in = ask(f"  ZCC synthetic IP range [{DEFAULT_SYNTHETIC_NET}]: ",
                   "ERROR: no terminal.").strip() or DEFAULT_SYNTHETIC_NET
    parse_synthetic_net(synth_in)      # validate before it reaches the store
    if not all([client_id, vanity, customer]):
        sys.exit("ERROR: client ID, vanity domain and customer ID are all "
                 "required.")

    print("\n  The client secret can be saved too, but it is stored in "
          "PLAINTEXT in\n"
          f"  {path} (ACL restricted to your account). By default this tool never writes\n"
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
             "vanity_domain": vanity, "customer_id": customer,
             "synthetic_net": synth_in}
    if secret:
        entry["client_secret"] = secret

    doc.setdefault("tenants", [])
    doc["tenants"] = [x for x in doc["tenants"] if x is not existing]
    doc["tenants"].append(entry)
    path, restricted = save_tenant_store(doc)
    # Report what is actually true. A numeric file mode has no meaning on
    # NTFS, and asserting one while the ACL may have failed to apply was the
    # tool telling the operator something it had not checked.
    acl = (f"ACL restricted to {_current_user()}" if restricted
           else "WARNING: ACL not restricted — see the message above")
    print(f"\nSaved tenant '{name}' to {path} ({acl})"
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
# DNS destinations CSV
# --------------------------------------------------------------------------
#
# An export of enterprise DNS records — one row per record, with the name,
# its CNAME chain, and the IPs it resolves to *from a DNS-server vantage*,
# i.e. with no Client Connector in the path. That makes it pre-ZPA ground
# truth, and the only reference the tool has for the question the segment
# inventory cannot answer: which internal names are NOT enrolled in ZPA.
#
# Deliberately no guessed ports. An enterprise-wide record list is a mix of
# every server role, so a fixed port set would (a) report a steered SQL host
# as TIMEOUT, which the summary reads as "traffic may not be steered" — the
# exact opposite of the truth — and (b) amount to a horizontal port scan
# from a managed endpoint. Names that match a ZPA segment are probed on that
# segment's own configured ports; names that do not are resolved and not
# probed at all. Resolution alone answers the steering question, because
# steering is observable in what the resolver returns.

DEFAULT_DNS_CSV = "dns_destinations.csv"


def resolve_dns_csv_path(value):
    """Locate the export. The bare flag looks beside the script first.

    The file is expected to sit next to the script, so a run from any working
    directory finds it; an explicit path is always honoured as given.
    """
    if value and os.path.basename(value) != value:
        return os.path.abspath(os.path.expanduser(value))
    name = value or DEFAULT_DNS_CSV
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, name), os.path.abspath(name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(here, name)

# Only records that can plausibly front a TCP service. TXT/MX/NS/SRV rows
# would contribute nothing but failures.
DNS_CSV_RECORD_TYPES = ("A", "CNAME")

# Ports per matched name in this mode, regardless of scope. The DNS sweep
# exists to establish steering coverage, not exhaustive reachability, and a
# segment defining a wide range would otherwise multiply across thousands of
# names into a scan. Whatever this drops is reported, never silent.
DNS_CSV_PORT_CAP = 4

# A port RANGE wider than this carries no information about what any single
# host behind the segment listens on, so it contributes nothing here.
#
# This is the common shape in practice: most records in an enterprise export
# match no segment *explicitly* — they are caught by a wildcard segment with
# a broad range. Treating that as an authoritative port list is worse than
# having none. expand_ports keeps range endpoints first, so `1-65535` yields
# ports 1, 65535, 2, 3; probing those across thousands of names produces
# nothing but TIMEOUT rows, which the summary reads as "traffic may not be
# steered", and reproduces exactly the scan this mode avoids.
#
# The filter is per-range rather than per-segment, so a segment defining
# `443, 8000-8100` still contributes 443 — real evidence — while discarding
# the range, which is not. A segment whose every range is wide contributes
# nothing and its names are resolved only. The steering answer is unaffected
# either way: that comes from resolution, not from any connect.
DNS_CSV_MAX_RANGE_SPAN = 4


# Ports whose service is UDP in normal deployment. A TCP connect to one of
# these times out on a perfectly healthy host, so a TCP-only probe reports
# the service as unreachable when it is running fine — and this tool's
# summary classifies TIMEOUT as "nothing answered, traffic may not be
# steered", which turns a protocol mismatch into a false ZPA finding.
#
# 53 is deliberately absent: DNS runs on TCP as well as UDP, so a TCP probe
# there is meaningful.
UDP_PRIMARY_PORTS = {
    69: "TFTP", 123: "NTP", 137: "NetBIOS name", 138: "NetBIOS datagram",
    161: "SNMP", 162: "SNMP trap", 500: "IKE", 514: "syslog",
    1900: "SSDP", 4500: "IPsec NAT-T", 5353: "mDNS",
}


# Ports whose horizontal sweep is a standard IDS/EDR/NDR signature. Probing
# one of these on a handful of hosts is unremarkable; probing it across an
# entire DNS export from a single endpoint is the textbook shape of
# reconnaissance, and it will be attributed to the account running it.
#
# This is not a refusal — testing your own estate is legitimate work — but
# the run should name which of the requested ports are the noisy ones rather
# than issue a vague caution the operator cannot act on.
SCAN_SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "telnet", 111: "rpcbind/portmapper",
    135: "MSRPC endpoint mapper", 139: "NetBIOS session", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle TNS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}


def scan_sensitive_in(ports):
    """[(port, service)] for ports whose sweep commonly raises an alert."""
    return [(p, SCAN_SENSITIVE_PORTS[p]) for p in ports
            if p in SCAN_SENSITIVE_PORTS]


def parse_dns_ports(value):
    """Parse --dns-ports, or exit with a usable message."""
    if not value:
        return []
    ports = []
    for part in str(value).replace(" ", "").split(","):
        if not part:
            continue
        try:
            p = int(part)
        except ValueError:
            sys.exit(f"ERROR: --dns-ports {part!r} is not a port number.")
        if not 1 <= p <= 65535:
            sys.exit(f"ERROR: --dns-ports {p} is out of range (1-65535).")
        if p not in ports:
            ports.append(p)
    return ports


def dns_ports_for(args):
    """--dns-ports resolved once and cached on args."""
    cached = getattr(args, "dns_ports_resolved", None)
    if cached is not None:
        return cached
    ports = parse_dns_ports(getattr(args, "dns_ports", None))
    args.dns_ports_resolved = ports
    return ports


def udp_primary_in(ports):
    """[(port, service)] for ports a TCP probe cannot meaningfully test."""
    return [(p, UDP_PRIMARY_PORTS[p]) for p in ports if p in UDP_PRIMARY_PORTS]


def dns_specific_ports(seg, cap):
    """(ports, dropped) — only the ports that actually identify a service.

    Wide ranges are dropped rather than sampled. Sampling one would test two
    arbitrary ports out of a hundred and silently leave the rest untested,
    which reads in the summary as though the host had been checked.
    """
    ranges = port_ranges(seg, "tcpPortRange")
    narrow, dropped = [], 0
    for lo, hi in ranges:
        if hi - lo + 1 <= DNS_CSV_MAX_RANGE_SPAN:
            narrow.append((lo, hi))
        else:
            dropped += hi - lo + 1
    ports, trunc = expand_ports(narrow, cap)
    return ports, dropped + trunc

DNS_CSV_FIELDS = ["dns_record_type", "dns_terminal_name", "dns_resolved_ips",
                  "dns_only_external", "dns_has_internal", "dns_in_zpa",
                  "dns_ip_match", "dns_verdict"]

# What each cross-reference verdict means, for the summary legend.
DNS_VERDICTS = {
    "STEERED": "resolved into the synthetic range — ZPA is handling it",
    "NOT_STEERED_INTERNAL": "resolved to an internal IP, not into ZPA — "
                            "an internal app reached outside ZPA",
    "NOT_STEERED_EXTERNAL": "external-only in DNS — not a ZPA candidate, "
                            "expected",
    "NOT_STEERED_UNKNOWN": "not steered, and the export has no IPs to "
                           "classify it by",
    "DNS_FAIL": "did not resolve at the endpoint",
}


def _csv_bool(value):
    """TRUE/FALSE from the export; anything unrecognised stays unknown."""
    v = str(value or "").strip().lower()
    if v in ("true", "1", "yes"):
        return True
    if v in ("false", "0", "no"):
        return False
    return None


def _dns_row_get(row, *names):
    """Case-insensitive column read; the export's casing is not guaranteed.

    This used to claim case-insensitivity while doing an exact dict lookup,
    which meant an ALL-CAPS export parsed without error and silently
    produced NOT_STEERED_UNKNOWN for every name: RecordType, ResolvedIPs and
    HasAnyInternalIP all read as empty, so nothing could be classified. The
    run looked successful and every verdict was worthless.
    """
    low = {str(k).strip().lower(): v for k, v in row.items() if k}
    for name in names:
        key = str(name).strip().lower()
        if key in low:
            return (low[key] or "").strip()
    return ""


def load_dns_csv(path, args):
    """Parse the DNS export into per-name records, or exit with guidance.

    Returns (by_name, stats). Rows are keyed by the *queried* name, not the
    CNAME terminal: ZPA steering matches what the client asks for, so the
    alias is the thing to probe and the terminal is reference data.
    """
    if not os.path.exists(path):
        sys.exit(f"ERROR: --dns-csv file not found: {path}\n"
                 f"Place {DEFAULT_DNS_CSV} beside the script, or pass an "
                 "explicit path.")
    # utf-8-sig so an Excel-written BOM does not become part of the first
    # header name, which would silently break every column lookup.
    #
    # The fallback is not defensive padding: Excel on Windows writes cp1252
    # by default, so one accented character or smart quote anywhere in an
    # enterprise-wide export would otherwise abort the whole run with a
    # UnicodeDecodeError. Names are ASCII in practice, so decoding the rest
    # leniently loses nothing that matters.
    encoding = "utf-8-sig"
    try:
        with open(path, encoding=encoding) as probe:
            probe.read(65536)
    except UnicodeDecodeError:
        encoding = "cp1252"
        print(f"[*] {os.path.basename(path)} is not UTF-8; reading as cp1252")
    except OSError as e:
        sys.exit(f"ERROR: cannot read --dns-csv {path}: {e}")
    try:
        fh = open(path, newline="", encoding=encoding, errors="replace")
    except OSError as e:
        sys.exit(f"ERROR: cannot read --dns-csv {path}: {e}")
    stats = {"rows": 0, "skipped_type": 0, "skipped_lookup": 0,
             "skipped_wildcard": 0, "skipped_noname": 0, "duplicates": 0,
             "record_types": {}}
    by_name = {}
    try:
        try:
            reader = csv.DictReader(fh)
            fields = reader.fieldnames or []
            if not any(f and f.strip().lower() == "name" for f in fields):
                sys.exit(f"ERROR: {path} has no 'Name' column — this does "
                         "not look like a DNS destinations export. Columns "
                         f"found: {', '.join(str(f) for f in fields[:8])}")
            # A missing column is indistinguishable from an empty one once
            # rows are being read, and the consequence is silent: every name
            # classifies as NOT_STEERED_UNKNOWN. Say so up front instead.
            present = {str(f).strip().lower() for f in fields if f}
            absent = [c for c in ("RecordType", "LookupStatus", "ResolvedIPs",
                                  "HasAnyInternalIP", "OnlyExternalIPs")
                      if c.lower() not in present]
            if absent:
                print(f"[!] {os.path.basename(path)} has no "
                      f"{', '.join(absent)} column(s). Names will still be "
                      "probed, but the cross-reference cannot classify what "
                      "it cannot read.")
            for raw in reader:
                stats["rows"] += 1
                name = _dns_row_get(raw, "Name", "name", "NAME").lower()
                name = name.rstrip(".")
                if not name:
                    stats["skipped_noname"] += 1
                    continue
                rtype = _dns_row_get(raw, "RecordType", "recordtype",
                                     "Record_Type").upper()
                stats["record_types"][rtype or "(blank)"] = \
                    stats["record_types"].get(rtype or "(blank)", 0) + 1
                if rtype and rtype not in DNS_CSV_RECORD_TYPES:
                    stats["skipped_type"] += 1
                    continue
                lookup = _dns_row_get(raw, "LookupStatus",
                                      "lookupstatus").upper()
                if lookup and lookup != "OK":
                    stats["skipped_lookup"] += 1
                    continue
                wildcard = _csv_bool(_dns_row_get(raw, "IsWildcard",
                                                  "iswildcard"))
                if wildcard or name.startswith("*"):
                    if not args.wildcard_probe:
                        stats["skipped_wildcard"] += 1
                        continue
                    name = args.wildcard_probe + name.lstrip("*")
                if name in by_name:
                    stats["duplicates"] += 1
                    continue
                ips = [p.strip() for p in
                       _dns_row_get(raw, "ResolvedIPs", "resolvedips")
                       .replace(",", ";").split(";") if p.strip()]
                by_name[name] = {
                    "name": name,
                    "record_type": rtype,
                    "terminal": _dns_row_get(raw, "TerminalName",
                                             "terminalname").lower(),
                    "ips": ips,
                    "only_external": _csv_bool(
                        _dns_row_get(raw, "OnlyExternalIPs",
                                     "onlyexternalips")),
                    "has_internal": _csv_bool(
                        _dns_row_get(raw, "HasAnyInternalIP",
                                     "hasanyinternalip")),
                    "zone": _dns_row_get(raw, "ZoneName", "zonename"),
                }
        except csv.Error as e:
            sys.exit(f"ERROR: {path} is not readable as CSV: {e}")
    finally:
        fh.close()
    if not by_name:
        sys.exit(f"ERROR: {path} yielded no usable records "
                 f"({stats['rows']} rows read; "
                 f"{stats['skipped_type']} wrong record type, "
                 f"{stats['skipped_lookup']} lookup not OK, "
                 f"{stats['skipped_wildcard']} wildcard).")
    return by_name, stats


def segment_domain_index(segments, args):
    """domain -> segment, for every segment the run's filters keep.

    Wildcards are stored under their parent so `*.corp.example` matches
    `app.corp.example`, which is how ZPA itself resolves an app-list hit.
    """
    exact, wild = {}, {}
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        name = str(seg.get("name") or f"(unnamed-{seg.get('id', '?')})")
        if args.sipa_only and not seg.get("ipAnchored"):
            continue
        if args.enabled_only and not seg.get("enabled", True):
            continue
        if args.segment and args.segment.lower() not in name.lower():
            continue
        for entry in seg.get("domainNames") or []:
            e = str(entry).strip().lower()
            if not e:
                continue
            if e.startswith("*."):
                wild.setdefault(e[1:], (name, seg))
            elif classify_entry(e) == "fqdn":
                exact.setdefault(e, (name, seg))
    return exact, wild


def match_segment(host, exact, wild):
    """(segment_name, segment) for a host, or (None, None)."""
    h = host.lower().rstrip(".")
    if h in exact:
        return exact[h]
    parent = h
    while "." in parent:
        parent = parent.split(".", 1)[1]
        hit = wild.get("." + parent)
        if hit:
            return hit
    return None, None


def build_dns_targets(by_name, segments, args):
    """Targets from the DNS export. Ports come only from matched segments."""
    exact, wild = segment_domain_index(segments or [], args)
    # Whether enrolment could be checked AT ALL. Without an inventory,
    # "not in a segment" is not a finding — it is an unasked question, and
    # recording it as False produced a run that reported every steered name
    # as an enrolment gap while its own verdict said ZPA was steering them.
    have_segments = bool(exact or wild)
    names = sorted(by_name)
    stats = {"names_total": len(names), "names_sampled_out": 0,
             "enrolment_checked": have_segments,
             "matched": 0, "unmatched": 0, "ports_truncated": 0,
             "matched_exact": 0, "matched_wildcard": 0,
             "broad_ports": 0, "probed": 0, "broad_segments": {}}

    # --scope deliberately does NOT thin this list. The question the export
    # answers is which names are absent from ZPA, and sampling would drop
    # exactly the unenrolled records being hunted. Resolution is cheap, so
    # the default is every record; --dns-sample caps it explicitly.
    if args.dns_sample and len(names) > args.dns_sample:
        keep = spread_sample(names, args.dns_sample)
        stats["names_sampled_out"] = len(names) - len(keep)
        names = keep

    cap = min(DNS_CSV_PORT_CAP, args.max_ports or DNS_CSV_PORT_CAP)
    # Fallback ports are used only where the segment supplied no specific
    # evidence — a broad-range match, or no match at all. They never
    # override a segment that does define discrete ports.
    fallback = dns_ports_for(args)
    stats["fallback_ports"] = list(fallback)
    stats["fallback_used"] = 0
    stats["udp_primary"] = udp_primary_in(fallback)
    stats["scan_sensitive"] = scan_sensitive_in(fallback)
    stats["udp_confirmed"] = {}
    # Port breadth is a property of the segment, not of the name, so it is
    # measured once per segment rather than per record.
    breadth = {}
    targets = []
    for name in names:
        seg_name, seg = match_segment(name, exact, wild)
        via_wild = seg is not None and name not in exact
        # Only fallback ports are walked in order and stopped early. Ports a
        # segment actually defines are a port inventory, and there every
        # port's individual status is the point.
        ordered = False
        if seg is None:
            stats["unmatched"] += 1
            ports, udp = list(fallback), []
            if ports:
                stats["fallback_used"] += 1
                ordered = not getattr(args, "dns_ports_all", False)
            seg_label = ("(not in any ZPA segment)" if have_segments
                         else "(no segment inventory loaded)")
        else:
            stats["matched"] += 1
            stats["matched_wildcard" if via_wild else "matched_exact"] += 1
            sid = str(seg.get("id") or seg_name)
            if sid not in breadth:
                breadth[sid] = dns_specific_ports(seg, cap)
            ports, dropped = breadth[sid]
            ports = list(ports)
            stats["ports_truncated"] += dropped
            if ports:
                stats["probed"] += 1
            else:
                # Nominally matched, but every range the segment defines is
                # too wide to say anything about this host. Record which
                # segment caused it, then fall back if one was configured.
                stats["broad_ports"] += 1
                stats["broad_segments"][seg_name] = \
                    stats["broad_segments"].get(seg_name, 0) + 1
                if fallback:
                    ports = list(fallback)
                    stats["fallback_used"] += 1
                    ordered = not getattr(args, "dns_ports_all", False)
                    # The segment's own UDP definition is direct evidence
                    # that a fallback port is UDP here, not a guess from a
                    # well-known-ports table.
                    for lo, hi in port_ranges(seg, "udpPortRange"):
                        for p in fallback:
                            if lo <= p <= hi:
                                stats["udp_confirmed"].setdefault(
                                    p, set()).add(seg_name)
            udp = []
            seg_label = seg_name
        targets.append({
            "segment": seg_label,
            "segment_id": (seg or {}).get("id", ""),
            "enabled": bool((seg or {}).get("enabled", True)),
            "ip_anchored": bool((seg or {}).get("ipAnchored", False)),
            "ports": ports,
            "udp_ranges": udp,
            "kind": "fqdn",
            "domain": name,
            "probe_domain": name,
            "dns_ref": by_name[name],
            # True / False / "" — the empty string is "not checked", and
            # every consumer must distinguish it from False.
            "dns_in_zpa": (seg is not None) if have_segments else "",
            "dns_via_wildcard": via_wild,
            "dns_ordered": ordered,
        })
    return targets, stats


def dns_verdict_for(row, ref, intercepted):
    """Steering verdict for one name, given the export as the reference."""
    if str(row.get("status", "")).startswith("DNS_FAIL"):
        return "DNS_FAIL"
    if intercepted is True:
        return "STEERED"
    if ref.get("only_external") is True:
        return "NOT_STEERED_EXTERNAL"
    if ref.get("has_internal") is True or ref.get("ips"):
        return "NOT_STEERED_INTERNAL"
    return "NOT_STEERED_UNKNOWN"


def annotate_dns_rows(rows, targets):
    """Attach the export's reference data and the verdict to each row.

    Keyed on probe_domain rather than carried through the probe path, so the
    concurrency layer stays unaware of any of this.
    """
    refs = {t["probe_domain"]: t for t in targets if t.get("dns_ref")}
    for row in rows:
        t = refs.get(str(row.get("probe_domain", "")))
        if not t:
            continue
        ref = t["dns_ref"]
        intercepted = row.get("zpa_intercepted")
        ip = str(row.get("resolved_ip") or "")
        ip_match = "" if not ref["ips"] or not ip else (ip in ref["ips"])
        row.update({
            "dns_record_type": ref["record_type"],
            "dns_terminal_name": ref["terminal"],
            "dns_resolved_ips": ";".join(ref["ips"]),
            "dns_only_external": ref["only_external"]
            if ref["only_external"] is not None else "",
            "dns_has_internal": ref["has_internal"]
            if ref["has_internal"] is not None else "",
            "dns_in_zpa": t["dns_in_zpa"],
            "dns_ip_match": ip_match,
            "dns_verdict": dns_verdict_for(row, ref, intercepted),
        })
    return rows


def dns_stats(rows):
    """Cross-reference rollup, or None when --dns-csv was not used.

    Counted per NAME, not per probe: a name with four ports would otherwise
    contribute four times to a coverage figure that is about names.
    """
    seen, verdicts = {}, {}
    for r in rows:
        v = r.get("dns_verdict")
        if not v:
            continue
        name = str(r.get("probe_domain", ""))
        if name in seen:
            continue
        seen[name] = r
        verdicts[v] = verdicts.get(v, 0) + 1
    if not seen:
        return None

    def _in_zpa(row):
        """True / False / None. None means enrolment was never checked."""
        v = row.get("dns_in_zpa")
        if v is True or v == "True":
            return True
        if v is False or v == "False":
            return False
        return None

    checked = [r for r in seen.values() if _in_zpa(r) is not None]
    in_zpa = sum(1 for r in checked if _in_zpa(r) is True)
    # An internal name in no ZPA segment cannot be steered — that is an
    # enrolment gap, distinct from a name that is enrolled and still is not
    # being steered.
    # Only names actually checked can be an enrolment gap. Without an
    # inventory this list is empty and enrolment_checked is False, so the
    # summary says "unknown" instead of inventing a coverage finding.
    enrol_gap = [n for n, r in seen.items()
                 if _in_zpa(r) is False
                 and r.get("dns_has_internal") in (True, "True")]
    # A name known NOT to be in any segment is expected not to be steered;
    # that is an enrolment question, not a steering one. Unknown enrolment
    # still counts, because the verdict itself is the finding.
    steer_gap = [n for n, r in seen.items()
                 if r.get("dns_verdict") == "NOT_STEERED_INTERNAL"
                 and _in_zpa(r) is not False]
    diverged = [n for n, r in seen.items() if r.get("dns_ip_match") is False
                and r.get("dns_verdict") != "STEERED"]
    return {
        "names": len(seen),
        "enrolment_checked": bool(checked),
        "in_zpa": in_zpa,
        "not_in_zpa": len(checked) - in_zpa,
        "enrolment_unknown": len(seen) - len(checked),
        "verdicts": verdicts,
        "steered": verdicts.get("STEERED", 0),
        "pct_steered": round(100.0 * verdicts.get("STEERED", 0) / len(seen), 1),
        "enrolment_gap": sorted(enrol_gap),
        "steering_gap": sorted(steer_gap),
        "diverged": sorted(diverged),
    }


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
    workers = max(1, int(getattr(args, "workers", 400) or 400))
    timeout = float(getattr(args, "timeout", 3.0) or 3.0)
    # Each retry is another full timeout plus the jittered backoff in
    # tcp_probe_retry, so ignoring retries understated the worst case by
    # roughly 2x at the default --retries 1 — and confirm_run gates on this
    # number, which --yes does not bypass.
    attempts = int(getattr(args, "retries", 0) or 0) + 1
    worst = n_probes * (attempts * timeout + (attempts - 1) * 0.35) / workers
    return n_probes / (workers * 200.0), worst


def confirm_run(n_probes, args):
    best, worst = estimate_duration(n_probes, args)

    # A full-scope run against a large tenant can plan hundreds of billions
    # of probes — every CIDR expanded to every host, times a 1-65535 port
    # range.
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

def resolve(domain):
    """Resolve a domain; returns (ip or None, error or None).

    There is deliberately no timeout parameter. getaddrinfo has no per-call
    timeout and socket.setdefaulttimeout does not bound it — that only
    stamps newly created socket objects, while getaddrinfo goes straight to
    the platform resolver. The previous signature took a timeout, ignored
    it, and documented a bound that did not exist. Windows applies its own
    bounded per-server retry ladder, which is what actually limits this.
    """
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        return infos[0][4][0], None
    except socket.gaierror as e:
        return None, str(e)
    except OSError as e:
        return None, str(e)


# How long a platform takes to report a connection refusal, measured.
# Windows delivers it at ~2.04s, so a --timeout below that fires first and
# reports TIMEOUT for a port that demonstrably answered. The summary reads those oppositely — REFUSED proves
# the path works, TIMEOUT suggests traffic is not being steered — so the run
# warns rather than letting the misreading through.
#
# Recovering it below the threshold is not possible: when the timeout fires
# the connect is still pending and SO_ERROR is 0, so there is no error to
# read yet. Tried and measured, not assumed.
REFUSAL_LATENCY_S = 2.5


def tcp_probe(host, port, timeout):
    """Attempt a TCP connect; returns (status, latency_ms).

    Resolution happens before the clock starts. socket.create_connection()
    resolves *inside* the region it times, which had two consequences: DNS
    latency was reported as connect latency, and --timeout bounded only the
    connect half of the call, so a run with --timeout 2 could legitimately
    report a 5.8s probe.

    The connect still targets a freshly resolved address rather than the one
    cached during the resolve phase. ZPA steering is expressed in what the
    resolver returns for the FQDN, so resolving here keeps the probe on
    exactly the path create_connection would have taken.
    """
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET,
                                   socket.SOCK_STREAM)
    except OSError as e:                        # gaierror included
        return f"ERROR:{e.strerror or e}", None
    if not infos:
        return "ERROR:no address returned", None

    af, socktype, proto, _canon, sockaddr = infos[0]
    sock = socket.socket(af, socktype, proto)
    try:
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.connect(sockaddr)
        return "OPEN", round((time.monotonic() - start) * 1000, 1)
    except socket.timeout:
        return "TIMEOUT", None
    except ConnectionRefusedError:
        return "REFUSED", None
    except OSError as e:
        return f"ERROR:{e.strerror or e}", None
    finally:
        sock.close()


def tcp_probe_retry(host, port, timeout, retries):
    """TCP connect with retries on transient failures.

    REFUSED is definitive (something answered) so it is never retried.
    A port that only succeeds on a later attempt is flagged OPEN_FLAKY so
    intermittent connector behaviour is visible rather than averaged away.
    """
    attempts = 0
    # Seeded NOT_PROBED, not TIMEOUT: if the loop somehow never runs, an
    # unprobed unit must not be readable as "nothing answered", which the
    # summary treats as evidence about steering.
    status, latency = "NOT_PROBED", None
    for i in range(max(1, retries + 1)):
        attempts += 1
        status, latency = tcp_probe(host, port, timeout)
        if status in ("OPEN", "REFUSED"):
            break
        if i < retries:
            time.sleep(0.2 + random.random() * 0.3)   # jitter
    if status == "OPEN" and attempts > 1:
        status = "OPEN_FLAKY"
    return status, latency, attempts


def l7_timeout_for(args):
    """Timeout budget for the L7 step, resolved once and cached on args.

    Deliberately not --timeout. A TCP connect brokered by Client Connector
    completes locally and fast, so --timeout is tuned low; a TLS handshake
    over the same path has to traverse the App Connector to the backend and
    routinely needs several times as long. Sharing one budget reported
    working applications as L7 timeouts, which reads as an application
    fault rather than a measurement artefact.
    """
    cached = getattr(args, "l7_timeout_resolved", None)
    if cached is not None:
        return cached
    raw = getattr(args, "l7_timeout", None)
    if raw is not None:
        if raw <= 0:
            sys.exit("ERROR: --l7-timeout must be greater than 0.")
        val = float(raw)
    else:
        val = min(L7_TIMEOUT_CEILING,
                  max(L7_TIMEOUT_FLOOR,
                      getattr(args, "timeout", 2.0) * L7_TIMEOUT_FACTOR))
    args.l7_timeout_resolved = val
    return val


def l7_probe(host, port, timeout, sni=None):
    """Verify something is actually serving, not just that TCP answered.

    Tries TLS first; falls back to a plaintext HTTP HEAD. Certificates are
    not validated — the goal is proof of an application response, and
    internal PKI/TLS inspection would otherwise produce noise.

    The two non-answering outcomes are reported separately because they mean
    different things. A peer that accepts and then sends nothing at all
    (OPEN_NO_L7_DATA) is the signature of a connection terminated locally by
    Client Connector with nothing serving behind the App Connector. A peer
    that sends bytes which are neither TLS nor HTTP (OPEN_NON_HTTP) is a
    live application this probe simply cannot speak to. Collapsing both into
    one status made a real ZPA finding indistinguishable from a protocol
    mismatch.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # One budget for the whole L7 exchange, not one per attempt. A peer that
    # accepts and then hangs used to cost 2x l7_timeout (24s at the default
    # --timeout 3) because the TLS read and the HTTP read each blocked a
    # full budget on the same dead peer.
    #
    # The outcome deliberately stays L7_ERROR rather than OPEN_NO_L7_DATA:
    # those mean different things (see L7_MEANINGS), and collapsing them
    # would report a slow application as a silent one — the exact
    # misreading l7_timeout_for exists to prevent.
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                    return f"TLS:{tls.version()}"
            except (ssl.SSLError, OSError):
                pass
        # not TLS — try a plaintext HTTP request on a fresh connection
        remaining = deadline - time.monotonic()
        if remaining <= L7_MIN_SECOND_ATTEMPT:
            # Same string the second attempt would have produced, so the
            # operator's remedy (raise --l7-timeout) is unchanged.
            return "L7_ERROR:timed out"
        with socket.create_connection((host, port),
                                      timeout=remaining) as sock:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: "
                         + (sni or host).encode() + b"\r\n\r\n")
            raw = sock.recv(128)
        if not raw:
            return "OPEN_NO_L7_DATA"
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})", raw.decode("latin-1", "replace"))
        if m:
            return f"HTTP:{m.group(1)}"
        return "OPEN_NON_HTTP"
    except (OSError, ssl.SSLError) as e:
        return f"L7_ERROR:{getattr(e, 'strerror', None) or type(e).__name__}"


def target_base(target):
    """Row fields shared by every row this target produces."""
    return {
        "segment": target["segment"],
        "enabled": target["enabled"],
        "ip_anchored": target["ip_anchored"],
        "entry_kind": target["kind"],
        "domain": target["domain"],
        "probe_domain": target["probe_domain"],
    }


def resolve_target(target, args):
    """Resolve a target once. Ports reuse this rather than re-resolving.

    Note this is resolution for *reporting* (resolved_ip, zpa_intercepted).
    The probes themselves still connect by hostname — ZPA steering is
    FQDN-driven, so connecting to the resolved IP would bypass Client
    Connector's app-list matching and invalidate the result.
    """
    if target["kind"] in UNVERIFIABLE_KINDS:
        return {"ip": target["probe_domain"], "intercepted": "N/A",
                "sni": None, "dns_err": None}
    ip, dns_err = resolve(target["probe_domain"])
    if dns_err:
        return {"ip": "", "intercepted": "", "sni": target["probe_domain"],
                "dns_err": dns_err}
    try:
        intercepted = ipaddress.ip_address(ip) in synthetic_net_for(args)
    except ValueError:
        intercepted = ""
    return {"ip": ip, "intercepted": intercepted,
            "sni": target["probe_domain"], "dns_err": None}


def target_static_rows(target, res):
    """Rows needing no TCP probe: DNS failure, no-ports, UDP listing."""
    base = target_base(target)
    if res["dns_err"]:
        return [{**base, "resolved_ip": "", "zpa_intercepted": "",
                 "protocol": "dns", "port": "",
                 "status": f"DNS_FAIL:{res['dns_err']}", "attempts": 1,
                 "latency_ms": "", "l7_result": ""}]
    rows = []
    if not target["ports"]:
        rows.append({**base, "resolved_ip": res["ip"],
                     "zpa_intercepted": res["intercepted"],
                     "protocol": "dns" if target["kind"] == "fqdn" else "tcp",
                     "port": "", "status": "NO_TCP_PORTS", "attempts": 0,
                     "latency_ms": "", "l7_result": ""})
    for lo, hi in target["udp_ranges"]:
        rows.append({**base, "resolved_ip": res["ip"],
                     "zpa_intercepted": res["intercepted"],
                     "protocol": "udp",
                     "port": f"{lo}-{hi}" if lo != hi else lo,
                     "status": "UDP_NOT_PROBED", "attempts": 0,
                     "latency_ms": "", "l7_result": ""})
    return rows


def probe_port(target, port, res, args):
    """Probe a single (target, port) — the unit of concurrency.

    Splitting this out is what lets a segment's ports run in parallel.
    Previously one pool task handled a whole target and walked its ports
    serially, so concurrency was capped by target count: a 50-target run
    could not go faster than 8 ports x timeout no matter how many workers
    were configured.
    """
    status, latency, attempts = tcp_probe_retry(
        target["probe_domain"], port, args.timeout, args.retries)
    l7 = ""
    if args.l7 and status in OK_STATUSES:
        l7 = l7_probe(target["probe_domain"], port, l7_timeout_for(args),
                      res["sni"])
    return {**target_base(target), "resolved_ip": res["ip"],
            "zpa_intercepted": res["intercepted"],
            "protocol": "tcp", "port": port,
            "status": status, "attempts": attempts,
            "latency_ms": latency if latency is not None else "",
            "l7_result": l7}


# A status that proves the path works. REFUSED belongs here: something at
# the far end answered and declined, which for a liveness check is as
# conclusive as an accepted connection.
ANSWERED_STATUSES = ("OPEN", "OPEN_FLAKY", "REFUSED")


def probe_ports_ordered(target, res, args):
    """Walk this target's ports in the given order, stopping at the first
    that answers. Returns the rows actually produced.

    Fallback ports are a liveness check, not a port inventory: once one
    answers, the path through ZPA is demonstrated and every further connect
    is pure scan volume. On a healthy host this is one connect instead of
    len(ports), which is the difference between a sweep and a probe when it
    runs across a whole DNS export.

    The order is the operator's — parse_dns_ports preserves input order —
    so the most likely port for the estate can be tried first. Ports never
    reached are counted by the caller and reported, never silently absent.
    """
    rows = []
    for port in target["ports"]:
        row = probe_port(target, port, res, args)
        rows.append(row)
        if str(row.get("status")) in ANSWERED_STATUSES:
            break
    return rows


def probe_error_row(target, exc):
    """A failed work unit, recorded rather than lost to a traceback."""
    return {**target_base(target), "resolved_ip": "", "zpa_intercepted": "",
            "protocol": "", "port": "",
            "status": f"PROBE_ERROR:{type(exc).__name__}",
            "attempts": 0, "latency_ms": "", "l7_result": ""}


def probe_target(target, args):
    """Serial probe of one target — kept for callers that want it whole."""
    res = resolve_target(target, args)
    rows = target_static_rows(target, res)
    if res["dns_err"]:
        return rows
    rows.extend(probe_port(target, p, res, args) for p in target["ports"])
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

    A flat failure list buries the findings that matter: at scale the
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
        # In --dns-csv mode the binding cap is DNS_CSV_PORT_CAP, and --scope
        # full does NOT lift it. Naming --max-ports here would send someone
        # to a flag that cannot change the number they are looking at.
        why = (f"--dns-csv caps ports at {DNS_CSV_PORT_CAP} per name; "
               "--scope does not lift this"
               if getattr(args, "dns_csv", None) else
               f"--max-ports {args.max_ports}; --scope full for all")
        lines.append(f"                     {stats['ports_truncated']} dropped "
                     f"({why})")
    return lines


def next_steps(args, stats, action, unverifiable, dns_fail, dns_flush_ok,
               intercepted, l7s=None, dstats=None):
    """Recommendations derived from this run's actual results.

    dns_flush_ok is the boolean from flush_dns_cache(): True flushed,
    False attempted-but-failed, None not attempted. Do NOT infer it from
    the detail string — match the boolean.
    """
    prog = os.path.basename(sys.argv[0]) or "zpa_segment_connectivity.py"
    steps = []
    if dns_fail and args.phase == "post":
        if dns_flush_ok is False:
            steps.append(
                "The DNS cache flush failed, and a stale negative entry can "
                "fake a post-run DNS failure (caveat 2). ipconfig /flushdns "
                "needs no elevation, so a failure here usually means policy "
                "or a broken DNS Client service — check that, then re-run:\n"
                f"       py -3 {prog} test --phase post --flush-dns ...")
        elif dns_flush_ok is None:
            steps.append(
                "This post run did not flush the DNS cache, so a negative "
                "entry cached during the pre run can mask steering "
                "(caveat 2). Re-run with --flush-dns — it needs no "
                "elevation on Windows.")
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
    # getattr, not attribute access: next_steps is called by tests and by
    # any caller assembling its own namespace. Reading args.dns_csv directly
    # is the same failure that broke --tenant on export-targets in v1.8.1,
    # and it has now recurred twice more in this feature.
    udp_ports = (udp_primary_in(dns_ports_for(args))
                 if getattr(args, "dns_csv", None) else [])
    if udp_ports:
        named = ", ".join(f"{p}/tcp ({svc})" for p, svc in udp_ports)
        steps.append(
            f"{named} were probed over TCP, but those services run over UDP. "
            "A timeout there says nothing about reachability or steering — "
            "the host may be answering perfectly on UDP. Read those rows as "
            "'not tested', not as failures, and drop them from --dns-ports "
            "unless you know the service is bound to TCP as well. ZPA "
            "segments record UDP ports separately (udpPortRange); this tool "
            "lists them as UDP_NOT_PROBED and never probes them.")
    if dstats and dstats["steering_gap"]:
        # Only claim enrolment when it was actually checked; otherwise the
        # finding is the observation itself, without the attribution.
        lead = (f"{len(dstats['steering_gap'])} name(s) are enrolled in a ZPA "
                "segment but resolved to an internal IP rather than into the "
                "synthetic range."
                if dstats.get("enrolment_checked") else
                f"{len(dstats['steering_gap'])} name(s) resolved to an "
                "internal IP rather than into the synthetic range. Whether "
                "they are enrolled is unknown — no segment inventory was "
                "loaded.")
        steps.append(
            lead + " Those are reaching the app outside ZPA — check the "
            "access policy covers your account, and that no local resolver "
            "or hosts-file entry (%SystemRoot%\\System32\\drivers\\etc\\hosts) "
            "is short-circuiting Client Connector.")
    if dstats and not dstats.get("enrolment_checked"):
        steps.append(
            "Enrolment was not checked: this run had no segment inventory to "
            "join against, so the export could only answer which names are "
            "being steered — not which are enrolled. Re-run with "
            "--targets-file zpa-targets.json (or credentials) to get the "
            "coverage answer the export exists to provide.")
    if dstats and dstats["enrolment_gap"]:
        steps.append(
            f"{len(dstats['enrolment_gap'])} internal name(s) in the DNS "
            "export are in no ZPA segment. They cannot be steered until a "
            "segment covers them — this is the coverage gap the export "
            "exists to surface. Review them for enrolment (dns_in_zpa=False "
            "with dns_has_internal=True in the CSV).")
    if l7s and l7s["unverified"]:
        err = l7s["breakdown"].get("L7_ERROR", 0)
        step = (f"{l7s['unverified']} of {l7s['probed']} OPEN probes "
                f"({100 - l7s['pct_verified']:.1f}%) had no application "
                "response. TCP reachability through ZPA is established by "
                "Client Connector locally, so a port reads as OPEN whether "
                "or not anything behind the App Connector is serving — do "
                "not read the reachability count as an application pass.")
        if err:
            step += (f" {err} of them were L7 errors rather than empty "
                     "replies; re-run with a larger --l7-timeout to separate "
                     "a tight budget from a genuinely silent backend.")
        step += (" Then confirm the App Connector can reach those backends "
                 "on those ports.")
        steps.append(step)
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


def run_verdict(args, intercepted, zcc, steer=None, net=None):
    """One-line answer to the question the run exists to settle.

    The pre-phase branch matters: running --phase pre on a laptop that is
    already enrolled silently captures a post-state labelled "pre", and the
    later compare is then meaningless rather than obviously wrong.

    `steer` is the routing-table evidence from windows_steering_path(). It is
    independent of the synthetic-IP observation, which lets a negative
    result say *why*: no tunnel claims the synthetic range at all (nothing
    to steer through), versus a tunnel exists but no name resolved into it
    (enrollment or policy).
    """
    n = len(intercepted)
    tunnel = (steer or {}).get("via_tunnel")
    iface = (steer or {}).get("interface") or "?"

    if args.phase == "pre":
        if n:
            return ("BASELINE INVALID",
                    f"{n} domain(s) already steered into ZPA — this is a "
                    "post-state, not a pre-ZPA baseline")
        if tunnel:
            return ("BASELINE SUSPECT",
                    f"no synthetic IPs, but the synthetic range already "
                    f"routes via {iface} — ZPA may be partly active, so this "
                    "may not be a clean pre-ZPA baseline")
        return ("BASELINE CAPTURED",
                "no synthetic IPs, as expected before ZPA is enabled")

    if n:
        corroborated = (f"; corroborated by the routing table ({iface})"
                        if tunnel else
                        "; note the routing table shows no tunnel for the "
                        "range, which is inconsistent — re-check ZCC state"
                        if tunnel is False else "")
        return ("ZPA IS STEERING",
                f"{n} domain(s) resolved into "
                f"{net or ZPA_SYNTHETIC_NET}{corroborated}")

    if zcc.get("state") == "not_detected":
        return ("NO STEERING OBSERVED",
                "no synthetic IPs, and ZCC is not installed on this host")
    if zcc.get("state") == "installed_not_running":
        return ("NO STEERING OBSERVED",
                "ZCC is installed but its daemon is not loaded — start "
                "Client Connector, then re-run")
    if tunnel is False:
        return ("NO STEERING OBSERVED",
                "ZCC is running, but nothing routes the synthetic range into "
                "a tunnel — Private Access is likely off or unauthenticated")
    return ("NO STEERING OBSERVED",
            f"a tunnel claims the synthetic range ({iface}) but no name "
            "resolved into it — check segment enrollment and access policy")


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


def l7_verified(value):
    """True when this l7_result proves an application responded."""
    return str(value).startswith(L7_VERIFIED_PREFIXES)


def l7_stats(rows):
    """Application-response breakdown over probes the L7 step actually ran.

    Returns None when --l7 was off, so callers can stay silent rather than
    print a section of zeroes.

    This exists because TCP reachability through ZPA is established by
    Client Connector locally: a port reads as OPEN as soon as ZCC accepts
    the connection, whether or not anything behind the App Connector is
    serving. A run could therefore report "249/249 TCP REACHABLE, 0 FAILING
    PROBES, 0 actionable findings" while more than half of those probes had
    no application on the other end. The L7 data was already being written
    to the CSV; it was simply absent from every headline that summarised it.
    """
    ran = [r for r in rows
           if str(r.get("status", "")) in OK_STATUSES and r.get("l7_result")]
    if not ran:
        return None
    verified = [r for r in ran if l7_verified(r.get("l7_result"))]
    unverified = [r for r in ran if not l7_verified(r.get("l7_result"))]

    breakdown = {}
    for r in ran:
        v = str(r.get("l7_result"))
        key = "L7_ERROR" if v.startswith("L7_ERROR:") else v
        breakdown[key] = breakdown.get(key, 0) + 1

    by_segment = {}
    for r in unverified:
        seg = str(r.get("segment", ""))
        by_segment[seg] = by_segment.get(seg, 0) + 1
    probed_by_segment = {}
    for r in ran:
        seg = str(r.get("segment", ""))
        probed_by_segment[seg] = probed_by_segment.get(seg, 0) + 1

    return {
        "probed": len(ran),
        "verified": len(verified),
        "unverified": len(unverified),
        "pct_verified": round(100.0 * len(verified) / len(ran), 1),
        "breakdown": breakdown,
        "unverified_by_segment": sorted(
            ((s, n, probed_by_segment.get(s, n)) for s, n in
             by_segment.items()), key=lambda t: (-t[1], t[0])),
    }


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


def _write_or_fallback(path, write_fn, label):
    """Write via write_fn(path); on OSError retry under %TEMP%.

    Results live only in memory until this call. A read-only output
    directory, a full disk or a path over MAX_PATH would otherwise discard
    an entire multi-hour run at the last step. Losing the run is strictly
    worse than writing it somewhere the operator did not ask for, so the
    fallback is taken and printed rather than raising.
    """
    try:
        write_fn(path)
        return path
    except OSError as e:
        alt_dir = os.path.join(tempfile.gettempdir(), "zpa-test-results")
        alt = os.path.join(alt_dir, os.path.basename(path))
        print(f"[!] Could not write {label} to {path}: {e}")
        try:
            os.makedirs(alt_dir, exist_ok=True)
            write_fn(alt)
            print(f"    Wrote it to {alt} instead — the run is not lost.")
            return alt
        except OSError as e2:
            print(f"[!] The fallback also failed ({e2}). "
                  f"This run's {label} could not be saved.")
            return ""


def run_test(args):
    args.scope_resolved = choose_scope(args)
    # Normalised once rather than read defensively in eight places. A
    # namespace assembled without these — a caller, or an older test
    # harness — would otherwise die with AttributeError partway through,
    # which is exactly how --tenant broke on export-targets in v1.8.1.
    args.dns_csv = getattr(args, "dns_csv", None)
    args.dns_sample = getattr(args, "dns_sample", 0)
    args.dns_ports = getattr(args, "dns_ports", None)
    args.dns_ports_all = getattr(args, "dns_ports_all", False)

    # With --dns-csv and no segment source, the run is a resolution sweep:
    # it still answers which names are steered, it just has nothing to join
    # against for ports or enrolment. That is a valid mode, so it must not
    # fail preflight for missing credentials.
    dns_standalone = bool(args.dns_csv) and not (
        args.targets_file or args.tenant or args.client_id
        or os.environ.get("ZSCALER_CLIENT_ID"))

    ok, checks = preflight_checks(
        args, need_api=not args.targets_file and not dns_standalone,
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

    synth = synthetic_net_for(args)
    zcc = detect_zcc()
    steer = windows_steering_path(synth)
    dnscfg = windows_dns_config()
    proxy = windows_proxy_config()
    if dns_standalone:
        segments, source = [], "none (--dns-csv resolve-only)"
    else:
        segments, source = load_segments(args)

    dns_by_name, dns_load, dns_build = None, None, None
    if args.dns_csv:
        dns_path = resolve_dns_csv_path(args.dns_csv)
        dns_by_name, dns_load = load_dns_csv(dns_path, args)
        targets, dns_build = build_dns_targets(dns_by_name, segments, args)
        skipped_wildcards = []
        stats = {"entries_total": dns_build["names_total"],
                 "entries_sampled_out": dns_build["names_sampled_out"],
                 "cidr_hosts_truncated": 0,
                 "ports_truncated": dns_build["ports_truncated"],
                 "segments_matched": dns_build["matched"],
                 "kinds": {"fqdn": dns_build["names_total"], "ip": 0,
                           "cidr": 0, "wildcard": 0}}
        source = f"dns-csv {os.path.basename(dns_path)}" + (
            "" if dns_standalone else f" x {source}")
    else:
        targets, skipped_wildcards, stats = build_targets(segments, args)

    k = stats["kinds"]
    print(f"[*] Scope: {args.scope_resolved.upper()}")
    if args.sipa_only:
        print("[*] SIPA filter active (ipAnchored=true segments only)")
    if args.dns_csv:
        print(f"[*] DNS export: {dns_path}")
        print(f"    {dns_load['rows']} rows -> {dns_build['names_total']} "
              "probeable names"
              + (f"; skipped {dns_load['skipped_type']} non-A/CNAME"
                 if dns_load["skipped_type"] else "")
              + (f", {dns_load['skipped_lookup']} lookup!=OK"
                 if dns_load["skipped_lookup"] else "")
              + (f", {dns_load['skipped_wildcard']} wildcard"
                 if dns_load["skipped_wildcard"] else "")
              + (f", {dns_load['duplicates']} duplicate"
                 if dns_load["duplicates"] else ""))
        print(f"    {dns_build['matched']} matched a ZPA segment "
              f"({dns_build['matched_exact']} by exact name, "
              f"{dns_build['matched_wildcard']} via a wildcard)")
        print(f"    {dns_build['probed']} probed on their segment's own "
              f"ports (max {DNS_CSV_PORT_CAP} per name)")
        if dns_build["broad_ports"]:
            print(f"    {dns_build['broad_ports']} matched a segment whose "
                  "every port range is wider than "
                  f"{DNS_CSV_MAX_RANGE_SPAN} — resolved, NOT probed: a wide "
                  "range says nothing about what any one host listens on, "
                  "and probing its endpoints would yield only timeouts")
            for sname, n in sorted(dns_build["broad_segments"].items(),
                                   key=lambda kv: -kv[1])[:5]:
                print(f"      {sname[:52]:<52} {n:>6} name(s)")
        print(f"    {dns_build['unmatched']} matched no segment"
              + (" — resolved, NOT probed (no guessed ports, no scan "
                 "footprint)" if not dns_build["fallback_ports"] else ""))
        if dns_build["fallback_ports"]:
            plist = ",".join(str(p) for p in dns_build["fallback_ports"])
            print(f"    {dns_build['fallback_used']} name(s) given "
                  f"--dns-ports {plist} because their segment supplied no "
                  "specific port")
            if not args.dns_ports_all:
                print(f"        tried in that order, stopping at the first "
                      "that answers — usually one connect per host, not "
                      f"{len(dns_build['fallback_ports'])}")
            if dns_build["udp_primary"]:
                names = ", ".join(f"{p}/tcp ({svc})"
                                  for p, svc in dns_build["udp_primary"])
                print(f"    [!] {names} — these services run over UDP. A TCP "
                      "connect to them times out on a")
                print("        perfectly healthy host, and this tool reads "
                      "TIMEOUT as 'traffic may not be")
                print("        steered'. Expect failures there that are not "
                      "failures.")
            for p, segs in sorted(dns_build["udp_confirmed"].items()):
                print(f"    [!] port {p} is defined as UDP by "
                      f"{len(segs)} matched segment(s) — confirmed by ZPA, "
                      "not inferred")
            total = (dns_build["fallback_used"]
                     * len(dns_build["fallback_ports"]))
            print(f"    [!] {dns_build['fallback_used']} names x "
                  f"{len(dns_build['fallback_ports'])} ports = {total} "
                  "connects across the estate")
            noisy = dns_build.get("scan_sensitive") or []
            if noisy:
                named = ", ".join(f"{p} ({svc})" for p, svc in noisy)
                print(f"        a horizontal sweep of {named} is a standard "
                      "IDS/EDR signature and will be")
                print("        attributed to the account running it — tell "
                      "whoever watches it first")
        print("    steering is settled — resolved, "
              "NOT probed (no guessed ports, no scan footprint)")
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
        print(f"[*] {stats['ports_truncated']} ports dropped by "
              + (f"the --dns-csv cap of {DNS_CSV_PORT_CAP} per name "
                 "(deliberate: it keeps a wide segment range from "
                 "multiplying across the export into a scan)"
                 if args.dns_csv else
                 "--max-ports cap (use --scope full for all ports)"))
    if skipped_wildcards:
        print(f"[!] {len(skipped_wildcards)} wildcard domains skipped "
              f"(re-run with --wildcard-probe <label> to include them)")

    if args.timeout < REFUSAL_LATENCY_S:
        print(f"[!] --timeout {args.timeout}s is below this platform's "
              f"~{REFUSAL_LATENCY_S}s connection-refusal latency, so a "
              "refused port will be")
        print("    reported as TIMEOUT rather than REFUSED. The summary "
              "reads those oppositely — a")
        print("    refusal proves the path works. Raise --timeout to "
              "distinguish them.")

    if not targets:
        sys.exit(
            "ERROR: no targets to probe — every entry was filtered out.\n"
            f"       {stats['segments_matched']} segment(s) matched the "
            "filters. Check --segment, --sipa-only, --enabled-only and\n"
            "       --sample-domains. Refusing to write a run whose verdict "
            "would assert a cause from zero evidence.")

    n_probes = estimate_probes(targets)
    print(f"[*] {len(targets)} targets / ~{n_probes} probes planned"
          + (f" (+ up to {args.retries} retry each)" if args.retries else ""))
    confirm_run(n_probes, args)

    # Bounds connects made by socket objects created after this point. It
    # does NOT bound getaddrinfo, which is why resolve() takes no timeout.
    socket.setdefaulttimeout(args.timeout)
    started = datetime.now(timezone.utc)

    # Two pooled phases. Resolution happens once per target; probing is then
    # one pool task per (target, port), so a segment's ports run in parallel.
    # A single flat pool also keeps sockets bounded by --workers — nesting a
    # pool inside each target would multiply into workers x ports and blow
    # past what a single process can hold open. Windows has no small
    # per-process socket cap to worry about, but nesting would still
    # multiply to workers x ports for no gain.
    all_rows, interrupted, worker_errors = [], False, 0
    ordered_untried, ordered_answered = 0, 0
    sleep_block = SleepBlocker().__enter__()
    if sleep_block.detail:
        print(f"[*] {sleep_block.detail}")
    pool = concurrent.futures.ThreadPoolExecutor(args.workers)
    try:
        res_futs = {pool.submit(resolve_target, t, args): i
                    for i, t in enumerate(targets)}
        resolutions = {}
        for fut in concurrent.futures.as_completed(res_futs):
            i = res_futs[fut]
            try:
                resolutions[i] = fut.result()
            except Exception as e:
                worker_errors += 1
                all_rows.append(probe_error_row(targets[i], e))

        units = []
        for i, t in enumerate(targets):
            res = resolutions.get(i)
            if res is None:
                continue
            all_rows.extend(target_static_rows(t, res))
            if res["dns_err"]:
                continue
            if t.get("dns_ordered") and t["ports"]:
                units.append((t, None, res))
            else:
                units.extend((t, p, res) for p in t["ports"])

        def run_unit(t, p, r):
            """Always returns a list of rows, so both shapes are uniform."""
            if p is None:
                return probe_ports_ordered(t, r, args)
            return [probe_port(t, p, r, args)]

        n_ordered = sum(1 for _, p, _ in units if p is None)
        print(f"    resolved {len(resolutions)}/{len(targets)} targets; "
              f"{len(units)} probe unit(s) queued"
              + (f" ({n_ordered} ordered: stop at the first port that "
                 "answers)" if n_ordered else ""))
        futures = {pool.submit(run_unit, t, p, r): t for t, p, r in units}
        done, step = 0, max(25, (len(futures) // 20) or 25)
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            try:
                rows = fut.result()
                all_rows.extend(rows)
                if t.get("dns_ordered"):
                    # What the early stop saved, counted here rather than
                    # left as an unexplained gap between planned and actual.
                    ordered_untried += max(0, len(t["ports"]) - len(rows))
                    if rows and str(rows[-1].get("status")) in \
                            ANSWERED_STATUSES:
                        ordered_answered += 1
            except Exception as e:
                # One bad unit must not discard a long run's results; record
                # it as a row so it is visible in the CSV, not a traceback.
                worker_errors += 1
                all_rows.append(probe_error_row(t, e))
            done += 1
            if done % step == 0 or done == len(futures):
                print(f"    probed {done}/{len(futures)} unit(s)")
    except KeyboardInterrupt:
        # long full-scope runs are worth salvaging — keep partial results
        interrupted = True
        print("\n[!] Interrupted — writing partial results collected so far.")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        sleep_block.__exit__(None, None, None)

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

    # After sorting, before writing: the cross-reference reads finished rows
    # and adds columns, so the probe path never has to know about the export.
    if args.dns_csv:
        annotate_dns_rows(all_rows, targets)

    out_dir = os.path.abspath(os.path.expanduser(args.output_dir))
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        # Not fatal: _write_or_fallback will place the results under %TEMP%.
        print(f"[!] Could not create {out_dir}: {e}")
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
    fieldnames = CSV_FIELDS + (DNS_CSV_FIELDS if args.dns_csv else [])

    def _write_csv(target):
        with open(target, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(all_rows)

    out_path = _write_or_fallback(out_path, _write_csv, "results CSV")

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
    verdict_label, verdict_detail = run_verdict(args, intercepted, zcc,
                                                steer, synth)
    lat = latency_stats(all_rows)
    l7s = l7_stats(all_rows)
    dstats = dns_stats(all_rows) if args.dns_csv else None

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
                     "timeout_s": args.timeout,
                     "l7_timeout_s": l7_timeout_for(args) if args.l7 else None,
                     "workers": args.workers},
        "zcc": zcc,
        "synthetic_net": str(synth),
        "windows": {"steering_path": steer, "dns": dnscfg,
                    "proxy": proxy,
                    "sleep_block": sleep_block.detail,
                    "os_version": platform.version()},
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
        "l7": l7s,
        "dns_csv": (None if not args.dns_csv else
                    {"path": dns_path, "load": dns_load,
                     "build": {k: (sorted(v) if isinstance(v, set) else
                                   {kk: sorted(vv) for kk, vv in v.items()}
                                   if k == "udp_confirmed" else v)
                               for k, v in dns_build.items()},
                     "crossref": dstats,
                     "ordered_probe": {"answered": ordered_answered,
                                       "ports_not_tried": ordered_untried}}),
        "slowest_segments": [{"segment": s, "median_ms": m, "probes": n}
                             for s, m, n in slowest_segments(all_rows)],

        "intercepted_domain_list": sorted(intercepted),
    }
    meta_path = os.path.join(out_dir, stem + ".meta.json")

    def _write_meta(target):
        with open(target, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    meta_path = _write_or_fallback(meta_path, _write_meta, "metadata")

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
    # Immediately below the reachability count, because that is the number
    # this qualifies: OPEN means ZCC accepted the connection, not that an
    # application answered.
    if l7s:
        print(f"  L7        {l7s['verified']}/{l7s['probed']} OPEN probes had "
              f"an application respond ({l7s['pct_verified']}%)")
    if worker_errors:
        print(f"  [!] {worker_errors} target(s) raised a probe error — see "
              "PROBE_ERROR rows in the CSV")

    print(_section("COVERAGE"))
    for line in coverage_report(stats, args, len(tcp_rows)):
        print(line)

    if ordered_answered or ordered_untried:
        planned = ordered_untried + sum(
            1 for r in all_rows if r.get("protocol") == "tcp")
        print(_section("ORDERED PROBES (stop at the first port that answers)"))
        print(f"    destinations answered  {ordered_answered:>7}")
        print(f"    ports not tried        {ordered_untried:>7}  "
              "an earlier port in the order already answered")
        print(f"    connects avoided       {ordered_untried:>7}  "
              f"of {planned} planned"
              + (f" ({100.0 * ordered_untried / planned:.0f}% fewer)"
                 if planned else ""))

    if dstats:
        print(_section("DNS CROSS-REFERENCE (export vs endpoint)"))
        print(f"    names checked  {dstats['names']:>6}")
        if dstats["enrolment_checked"]:
            print(f"    in a ZPA segment {dstats['in_zpa']:>4}   "
                  f"in none {dstats['not_in_zpa']:>6}")
        else:
            print("    in a ZPA segment  UNKNOWN — no segment inventory was "
                  "loaded, so enrolment")
            print("                      was never checked. Add "
                  "--targets-file for the ZPA join.")
        print(f"    steered        {dstats['steered']:>6}  "
              f"({dstats['pct_steered']}% of names)")
        print("\n    verdicts:")
        for v, n in sorted(dstats["verdicts"].items(), key=lambda kv: -kv[1]):
            mark = " [!]" if v == "NOT_STEERED_INTERNAL" else "    "
            print(f"     {mark} {v:<24} {n:>5}"
                  + (f"  — {DNS_VERDICTS[v]}" if v in DNS_VERDICTS else ""))

        for label, names, note in (
                ("STEERING GAP", dstats["steering_gap"],
                 "enrolled in a ZPA segment, but resolved to an internal IP "
                 "instead of into ZPA"),
                ("ENROLMENT GAP", dstats["enrolment_gap"],
                 "internal in DNS and in no ZPA segment at all — cannot be "
                 "steered until a segment covers them"),
                ("DNS DIVERGENCE", dstats["diverged"],
                 "endpoint resolved to an address the export does not list "
                 "— split-horizon, staleness, or a different resolver")):
            if not names:
                continue
            print(f"\n    {label} ({len(names)}) — {note}")
            for n in names[:INTERCEPT_LIST_CAP]:
                print(f"      {n}")
            if len(names) > INTERCEPT_LIST_CAP:
                print(f"      ... +{len(names) - INTERCEPT_LIST_CAP} more "
                      "(see dns_verdict in the CSV)")

    if l7s:
        print(_section("L7 VERIFICATION (application response on OPEN ports)"))
        print(f"    verified   {l7s['verified']:>5}  "
              f"({l7s['pct_verified']}% of {l7s['probed']} probes)")
        print(f"    unverified {l7s['unverified']:>5}  "
              "TCP opened, no application response")
        print(f"    l7 timeout {l7_timeout_for(args)}s "
              f"(--timeout {args.timeout}s; raise --l7-timeout to rule out a "
              "tight budget)")
        print("\n    breakdown:")
        for v, n in sorted(l7s["breakdown"].items(), key=lambda kv: -kv[1]):
            note = L7_ERROR_MEANING if v == "L7_ERROR" else L7_MEANINGS.get(v)
            mark = "    " if l7_verified(v) else " [!]"
            print(f"     {mark} {v:<24} {n:>5}"
                  + (f"  — {note}" if note else ""))
        if l7s["unverified_by_segment"]:
            print("\n    unverified by segment (unverified/probed):")
            for seg, n, tot in l7s["unverified_by_segment"][:ROLLUP_CAP]:
                print(f"      {seg[:44]:<44} {n:>5}/{tot}")

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
            # "behaved as expected" was previously printed on the strength of
            # the TCP result alone, which made a run where most probes had no
            # application response read as a clean pass.
            if l7s and l7s["unverified"]:
                print("    no TCP-level failures, but "
                      f"{l7s['unverified']} of {l7s['probed']} OPEN probes "
                      "had no application response — see L7 VERIFICATION")
    
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
                       dns_flush_ok, intercepted, l7s, dstats)
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
  // Mirrors l7_verified() in the Python: only a TLS handshake or an HTTP
  // status line proves an application answered.
  function l7ran(d){ return ok(d.status) && d.l7 !== ''; }
  function l7ok(d){ return d.l7.indexOf('TLS:') === 0
                        || d.l7.indexOf('HTTP:') === 0; }
  var PRED = {
    reachable: function(d){ return tcp(d) && ok(d.status); },
    failing:   function(d){ return tcp(d) && !ok(d.status); },
    flaky:     function(d){ return d.proto === 'tcp'
                                   && d.status === 'OPEN_FLAKY'; },
    dnsfail:   function(d){ return d.status.indexOf('DNS_FAIL') === 0; },
    steered:   function(d){ return d.steered === 'True'; },
    l7verified:   function(d){ return l7ran(d) && l7ok(d); },
    l7unverified: function(d){ return l7ran(d) && !l7ok(d); },
    dnssteered:   function(d){ return d.dnsv === 'STEERED'; },
    dnsgap:       function(d){ return d.dnsv === 'NOT_STEERED_INTERNAL'; },
    dnsnotinzpa:  function(d){ return d.dnsv !== '' && d.dnszpa === 'False'
                                     && d.dnsint === 'True'; }
  };
  var LABEL = {
    reachable: 'TCP reachable', failing: 'failing probes',
    flaky: 'flaky (retry only)', dnsfail: 'DNS failures',
    steered: 'ZPA-steered rows',
    l7verified: 'L7 verified (application responded)',
    l7unverified: 'OPEN with no application response',
    dnssteered: 'DNS names steered into ZPA',
    dnsgap: 'enrolled but resolved to an internal IP',
    dnsnotinzpa: 'internal in DNS, in no ZPA segment'
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
                  l7:      tr.getAttribute('data-l7')      || '',
                  dnsv:    tr.getAttribute('data-dnsv')    || '',
                  dnszpa:  tr.getAttribute('data-dnszpa')  || '',
                  dnsint:  tr.getAttribute('data-dnsint')  || '',
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
        # .get, not [], throughout: rows reach this function from callers as
        # well as from a results CSV, and one missing column should not be a
        # traceback in the reporting layer.
        interc = {r.get("domain", "") for r in rows
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
        # Derived from the rows, not from meta, so a CSV written before the
        # L7 summary existed still reports it.
        l7_ran = [r for r in tcp
                  if r.get("status") in OK_STATUSES and r.get("l7_result")]
        if l7_ran:
            l7_ok = [r for r in l7_ran if l7_verified(r.get("l7_result"))]
            l7_bad = len(l7_ran) - len(l7_ok)
            parts.append(_tile(f"{len(l7_ok)}/{len(l7_ran)}", "L7 verified",
                               "ok" if not l7_bad else "warn",
                               filt="l7verified"))
            parts.append(_tile(l7_bad, "no app response",
                               "bad" if l7_bad else "ok", filt="l7unverified"))
        # Derived from the rows for the same reason as the L7 pair: a CSV
        # written by any version renders correctly without its meta.
        dns_rows = [r for r in rows if r.get("dns_verdict")]
        if dns_rows:
            seen_names, dv = set(), {}
            for r in dns_rows:
                nm = str(r.get("probe_domain", ""))
                if nm in seen_names:
                    continue
                seen_names.add(nm)
                dv[r["dns_verdict"]] = dv.get(r["dns_verdict"], 0) + 1
                # "" is not-checked and must not count as an enrolment gap
                if str(r.get("dns_in_zpa")) == "False" \
                        and str(r.get("dns_has_internal")) == "True":
                    dv["_enrol"] = dv.get("_enrol", 0) + 1
                if str(r.get("dns_in_zpa")) not in ("True", "False"):
                    dv["_unknown"] = dv.get("_unknown", 0) + 1
            steered_n = dv.get("STEERED", 0)
            gap_n = dv.get("NOT_STEERED_INTERNAL", 0)
            parts.append(_tile(f"{steered_n}/{len(seen_names)}",
                               "DNS names steered",
                               "ok" if steered_n == len(seen_names) else "info",
                               filt="dnssteered"))
            parts.append(_tile(gap_n, "not steered (internal)",
                               "bad" if gap_n else "ok", filt="dnsgap"))
            if dv.get("_unknown"):
                # A count here would read as a coverage finding. It is not
                # one: nothing was checked.
                parts.append(_tile("n/a", "enrolment not checked", "info"))
            else:
                parts.append(_tile(dv.get("_enrol", 0),
                                   "internal, not in ZPA",
                                   "warn" if dv.get("_enrol") else "ok",
                                   filt="dnsnotinzpa"))
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
        # The DNS columns only exist on a --dns-csv run; adding them
        # unconditionally would render a block of empty cells on every
        # other report.
        cols += [c for c in DNS_CSV_FIELDS if any(c in r for r in rows)]
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
                f'data-l7="{html.escape(str(r.get("l7_result", "")))}" '
                f'data-dnsv="{html.escape(str(r.get("dns_verdict", "")))}" '
                f'data-dnszpa="{html.escape(str(r.get("dns_in_zpa", "")))}" '
                f'data-dnsint="{html.escape(str(r.get("dns_has_internal", "")))}" '
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
    SIPA anchors are IPv4, and this tool is scoped to IPv4 accordingly.
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

# Subcommands that read the synthetic range from a run's saved metadata
# rather than taking it as input. Accepting the flag here and ignoring it
# would silently produce a report keyed to the wrong range.
SYNTHETIC_NET_NOT_APPLICABLE = ("compare", "report", "tenants")


def add_synthetic_net_arg(p, suppress_default=False):
    """--synthetic-net, accepted both before and after the subcommand.

    It was previously only defined on the subparsers, so the natural global
    position produced 'argument cmd: invalid choice: 100.64.0.0/16' — an
    error that never names the option the user actually typed. Defining it
    on both parsers fixes that; the subparser copy uses SUPPRESS so that
    omitting it after the subcommand does not overwrite a value given
    before it.
    """
    kwargs = {"metavar": "CIDR",
              "help": "ZCC synthetic IP range for this tenant (default "
                      f"{DEFAULT_SYNTHETIC_NET}). Tenant-configurable and "
                      "commonly narrowed, e.g. 100.64.0.0/16. Too wide a "
                      "range reports CGNAT addresses as ZPA-steered. May be "
                      "given before or after the subcommand, or stored per "
                      "tenant"}
    if suppress_default:
        kwargs["default"] = argparse.SUPPRESS
    p.add_argument("--synthetic-net", **kwargs)


def add_api_args(p):
    p.add_argument("--tenant", metavar="NAME",
                   help="use a saved tenant (see the 'tenants' subcommand). "
                        "Without it, saved tenants are offered interactively; "
                        "selection is confirmed twice")
    add_synthetic_net_arg(p, suppress_default=True)
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
    # This build is Windows-only by design: it uses Find-NetRoute, NRPT
    # policy, the service registry and SetThreadExecutionState, none of
    # which exist elsewhere. Fail clearly rather than behave oddly.
    if platform.system() != "Windows":
        sys.exit("ERROR: this tool requires Windows. It uses Find-NetRoute, "
                 "NRPT policy, the\nservice registry and "
                 "SetThreadExecutionState, none of which exist on "
                 f"{platform.system()}.")

    # A Windows console defaults to an OEM code page (437 is common) while
    # Python defaults the stream to cp1252. Reconfiguring the stream to
    # UTF-8 without also telling the CONSOLE makes every non-ASCII glyph
    # render as mojibake, so both must be set, and before anything prints.
    #
    # SetConsoleOutputCP fails harmlessly when stdout is a pipe or a file
    # rather than a console — which is exactly when it is not needed.
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP.argtypes = [wintypes.UINT]
        ctypes.windll.kernel32.SetConsoleOutputCP.restype = wintypes.BOOL
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)   # CP_UTF8
    except (AttributeError, OSError, ValueError):
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(
        description="ZPA application segment connectivity tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run '<subcommand> --help' for per-command options.")
    add_synthetic_net_arg(ap)
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
               "The store lives at "
               "%USERPROFILE%\\.zpa-connectivity-tester\\tenants.json, with "
               "its ACL\nrestricted to your account and read back to "
               "confirm it (override with\n$ZPA_TENANT_STORE).\n"
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
                        "cached during the pre run can mask ZPA steering. "
                        "Needs no elevation on Windows")
    t.add_argument("--l7", action="store_true",
                   help="on OPEN ports, verify an app actually responds "
                        "(TLS handshake or HTTP status), not just TCP")
    t.add_argument("--l7-timeout", type=float, metavar="SECONDS",
                   help=f"timeout for the L7 step (default: {L7_TIMEOUT_FACTOR}x "
                        f"--timeout, clamped to {L7_TIMEOUT_FLOOR}-"
                        f"{L7_TIMEOUT_CEILING}s; an explicit value is not "
                        "clamped). A TCP "
                        "connect through ZPA completes locally at Client "
                        "Connector, but a TLS handshake has to reach the "
                        "backend via the App Connector — sharing --timeout "
                        "reports working apps as L7 timeouts")
    t.add_argument("--dns-csv", nargs="?", const=DEFAULT_DNS_CSV,
                   metavar="CSV",
                   help=f"drive the run from a DNS destinations export "
                        f"instead of the segment inventory. Bare --dns-csv "
                        f"looks for {DEFAULT_DNS_CSV} beside the script. "
                        "Each name is matched against the ZPA segments: "
                        "matched names are probed on that segment's OWN "
                        "ports, unmatched names are resolved and never "
                        "probed — no guessed ports, so no false timeouts and "
                        "no scan footprint. Combine with --targets-file (or "
                        "credentials) for the segment join; without one it "
                        "is a resolution-only sweep")
    t.add_argument("--dns-ports", metavar="PORTS",
                   help="[--dns-csv] comma-separated TCP ports to probe on "
                        "names whose matched segment supplied no specific "
                        "port (a wide range) or that matched no segment. "
                        "Default: none — those names are resolved only. "
                        "Never overrides a segment that defines discrete "
                        "ports. Ports whose service is UDP (123 NTP, 161 "
                        "SNMP, ...) are flagged: a TCP probe there times out "
                        "on a healthy host. Probing a fixed set across a "
                        "whole DNS export is a horizontal scan — notify "
                        "whoever watches IDS first")
    t.add_argument("--dns-ports-all", action="store_true",
                   help="[--dns-csv] probe every --dns-ports port on every "
                        "name instead of stopping at the first that answers. "
                        "Turns a liveness check into a port inventory and "
                        "multiplies the connect count accordingly")
    t.add_argument("--dns-sample", type=int, default=0, metavar="N",
                   help="cap the DNS export at N names (default 0 = every "
                        "record). --scope does not thin this list: sampling "
                        "would drop exactly the unenrolled names the export "
                        "exists to surface, and resolution is cheap")
    t.add_argument("--sipa-only", action="store_true",
                   help="only test Source IP Anchoring segments "
                        "(ipAnchored=true) — typical for --phase pre")
    t.add_argument("--enabled-only", action="store_true",
                   help="skip disabled segments")
    t.add_argument("--segment", metavar="SUBSTR",
                   help="only segments whose name contains SUBSTR")
    t.add_argument("--timeout", type=float, default=3.0,
                   help="per-probe timeout seconds (default 3). Windows "
                        "delivers a connection refusal at ~2.04s, so a value "
                        "below ~2.5 reports REFUSED as TIMEOUT — and the "
                        "summary reads those oppositely")
    t.add_argument("--workers", type=int, default=400,
                   help="concurrent probe workers (default 400 — measured on "
                        "Windows 11: 20 gives ~569 probes/s, 200 ~1106, 400 "
                        "~1827, 800 only ~1888. Windows has no per-process "
                        "socket limit to raise)")
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
    # Reject rather than ignore: these subcommands take the range from the
    # metadata written alongside the CSV, so honouring the flag here would
    # mean re-labelling a finished run with a range it was not measured on.
    # Validated here rather than at first use: --workers 0 and --timeout -1
    # are plausible typos that otherwise raise deep inside run_test, after
    # the OAuth token fetch, the full paged inventory pull and the
    # operator's confirmation. The cost of being wrong is the whole setup.
    for _flag, _val, _ok, _why in (
            ("--workers", getattr(args, "workers", None),
             lambda v: v >= 1, "must be at least 1"),
            ("--retries", getattr(args, "retries", None),
             lambda v: v >= 0, "cannot be negative"),
            ("--timeout", getattr(args, "timeout", None),
             lambda v: v > 0, "must be greater than 0"),
            ("--dns-sample", getattr(args, "dns_sample", None),
             lambda v: v >= 0, "cannot be negative")):
        if _val is not None and not _ok(_val):
            extra = ""
            if _flag == "--timeout":
                extra = (f" Values below ~{REFUSAL_LATENCY_S}s also report a "
                         "refused port as TIMEOUT, which the summary reads "
                         "as the opposite.")
            sys.exit(f"ERROR: {_flag} {_val} {_why}.{extra}")

    if (getattr(args, "synthetic_net", None)
            and args.cmd in SYNTHETIC_NET_NOT_APPLICABLE):
        sys.exit(f"ERROR: --synthetic-net does not apply to '{args.cmd}'. The "
                 "range is recorded per run in its .meta.json and read from "
                 "there. Set it on 'test'/'preflight'/'export-targets', or "
                 "store it per tenant with 'tenants add'.")
    args.func(args)


if __name__ == "__main__":
    main()
