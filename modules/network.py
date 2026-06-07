"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    local_os · modules · network.py                          ║
║              Enterprise-Grade Network Reconnaissance Module                  ║
║                                                                              ║
║  Features:                                                                   ║
║    • TCP/UDP port scanner  (async, threaded, banner grabbing)                ║
║    • ICMP / TCP ping  with RTT statistics (min/avg/max/jitter)               ║
║    • DNS resolver  (A/AAAA/MX/NS/TXT/CNAME/SOA/PTR/SRV)                    ║
║    • Reverse DNS & batch PTR lookup                                          ║
║    • Traceroute  (UDP/ICMP, TTL-based, cross-platform)                       ║
║    • Whois query  (raw TCP whois protocol)                                   ║
║    • HTTP/HTTPS header inspector & redirect chain follower                   ║
║    • SSL/TLS certificate inspector                                           ║
║    • Network interface enumeration                                           ║
║    • ARP table reader                                                        ║
║    • Subnet calculator  (CIDR, hosts, broadcast, mask)                       ║
║    • Connection table  (active sockets via psutil)                           ║
║    • Interactive terminal menu integrated with core.ui                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : local_os project
License : MIT
Python  : ≥ 3.10
Deps    : rich, psutil  (optional: dnspython, requests)
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Generator, Iterator
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ─── optional third-party ────────────────────────────────────────────────────
try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

try:
    import dns.resolver
    import dns.reversename
    import dns.rdatatype
    _DNSPYTHON = True
except ImportError:
    _DNSPYTHON = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.progress import (
        Progress, BarColumn, TextColumn,
        TimeElapsedColumn, SpinnerColumn, MofNCompleteColumn,
    )
    from rich.live import Live
    from rich.text import Text
    from rich import print as rprint
    _RICH = True
    _console = Console()
except ImportError:
    _RICH = False
    _console = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT        : float = 1.5     # seconds per connection attempt
DEFAULT_THREADS        : int   = 256     # port-scan thread pool size
DEFAULT_PING_COUNT     : int   = 4       # ICMP echo repetitions
DEFAULT_PING_TIMEOUT   : float = 2.0
BANNER_TIMEOUT         : float = 2.0
WHOIS_PORT             : int   = 43
WHOIS_TIMEOUT          : float = 8.0
HTTP_TIMEOUT           : float = 10.0
MAX_REDIRECTS          : int   = 10
TRACEROUTE_MAX_HOPS    : int   = 30
TRACEROUTE_TIMEOUT     : float = 2.0
TRACEROUTE_PROBES      : int   = 3

# ─── Well-known service names (supplement socket.getservbyport) ───────────────
COMMON_PORTS: dict[int, str] = {
    20: "FTP-data",   21: "FTP",       22: "SSH",        23: "Telnet",
    25: "SMTP",       53: "DNS",       67: "DHCP",       68: "DHCP",
    69: "TFTP",       80: "HTTP",      110: "POP3",      119: "NNTP",
    123: "NTP",       143: "IMAP",     161: "SNMP",      162: "SNMP-trap",
    179: "BGP",       194: "IRC",      389: "LDAP",      443: "HTTPS",
    445: "SMB",       465: "SMTPS",    514: "Syslog",    515: "LPD",
    587: "SMTP-sub",  631: "IPP",      636: "LDAPS",     873: "rsync",
    993: "IMAPS",     995: "POP3S",    1080: "SOCKS",    1194: "OpenVPN",
    1433: "MSSQL",    1521: "Oracle",  1723: "PPTP",     2049: "NFS",
    2181: "ZooKeep",  2375: "Docker",  2376: "Docker-TLS",
    3000: "Dev-HTTP", 3306: "MySQL",   3389: "RDP",      4369: "EPMD",
    5000: "Flask",    5432: "Postgres",5601: "Kibana",   5672: "AMQP",
    5900: "VNC",      6379: "Redis",   6443: "K8s-API",  6667: "IRC",
    8000: "HTTP-alt", 8080: "HTTP-px", 8443: "HTTPS-alt",8888: "Jupyter",
    9000: "PHP-FPM",  9090: "Prometheus",9092: "Kafka",  9200: "Elastic",
    9300: "Elastic-T",10250:"K8s-node",15672:"RabbitMQ", 27017:"MongoDB",
    27018:"MongoDB",  50070:"HDFS",    61616:"ActiveMQ",
}

PORT_GROUPS: dict[str, list[int]] = {
    "top-20"  : [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080],
    "top-100" : [
        7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,
        139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,
        548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,
        1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,
        3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,
        5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,
        9100,9999,10000,32768,49152,49153,49154,49155,49156,49157,
    ],
    "web"     : [80,81,443,8000,8008,8080,8081,8443,8888,9000,3000,4000,5000],
    "db"      : [1433,1521,3306,5432,6379,9200,9300,27017,27018,5672,9092],
    "remote"  : [22,23,3389,5900,5901,2222,4899],
    "mail"    : [25,110,143,465,587,993,995],
    "dns"     : [53,5353,853],
}

DNS_RECORD_TYPES = ["A","AAAA","MX","NS","TXT","CNAME","SOA","PTR","SRV","CAA"]


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port    : int
    proto   : str
    state   : str          # "open" | "closed" | "filtered"
    service : str
    banner  : str = ""
    latency : float = 0.0  # ms


@dataclass
class PingResult:
    host        : str
    ip          : str
    packets_sent: int
    packets_recv: int
    rtt_min     : float
    rtt_avg     : float
    rtt_max     : float
    rtt_jitter  : float
    alive       : bool


@dataclass
class DnsRecord:
    name   : str
    rtype  : str
    ttl    : int
    data   : str


@dataclass
class TraceHop:
    ttl     : int
    ip      : str
    hostname: str
    rtts    : list[float]  # ms per probe (* = timeout)


@dataclass
class CertInfo:
    subject    : dict
    issuer     : dict
    san        : list[str]
    not_before : datetime
    not_after  : datetime
    serial     : str
    version    : int
    sig_algo   : str
    expired    : bool
    days_left  : int


@dataclass
class HttpInfo:
    url         : str
    status_code : int
    reason      : str
    headers     : dict[str, str]
    redirect_chain: list[tuple[int, str]]
    server      : str
    elapsed_ms  : float
    tls         : CertInfo | None = None


@dataclass
class NetworkInterface:
    name       : str
    addresses  : list[dict]   # {family, addr, netmask, broadcast}
    stats      : dict         # speed, duplex, mtu, isup
    mac        : str


@dataclass
class SubnetInfo:
    network      : str
    broadcast    : str
    netmask      : str
    wildcard     : str
    prefix_len   : int
    total_hosts  : int
    usable_hosts : int
    first_host   : str
    last_host    : str
    ip_class     : str
    is_private   : bool
    ip_type      : str


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve(host: str) -> str:
    """Resolve hostname → IPv4, return as-is if already IP."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve '{host}': {exc}") from exc


def _service_name(port: int, proto: str = "tcp") -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def _print(msg: str, style: str = "") -> None:
    if _RICH and _console:
        _console.print(msg, style=style)
    else:
        print(msg)


def _prompt(label: str, default: str = "") -> str:
    if _RICH:
        return Prompt.ask(label, default=default)
    v = input(f"{label} [{default}]: ").strip()
    return v or default


def _confirm(label: str, default: bool = False) -> bool:
    if _RICH:
        return Confirm.ask(label, default=default)
    return input(f"{label} [y/N]: ").strip().lower() in ("y", "yes")


def _int_prompt(label: str, default: int = 0) -> int:
    if _RICH:
        return IntPrompt.ask(label, default=default)
    raw = input(f"{label} [{default}]: ").strip()
    return int(raw) if raw.isdigit() else default


def _progress(description: str = "Working") -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=36),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=_console,
        transient=True,
    )


def _grab_banner(ip: str, port: int, timeout: float = BANNER_TIMEOUT) -> str:
    """
    Attempt a plain-text banner read.
    Works for SSH, FTP, SMTP, POP3, IMAP, etc.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return data.decode(errors="replace").strip()[:120]
            except Exception:
                # Send a nudge for HTTP-like services
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256)
                    return data.decode(errors="replace").strip()[:120]
                except Exception:
                    return ""
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
#  1. Port Scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_port_tcp(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    grab_banner: bool = False,
) -> PortResult:
    """Attempt a TCP SYN-style connect to (host, port)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - t0) * 1000
            banner = _grab_banner(host, port) if grab_banner else ""
            return PortResult(
                port    = port,
                proto   = "tcp",
                state   = "open",
                service = _service_name(port, "tcp"),
                banner  = banner,
                latency = round(latency, 2),
            )
    except (ConnectionRefusedError, socket.error):
        return PortResult(port=port, proto="tcp", state="closed",
                          service=_service_name(port))
    except (socket.timeout, TimeoutError, OSError):
        return PortResult(port=port, proto="tcp", state="filtered",
                          service=_service_name(port))


def scan_port_udp(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> PortResult:
    """
    Heuristic UDP probe.
    Sends empty payload; ICMP port-unreachable → closed, else open|filtered.
    Note: Requires root on Linux for raw ICMP detection.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (host, port))
            try:
                s.recv(1024)
                return PortResult(port=port, proto="udp", state="open",
                                  service=_service_name(port, "udp"))
            except socket.timeout:
                return PortResult(port=port, proto="udp", state="open|filtered",
                                  service=_service_name(port, "udp"))
    except ConnectionRefusedError:
        return PortResult(port=port, proto="udp", state="closed",
                          service=_service_name(port, "udp"))
    except Exception:
        return PortResult(port=port, proto="udp", state="filtered",
                          service=_service_name(port, "udp"))


def scan_ports(
    host: str,
    ports: list[int],
    *,
    proto: str = "tcp",
    timeout: float = DEFAULT_TIMEOUT,
    max_threads: int = DEFAULT_THREADS,
    grab_banners: bool = False,
    open_only: bool = True,
    on_result: Callable[[PortResult], None] | None = None,
) -> list[PortResult]:
    """
    Multi-threaded port scan.

    Parameters
    ----------
    host         : target hostname or IP
    ports        : list of port numbers
    proto        : "tcp" or "udp"
    timeout      : per-connection timeout (seconds)
    max_threads  : thread-pool size
    grab_banners : attempt banner grab on open TCP ports
    open_only    : return only open ports
    on_result    : optional callback called immediately for each result

    Returns list of PortResult sorted by port number.
    """
    ip = _resolve(host)
    results: list[PortResult] = []
    lock = threading.Lock()

    def _worker(port: int) -> PortResult:
        if proto == "udp":
            r = scan_port_udp(ip, port, timeout)
        else:
            r = scan_port_tcp(ip, port, timeout, grab_banner=grab_banners)
        with lock:
            if not open_only or r.state in ("open", "open|filtered"):
                results.append(r)
            if on_result:
                on_result(r)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as pool:
        futures = {pool.submit(_worker, p): p for p in ports}
        concurrent.futures.wait(futures)

    results.sort(key=lambda r: r.port)
    return results


def expand_port_range(spec: str) -> list[int]:
    """
    Parse port specification into sorted unique port list.
    Examples: "22,80,443", "1-1024", "top-20", "web", "8080,9000-9010"
    """
    spec = spec.strip()

    # Named groups
    if spec in PORT_GROUPS:
        return sorted(set(PORT_GROUPS[spec]))

    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if "-" in token and not token.startswith("-"):
            parts = token.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
                ports.update(range(max(1, lo), min(65535, hi) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(token))
            except ValueError:
                pass
    return sorted(ports)


# ─────────────────────────────────────────────────────────────────────────────
#  2. Ping  (ICMP echo via subprocess for portability; raw socket on Linux)
# ─────────────────────────────────────────────────────────────────────────────

def ping(
    host: str,
    count: int = DEFAULT_PING_COUNT,
    timeout: float = DEFAULT_PING_TIMEOUT,
    *,
    interval: float = 0.5,
) -> PingResult:
    """
    Cross-platform ICMP ping using system ping binary.
    Falls back to TCP-connect probe if ping binary fails.
    """
    try:
        ip = _resolve(host)
    except ValueError:
        ip = host

    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    elif system == "darwin":
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), "-i", str(interval), host]
    else:  # Linux
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), "-i", str(interval), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * count + 5,
        )
        output = proc.stdout + proc.stderr
        return _parse_ping_output(host, ip, output, count)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback: TCP connect probe
        return _tcp_ping(host, ip, count, timeout)


def _parse_ping_output(host: str, ip: str, output: str, count: int) -> PingResult:
    """Extract statistics from ping command output (cross-platform)."""

    # Packet loss
    recv_match = re.search(r"(\d+) (?:packets )?received", output)
    recv = int(recv_match.group(1)) if recv_match else 0

    # RTT stats  (Linux/macOS: min/avg/max/mdev or min/avg/max)
    rtt_match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?",
        output,
        re.IGNORECASE,
    )
    # Windows: Minimum = Xms, Maximum = Xms, Average = Xms
    win_match = re.search(
        r"Minimum\s*=\s*([\d.]+)ms.*?Maximum\s*=\s*([\d.]+)ms.*?Average\s*=\s*([\d.]+)ms",
        output,
        re.IGNORECASE | re.DOTALL,
    )

    if rtt_match:
        rmin = float(rtt_match.group(1))
        ravg = float(rtt_match.group(2))
        rmax = float(rtt_match.group(3))
        jitter = float(rtt_match.group(4)) if rtt_match.group(4) else round(rmax - rmin, 3)
    elif win_match:
        rmin = float(win_match.group(1))
        rmax = float(win_match.group(2))
        ravg = float(win_match.group(3))
        jitter = round(rmax - rmin, 3)
    else:
        rmin = ravg = rmax = jitter = 0.0

    return PingResult(
        host         = host,
        ip           = ip,
        packets_sent = count,
        packets_recv = recv,
        rtt_min      = rmin,
        rtt_avg      = ravg,
        rtt_max      = rmax,
        rtt_jitter   = jitter,
        alive        = recv > 0,
    )


def _tcp_ping(host: str, ip: str, count: int, timeout: float) -> PingResult:
    """Fallback: TCP-connect latency probe on port 80."""
    rtts: list[float] = []
    for _ in range(count):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, 80), timeout=timeout):
                rtts.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.2)

    recv = len(rtts)
    if rtts:
        rmin = min(rtts)
        rmax = max(rtts)
        ravg = sum(rtts) / recv
        jitter = rmax - rmin
    else:
        rmin = ravg = rmax = jitter = 0.0

    return PingResult(
        host         = host,
        ip           = ip,
        packets_sent = count,
        packets_recv = recv,
        rtt_min      = round(rmin, 3),
        rtt_avg      = round(ravg, 3),
        rtt_max      = round(rmax, 3),
        rtt_jitter   = round(jitter, 3),
        alive        = recv > 0,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  3. DNS
# ─────────────────────────────────────────────────────────────────────────────

def dns_lookup(
    name: str,
    record_type: str = "A",
    nameserver: str | None = None,
) -> list[DnsRecord]:
    """
    Resolve a DNS record.
    Uses dnspython if available, falls back to socket for A records.
    """
    record_type = record_type.upper()
    records: list[DnsRecord] = []

    if _DNSPYTHON:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        try:
            answers = resolver.resolve(name, record_type)
            for rdata in answers:
                records.append(DnsRecord(
                    name  = name,
                    rtype = record_type,
                    ttl   = answers.rrset.ttl if answers.rrset else 0,
                    data  = str(rdata),
                ))
        except Exception as exc:
            raise ValueError(f"DNS lookup failed: {exc}") from exc
    else:
        # Fallback: only A / AAAA via socket
        if record_type not in ("A", "AAAA", "ANY"):
            raise RuntimeError(
                "Install 'dnspython' for full DNS record type support.\n"
                "Run: pip install dnspython"
            )
        family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
        try:
            results = socket.getaddrinfo(name, None, family)
            seen: set[str] = set()
            for r in results:
                ip = r[4][0]
                if ip not in seen:
                    seen.add(ip)
                    records.append(DnsRecord(name=name, rtype=record_type, ttl=0, data=ip))
        except socket.gaierror as exc:
            raise ValueError(f"DNS lookup failed: {exc}") from exc

    return records


def dns_lookup_all(
    name: str,
    nameserver: str | None = None,
) -> dict[str, list[DnsRecord]]:
    """Query all common record types for a domain."""
    results: dict[str, list[DnsRecord]] = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            records = dns_lookup(name, rtype, nameserver)
            if records:
                results[rtype] = records
        except Exception:
            pass
    return results


def reverse_dns(ip: str) -> str:
    """PTR lookup for an IP address."""
    try:
        if _DNSPYTHON:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR")
            return str(answers[0]).rstrip(".")
        else:
            return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def batch_ptr(
    ips: list[str],
    max_threads: int = 64,
) -> dict[str, str]:
    """Parallel reverse DNS for a list of IPs."""
    results: dict[str, str] = {}
    lock = threading.Lock()

    def _lookup(ip: str) -> None:
        hostname = reverse_dns(ip)
        with lock:
            results[ip] = hostname

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as pool:
        pool.map(_lookup, ips)
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  4. Traceroute
# ─────────────────────────────────────────────────────────────────────────────

def traceroute(
    host: str,
    max_hops: int = TRACEROUTE_MAX_HOPS,
    timeout: float = TRACEROUTE_TIMEOUT,
    probes: int = TRACEROUTE_PROBES,
) -> list[TraceHop]:
    """
    UDP-based traceroute (cross-platform via subprocess).
    On Windows uses tracert; on Unix uses traceroute.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)),
               "-q", str(probes), host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=max_hops * timeout * probes + 10,
        )
        return _parse_traceroute(proc.stdout + proc.stderr, probes)
    except FileNotFoundError:
        return _raw_traceroute(host, max_hops, timeout, probes)
    except subprocess.TimeoutExpired:
        return []


def _parse_traceroute(output: str, probes: int) -> list[TraceHop]:
    """Parse traceroute/tracert text output into TraceHop list."""
    hops: list[TraceHop] = []
    # Linux/macOS: " 1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms"
    # Windows:     " 1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    linux_re = re.compile(
        r"^\s*(\d+)\s+((?:\*\s*|\d+\.\d+\.\d+\.\d+\s+\d+\.?\d*\s+ms\s*)+)",
        re.MULTILINE,
    )
    hop_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([\d.]+)\s+ms")
    star_re = re.compile(r"\*")

    for line in output.splitlines():
        # Skip headers
        if re.match(r"^\s*(traceroute|Tracing|tracert|over)", line, re.IGNORECASE):
            continue
        ttl_match = re.match(r"^\s*(\d+)", line)
        if not ttl_match:
            continue
        ttl = int(ttl_match.group(1))
        if ttl == 0:
            continue

        ip_matches  = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
        rtt_matches = re.findall(r"([\d.]+)\s*ms", line)
        stars       = len(re.findall(r"\*", line))

        ip       = ip_matches[0] if ip_matches else "*"
        rtts     = [float(r) for r in rtt_matches[:probes]]
        rtts    += [-1.0] * (probes - len(rtts))  # -1.0 means timeout

        hops.append(TraceHop(
            ttl      = ttl,
            ip       = ip,
            hostname = "",
            rtts     = rtts,
        ))

    return hops


def _raw_traceroute(
    host: str,
    max_hops: int,
    timeout: float,
    probes: int,
) -> list[TraceHop]:
    """
    Raw socket UDP traceroute (requires root / CAP_NET_RAW on Linux).
    Falls back gracefully if permission denied.
    """
    try:
        dst_ip = _resolve(host)
    except ValueError:
        return []

    hops: list[TraceHop] = []
    port = 33434  # classic traceroute destination port

    for ttl in range(1, max_hops + 1):
        rtts: list[float] = []
        hop_ip = "*"

        for _ in range(probes):
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            recv_sock.settimeout(timeout)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            try:
                recv_sock.bind(("", port))
                send_sock.sendto(b"", (dst_ip, port))
                t0 = time.perf_counter()
                try:
                    data, addr = recv_sock.recvfrom(512)
                    rtt = (time.perf_counter() - t0) * 1000
                    hop_ip = addr[0]
                    rtts.append(round(rtt, 3))
                except socket.timeout:
                    rtts.append(-1.0)
            except PermissionError:
                return []
            finally:
                recv_sock.close()
                send_sock.close()

        hops.append(TraceHop(ttl=ttl, ip=hop_ip, hostname="", rtts=rtts))
        if hop_ip == dst_ip:
            break

    return hops


# ─────────────────────────────────────────────────────────────────────────────
#  5. Whois
# ─────────────────────────────────────────────────────────────────────────────

_WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "ru":  "whois.tcinet.ru",
    "uk":  "whois.nic.uk",
    "de":  "whois.denic.de",
    "jp":  "whois.jprs.jp",
    "cn":  "whois.cnnic.cn",
    "fr":  "whois.nic.fr",
    "au":  "whois.auda.org.au",
    "ca":  "whois.cira.ca",
    "br":  "whois.registro.br",
}
_WHOIS_IANA = "whois.iana.org"


def whois_query(target: str, server: str | None = None) -> str:
    """
    Perform a raw whois lookup over TCP port 43.
    Auto-selects whois server based on TLD.
    """
    target = target.strip().lower()

    # Determine server
    if server is None:
        tld = target.rsplit(".", 1)[-1] if "." in target else ""
        server = _WHOIS_SERVERS.get(tld, _WHOIS_IANA)

    try:
        with socket.create_connection((server, WHOIS_PORT), timeout=WHOIS_TIMEOUT) as s:
            s.sendall(f"{target}\r\n".encode())
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode(errors="replace")
    except Exception as exc:
        raise ConnectionError(f"Whois query to {server} failed: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
#  6. HTTP / HTTPS Inspector
# ─────────────────────────────────────────────────────────────────────────────

def inspect_http(
    url: str,
    *,
    follow_redirects: bool = True,
    timeout: float = HTTP_TIMEOUT,
    verify_ssl: bool = True,
    user_agent: str = "local_os/1.0 (network scanner)",
) -> HttpInfo:
    """
    Fetch HTTP headers and follow redirect chains.
    Returns HttpInfo with optional TLS certificate details.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    chain: list[tuple[int, str]] = []
    current_url = url
    t0 = time.perf_counter()

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    headers_dict: dict[str, str] = {}
    status_code = 0
    reason = ""
    tls_info: CertInfo | None = None

    for _ in range(MAX_REDIRECTS):
        parsed = urlparse(current_url)
        req = Request(
            current_url,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
            method="HEAD",
        )
        try:
            # We need raw socket for cert extraction
            if parsed.scheme == "https":
                tls_info = _get_cert_info(parsed.hostname or "", parsed.port or 443, ctx)

            with urlopen(req, timeout=timeout, context=ctx if parsed.scheme == "https" else None) as resp:
                status_code = resp.status
                reason = resp.reason or ""
                headers_dict = dict(resp.headers)
                location = resp.headers.get("Location")
                chain.append((status_code, current_url))
                if follow_redirects and location and status_code in (301, 302, 303, 307, 308):
                    current_url = location
                    continue
                break
        except HTTPError as e:
            status_code = e.code
            reason = e.reason or ""
            headers_dict = dict(e.headers) if e.headers else {}
            chain.append((status_code, current_url))
            break
        except URLError as e:
            raise ConnectionError(f"HTTP request failed: {e.reason}") from e

    elapsed = (time.perf_counter() - t0) * 1000

    return HttpInfo(
        url           = current_url,
        status_code   = status_code,
        reason        = reason,
        headers       = headers_dict,
        redirect_chain = chain[:-1],  # exclude final destination
        server        = headers_dict.get("Server", ""),
        elapsed_ms    = round(elapsed, 2),
        tls           = tls_info,
    )


def _get_cert_info(hostname: str, port: int, ctx: ssl.SSLContext) -> CertInfo | None:
    """Extract TLS certificate details via raw SSL socket."""
    try:
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return None

                def _parse_dn(items: tuple) -> dict:
                    return {k: v for pair in items for k, v in pair}

                subject = _parse_dn(cert.get("subject", ()))
                issuer  = _parse_dn(cert.get("issuer", ()))
                san_raw = cert.get("subjectAltName", ())
                san     = [v for _, v in san_raw]

                def _parse_dt(s: str) -> datetime:
                    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

                not_before = _parse_dt(cert["notBefore"])
                not_after  = _parse_dt(cert["notAfter"])
                now        = datetime.now(timezone.utc)
                days_left  = (not_after - now).days

                return CertInfo(
                    subject    = subject,
                    issuer     = issuer,
                    san        = san,
                    not_before = not_before,
                    not_after  = not_after,
                    serial     = cert.get("serialNumber", ""),
                    version    = cert.get("version", 0),
                    sig_algo   = "",  # not exposed by stdlib ssl
                    expired    = days_left < 0,
                    days_left  = max(days_left, 0),
                )
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  7. Network Interfaces
# ─────────────────────────────────────────────────────────────────────────────

def get_interfaces() -> list[NetworkInterface]:
    """
    Enumerate local network interfaces.
    Requires psutil for full stats; falls back to socket for basic info.
    """
    if _PSUTIL:
        return _interfaces_psutil()
    return _interfaces_socket()


def _interfaces_psutil() -> list[NetworkInterface]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    result: list[NetworkInterface] = []

    AF_NAMES = {
        socket.AF_INET:  "IPv4",
        socket.AF_INET6: "IPv6",
        psutil.AF_LINK:  "MAC",
    }

    for iface, addr_list in addrs.items():
        mac = ""
        addresses: list[dict] = []
        for addr in addr_list:
            family = AF_NAMES.get(addr.family, str(addr.family))
            entry: dict = {
                "family"    : family,
                "address"   : addr.address,
                "netmask"   : addr.netmask or "",
                "broadcast" : addr.broadcast or "",
            }
            addresses.append(entry)
            if addr.family == psutil.AF_LINK:
                mac = addr.address

        st = stats.get(iface)
        stat_dict: dict = {
            "speed"  : getattr(st, "speed",   0),
            "duplex" : getattr(st, "duplex",  ""),
            "mtu"    : getattr(st, "mtu",     0),
            "isup"   : getattr(st, "isup", False),
        }
        result.append(NetworkInterface(
            name      = iface,
            addresses = addresses,
            stats     = stat_dict,
            mac       = mac,
        ))
    return result


def _interfaces_socket() -> list[NetworkInterface]:
    """Minimal fallback using socket (hostname + primary IP only)."""
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "127.0.0.1"
    return [NetworkInterface(
        name      = "primary",
        addresses = [{"family": "IPv4", "address": ip, "netmask": "", "broadcast": ""}],
        stats     = {},
        mac       = "",
    )]


def get_connections(
    kind: str = "inet",
    status_filter: list[str] | None = None,
) -> list[dict]:
    """
    Return active network connections (requires psutil).
    kind: 'inet', 'inet4', 'inet6', 'tcp', 'udp', 'all'
    """
    if not _PSUTIL:
        raise RuntimeError("Install psutil: pip install psutil")

    conns = psutil.net_connections(kind=kind)
    rows: list[dict] = []

    for c in conns:
        status = c.status or ""
        if status_filter and status not in status_filter:
            continue
        try:
            proc_name = psutil.Process(c.pid).name() if c.pid else ""
        except Exception:
            proc_name = ""

        rows.append({
            "proto"  : "tcp" if c.type == socket.SOCK_STREAM else "udp",
            "laddr"  : f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "raddr"  : f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status" : status,
            "pid"    : c.pid or 0,
            "process": proc_name,
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  8. ARP Table
# ─────────────────────────────────────────────────────────────────────────────

def get_arp_table() -> list[dict]:
    """
    Read the system ARP cache.
    Cross-platform via 'arp -a' subprocess.
    """
    try:
        proc = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
        )
        return _parse_arp(proc.stdout)
    except Exception:
        return []


def _parse_arp(output: str) -> list[dict]:
    entries: list[dict] = []
    for line in output.splitlines():
        # Linux: "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"
        # macOS: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
        # Win:   "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
        ip_match  = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac_match = re.search(r"([0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}"
                              r"[:\-][0-9a-f]{2}[:\-][0-9a-f]{2}[:\-][0-9a-f]{2})",
                              line, re.IGNORECASE)
        if ip_match and mac_match:
            entries.append({
                "ip" : ip_match.group(1),
                "mac": mac_match.group(1).replace("-", ":").lower(),
            })
    return entries


# ─────────────────────────────────────────────────────────────────────────────
#  9. Subnet Calculator
# ─────────────────────────────────────────────────────────────────────────────

def subnet_calc(cidr: str) -> SubnetInfo:
    """
    Parse CIDR notation and return detailed subnet information.
    Accepts: "192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {cidr}") from exc

    is_v4 = isinstance(net, ipaddress.IPv4Network)
    hosts = list(net.hosts())

    if is_v4:
        ip_class = _ipv4_class(str(net.network_address))
        is_private = net.is_private
        ip_type = (
            "Loopback"   if net.is_loopback  else
            "Multicast"  if net.is_multicast else
            "Link-local" if net.is_link_local else
            "Private"    if net.is_private    else
            "Public"
        )
        wildcard = str(net.hostmask)
        broadcast = str(net.broadcast_address)
    else:
        ip_class  = "IPv6"
        is_private = net.is_private
        ip_type = "Private" if net.is_private else "Global"
        wildcard  = ""
        broadcast = ""

    return SubnetInfo(
        network      = str(net.network_address),
        broadcast    = broadcast,
        netmask      = str(net.netmask),
        wildcard     = wildcard,
        prefix_len   = net.prefixlen,
        total_hosts  = net.num_addresses,
        usable_hosts = max(0, net.num_addresses - 2) if is_v4 else net.num_addresses,
        first_host   = str(hosts[0]) if hosts else str(net.network_address),
        last_host    = str(hosts[-1]) if hosts else str(net.broadcast_address),
        ip_class     = ip_class,
        is_private   = is_private,
        ip_type      = ip_type,
    )


def _ipv4_class(ip: str) -> str:
    first = int(ip.split(".")[0])
    if first < 128:   return "A"
    if first < 192:   return "B"
    if first < 224:   return "C"
    if first < 240:   return "D (Multicast)"
    return "E (Reserved)"


# ─────────────────────────────────────────────────────────────────────────────
#  10. Display helpers (Rich tables)
# ─────────────────────────────────────────────────────────────────────────────

def _display_port_results(results: list[PortResult], host: str) -> None:
    if not results:
        _print("[yellow]No open ports found.[/yellow]")
        return
    if not _RICH:
        for r in results:
            print(f"{r.port}/{r.proto:<3}  {r.state:<12}  {r.service:<16}  {r.banner}")
        return

    table = Table(
        title       = f"Port Scan — {host}",
        border_style = "cyan",
        show_lines   = False,
    )
    table.add_column("Port",    style="bold yellow", justify="right", width=7)
    table.add_column("Proto",   style="dim",         width=5)
    table.add_column("State",   width=12)
    table.add_column("Service", style="cyan",        width=16)
    table.add_column("Latency", justify="right",     width=10)
    table.add_column("Banner",  style="dim",         max_width=50)

    for r in results:
        state_style = (
            "[bold green]open[/]"     if r.state == "open"        else
            "[yellow]open|filtered[/]" if "filtered" in r.state else
            "[dim]closed[/]"
        )
        table.add_row(
            str(r.port),
            r.proto,
            state_style,
            r.service,
            f"{r.latency:.1f} ms" if r.latency else "",
            r.banner,
        )
    _console.print(table)


def _display_ping(r: PingResult) -> None:
    loss = 100 * (r.packets_sent - r.packets_recv) / max(r.packets_sent, 1)
    alive_str = "[green]ALIVE[/]" if r.alive else "[red]UNREACHABLE[/]"

    if not _RICH:
        print(f"\nPing {r.host} ({r.ip})  {r.packets_recv}/{r.packets_sent} recv"
              f"  rtt min/avg/max = {r.rtt_min}/{r.rtt_avg}/{r.rtt_max} ms")
        return

    table = Table(title=f"Ping — {r.host}", border_style="cyan", show_header=False)
    table.add_column("K", style="bold cyan", width=18)
    table.add_column("V", style="white")
    table.add_row("Status",   alive_str)
    table.add_row("IP",       r.ip)
    table.add_row("Sent / Recv", f"{r.packets_sent} / {r.packets_recv}")
    table.add_row("Packet loss", f"{loss:.1f}%")
    table.add_row("RTT min",  f"{r.rtt_min:.3f} ms")
    table.add_row("RTT avg",  f"{r.rtt_avg:.3f} ms")
    table.add_row("RTT max",  f"{r.rtt_max:.3f} ms")
    table.add_row("Jitter",   f"{r.rtt_jitter:.3f} ms")
    _console.print(table)


def _display_dns(records_by_type: dict[str, list[DnsRecord]], host: str) -> None:
    if not _RICH:
        for rtype, recs in records_by_type.items():
            for r in recs:
                print(f"{r.name:<40} {r.ttl:<8} IN  {r.rtype:<8} {r.data}")
        return
    table = Table(title=f"DNS Records — {host}", border_style="cyan")
    table.add_column("Type",   style="bold cyan",  width=8)
    table.add_column("TTL",    style="dim",         width=8, justify="right")
    table.add_column("Data",   style="white")
    for rtype, recs in records_by_type.items():
        for r in recs:
            table.add_row(r.rtype, str(r.ttl), r.data)
    _console.print(table)


def _display_traceroute(hops: list[TraceHop], host: str) -> None:
    if not hops:
        _print("[yellow]Traceroute returned no hops.[/yellow]")
        return
    if not _RICH:
        for h in hops:
            rtts = "  ".join(f"{r:.1f}ms" if r >= 0 else "*" for r in h.rtts)
            print(f"{h.ttl:>3}  {h.ip:<18}  {rtts}")
        return
    table = Table(title=f"Traceroute — {host}", border_style="cyan")
    table.add_column("Hop",  style="bold yellow", justify="right", width=5)
    table.add_column("IP",   style="cyan",         width=18)
    table.add_column("Host", style="dim",          width=36)
    table.add_column("RTTs (ms)", style="white")
    for h in hops:
        rtts_str = "  ".join(
            f"[green]{r:.1f}[/]" if r >= 0 else "[red]*[/]"
            for r in h.rtts
        )
        table.add_row(str(h.ttl), h.ip, h.hostname, rtts_str)
    _console.print(table)


def _display_http(info: HttpInfo) -> None:
    if not _RICH:
        print(f"\n{info.status_code} {info.reason}  {info.url}")
        for k, v in info.headers.items():
            print(f"  {k}: {v}")
        return

    status_color = (
        "green" if 200 <= info.status_code < 300 else
        "yellow" if 300 <= info.status_code < 400 else
        "red"
    )

    _console.print(Panel(
        f"[bold {status_color}]{info.status_code} {info.reason}[/]  "
        f"[dim]{info.url}[/]  [dim]{info.elapsed_ms:.0f}ms[/]",
        title="HTTP Response",
        border_style="cyan",
    ))

    if info.redirect_chain:
        _console.print("[dim]Redirect chain:[/]")
        for code, url in info.redirect_chain:
            _console.print(f"  [yellow]{code}[/] → {url}")

    table = Table(title="Response Headers", border_style="dim", show_header=False)
    table.add_column("Header", style="cyan",  width=32)
    table.add_column("Value",  style="white")
    for k, v in sorted(info.headers.items()):
        table.add_row(k, v)
    _console.print(table)

    if info.tls:
        cert = info.tls
        days_color = "green" if cert.days_left > 30 else "yellow" if cert.days_left > 7 else "red"
        cert_table = Table(title="TLS Certificate", border_style="dim", show_header=False)
        cert_table.add_column("K", style="bold cyan", width=20)
        cert_table.add_column("V", style="white")
        cert_table.add_row("Subject CN", cert.subject.get("commonName", ""))
        cert_table.add_row("Issuer",     cert.issuer.get("organizationName", ""))
        cert_table.add_row("Valid from", str(cert.not_before.date()))
        cert_table.add_row("Valid until", str(cert.not_after.date()))
        cert_table.add_row("Days left",  f"[{days_color}]{cert.days_left}[/]")
        cert_table.add_row("Serial",     cert.serial[:24] + "…" if len(cert.serial) > 24 else cert.serial)
        cert_table.add_row("SAN",        "\n".join(cert.san[:8]) + ("…" if len(cert.san) > 8 else ""))
        _console.print(cert_table)


def _display_subnet(info: SubnetInfo) -> None:
    if not _RICH:
        print(f"\nNetwork:   {info.network}/{info.prefix_len}")
        print(f"Netmask:   {info.netmask}")
        print(f"Hosts:     {info.usable_hosts:,}")
        return
    table = Table(title="Subnet Calculator", border_style="cyan", show_header=False)
    table.add_column("K", style="bold cyan",  width=22)
    table.add_column("V", style="white")
    rows = [
        ("Network address",   f"{info.network}/{info.prefix_len}"),
        ("Broadcast",         info.broadcast or "N/A (IPv6)"),
        ("Netmask",           info.netmask),
        ("Wildcard mask",     info.wildcard or "N/A (IPv6)"),
        ("First usable host", info.first_host),
        ("Last usable host",  info.last_host),
        ("Total addresses",   f"{info.total_hosts:,}"),
        ("Usable hosts",      f"{info.usable_hosts:,}"),
        ("IP class",          info.ip_class),
        ("IP type",           info.ip_type),
        ("Private",           "Yes" if info.is_private else "No"),
    ]
    for k, v in rows:
        table.add_row(k, v)
    _console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
#  11. Interactive Terminal Menu
# ─────────────────────────────────────────────────────────────────────────────

class NetworkModule:
    """
    Terminal-facing wrapper integrated with core.terminal routing.
    All public menu_* methods are callable by the router.
    """

    NAME = "🌐 Network Tools"
    DESCRIPTION = "Port scan · Ping · DNS · Traceroute · Whois · HTTP · Subnet"

    # ── menu handlers ─────────────────────────────────────────────────────────

    def menu_port_scan(self) -> None:
        """Interactive port scanner."""
        host  = _prompt("Target host / IP")
        ports_spec = _prompt(
            "Ports [e.g. 1-1024 / top-20 / web / 22,80,443]",
            default="top-20",
        )
        proto       = _prompt("Protocol [tcp/udp]", default="tcp").lower()
        grab        = _confirm("Grab banners?", default=True)
        threads     = _int_prompt("Thread count", default=DEFAULT_THREADS)
        timeout     = float(_prompt("Timeout (s)", default=str(DEFAULT_TIMEOUT)))

        try:
            ports = expand_port_range(ports_spec)
        except Exception:
            _print("[red]Invalid port specification.[/red]")
            return

        _print(f"\n[cyan]Scanning {len(ports)} port(s) on [bold]{host}[/] …[/cyan]")

        try:
            ip = _resolve(host)
        except ValueError as e:
            _print(f"[red]✗ {e}[/red]")
            return

        open_count = 0

        if _RICH:
            with _progress(f"Scanning {host}") as prog:
                task = prog.add_task("", total=len(ports))
                results: list[PortResult] = []
                lock = threading.Lock()

                def _cb(r: PortResult) -> None:
                    nonlocal open_count
                    with lock:
                        if r.state in ("open", "open|filtered"):
                            open_count += 1
                        results.append(r)
                    prog.update(task, advance=1)

                results = scan_ports(
                    ip, ports, proto=proto, timeout=timeout,
                    max_threads=threads, grab_banners=grab,
                    open_only=False, on_result=_cb,
                )
        else:
            results = scan_ports(
                ip, ports, proto=proto, timeout=timeout,
                max_threads=threads, grab_banners=grab,
            )

        open_ports = [r for r in results if r.state in ("open", "open|filtered")]
        _display_port_results(open_ports, host)
        _print(f"\n[dim]Found [bold]{len(open_ports)}[/] open port(s) "
               f"out of {len(ports)} scanned.[/dim]")

    def menu_ping(self) -> None:
        """ICMP ping with statistics."""
        host    = _prompt("Target host / IP")
        count   = _int_prompt("Ping count", default=DEFAULT_PING_COUNT)
        timeout = float(_prompt("Timeout (s)", default=str(DEFAULT_PING_TIMEOUT)))
        _print(f"\n[cyan]Pinging [bold]{host}[/] × {count} …[/cyan]")
        try:
            result = ping(host, count=count, timeout=timeout)
            _display_ping(result)
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_dns_lookup(self) -> None:
        """DNS record lookup."""
        name   = _prompt("Domain name")
        mode   = _prompt("Mode [single/all]", default="all").lower()
        ns     = _prompt("Custom nameserver (blank = system default)", default="")
        ns = ns.strip() or None

        try:
            if "all" in mode:
                records = dns_lookup_all(name, ns)
                _display_dns(records, name)
            else:
                rtype = _prompt(
                    f"Record type [{'/'.join(DNS_RECORD_TYPES)}]",
                    default="A",
                ).upper()
                records_list = dns_lookup(name, rtype, ns)
                _display_dns({rtype: records_list}, name)
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_reverse_dns(self) -> None:
        """Reverse DNS / PTR lookup."""
        raw  = _prompt("IP address(es) — comma-separated")
        ips  = [ip.strip() for ip in raw.split(",") if ip.strip()]
        if len(ips) == 1:
            hostname = reverse_dns(ips[0])
            _print(f"[green]{ips[0]} → {hostname or '(no PTR)'}[/green]")
        else:
            _print(f"[cyan]Batch PTR lookup for {len(ips)} IPs …[/cyan]")
            results = batch_ptr(ips)
            if _RICH:
                table = Table(title="Reverse DNS", border_style="cyan")
                table.add_column("IP",       style="yellow")
                table.add_column("Hostname", style="green")
                for ip, host in results.items():
                    table.add_row(ip, host or "[dim](no PTR)[/dim]")
                _console.print(table)
            else:
                for ip, h in results.items():
                    print(f"{ip:<18} → {h or '(no PTR)'}")

    def menu_traceroute(self) -> None:
        """Traceroute to a host."""
        host     = _prompt("Target host / IP")
        max_hops = _int_prompt("Max hops", default=TRACEROUTE_MAX_HOPS)
        probes   = _int_prompt("Probes per hop", default=TRACEROUTE_PROBES)
        _print(f"\n[cyan]Tracing route to [bold]{host}[/] (max {max_hops} hops) …[/cyan]")
        try:
            hops = traceroute(host, max_hops=max_hops, probes=probes)
            # Batch PTR on hop IPs
            if _confirm("Resolve hostnames?", default=True):
                ips = [h.ip for h in hops if h.ip != "*"]
                ptrs = batch_ptr(ips)
                for h in hops:
                    h.hostname = ptrs.get(h.ip, "")
            _display_traceroute(hops, host)
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_whois(self) -> None:
        """Whois query."""
        target = _prompt("Domain or IP")
        server = _prompt("Whois server (blank = auto)", default="")
        _print(f"[cyan]Querying whois for [bold]{target}[/] …[/cyan]")
        try:
            result = whois_query(target, server.strip() or None)
            if _RICH:
                _console.print(Panel(
                    result[:4000] + ("…" if len(result) > 4000 else ""),
                    title=f"Whois — {target}",
                    border_style="cyan",
                ))
            else:
                print(result[:4000])
        except ConnectionError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_http_inspect(self) -> None:
        """HTTP/HTTPS header inspector."""
        url        = _prompt("URL or host", default="https://example.com")
        follow     = _confirm("Follow redirects?", default=True)
        verify_ssl = _confirm("Verify SSL certificate?", default=True)

        # Strip non-ASCII prefix from keyboard layout mistakes
        # (e.g. Cyrillic r typed before "https://" on Russian layout).
        url_clean = url.encode("ascii", errors="ignore").decode("ascii").strip()
        if not url_clean:
            _print("[red]✗ URL has no valid ASCII characters — check keyboard layout.[/red]")
            return
        if url_clean != url:
            _print(f"[yellow]Non-ASCII prefix stripped. Using: {url_clean}[/yellow]")

        _print(f"[cyan]Inspecting [bold]{url_clean}[/] …[/cyan]")
        try:
            info = inspect_http(url_clean, follow_redirects=follow, verify_ssl=verify_ssl)
            _display_http(info)
        except UnicodeEncodeError:
            _print("[red]✗ URL contains non-Latin characters that cannot be sent over HTTP.[/red]")
            _print("[dim]  Tip: check for Cyrillic letters (Russian keyboard layout).[/dim]")
        except ConnectionError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_subnet_calc(self) -> None:
        """CIDR subnet calculator."""
        cidr = _prompt("CIDR notation", default="192.168.1.0/24")
        try:
            info = subnet_calc(cidr)
            _display_subnet(info)
        except ValueError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_interfaces(self) -> None:
        """Show local network interfaces."""
        ifaces = get_interfaces()
        if not _RICH:
            for iface in ifaces:
                print(f"\n{iface.name}  MAC={iface.mac}")
                for a in iface.addresses:
                    print(f"  {a['family']}: {a['address']}")
            return

        for iface in ifaces:
            table = Table(
                title       = f"Interface: {iface.name}",
                border_style = "cyan",
                show_header  = False,
            )
            table.add_column("K", style="bold cyan", width=14)
            table.add_column("V", style="white")

            if iface.mac:
                table.add_row("MAC", iface.mac)

            for a in iface.addresses:
                if a["family"] == "MAC":
                    continue
                label = a["family"]
                val   = a["address"]
                if a.get("netmask"):
                    val += f"  /  {a['netmask']}"
                table.add_row(label, val)

            st = iface.stats
            if st:
                table.add_row("Status", "[green]UP[/]" if st.get("isup") else "[red]DOWN[/]")
                if st.get("speed"):
                    table.add_row("Speed",  f"{st['speed']} Mbps")
                if st.get("mtu"):
                    table.add_row("MTU",    str(st["mtu"]))

            _console.print(table)

    def menu_connections(self) -> None:
        """Show active network connections."""
        if not _PSUTIL:
            _print("[red]psutil not installed. Run: pip install psutil[/red]")
            return
        kind   = _prompt("Kind [inet/tcp/udp/all]", default="inet")
        status = _prompt("Filter status [ESTABLISHED/LISTEN/blank=all]", default="")
        status_filter = [status.strip()] if status.strip() else None

        try:
            conns = get_connections(kind, status_filter)
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")
            return

        if not _RICH:
            for c in conns:
                print(f"{c['proto']:<5} {c['laddr']:<26} {c['raddr']:<26} {c['status']:<14} {c['process']}")
            return

        table = Table(title="Active Connections", border_style="cyan")
        table.add_column("Proto",   style="yellow", width=6)
        table.add_column("Local",   style="white",  width=26)
        table.add_column("Remote",  style="cyan",   width=26)
        table.add_column("Status",  width=14)
        table.add_column("PID",     justify="right", width=7)
        table.add_column("Process", style="dim")

        STATUS_COLORS = {
            "ESTABLISHED": "green",
            "LISTEN"     : "cyan",
            "TIME_WAIT"  : "yellow",
            "CLOSE_WAIT" : "yellow",
            "SYN_SENT"   : "magenta",
        }

        for c in conns:
            sc = STATUS_COLORS.get(c["status"], "white")
            table.add_row(
                c["proto"],
                c["laddr"],
                c["raddr"] or "",
                f"[{sc}]{c['status']}[/]",
                str(c["pid"]) if c["pid"] else "",
                c["process"],
            )
        _console.print(table)
        _print(f"\n[dim]{len(conns)} connection(s) displayed.[/dim]")

    def menu_arp(self) -> None:
        """Display ARP table."""
        entries = get_arp_table()
        if not entries:
            _print("[yellow]ARP table empty or could not be read.[/yellow]")
            return
        if not _RICH:
            for e in entries:
                print(f"{e['ip']:<18} {e['mac']}")
            return
        table = Table(title="ARP Table", border_style="cyan")
        table.add_column("IP Address", style="yellow")
        table.add_column("MAC Address", style="cyan")
        for e in entries:
            table.add_row(e["ip"], e["mac"])
        _console.print(table)

    # ── main entry point ──────────────────────────────────────────────────────

    def run(self) -> None:
        MENU: list[tuple[str, str, Callable]] = [
            ("1",  "Port scanner  (TCP / UDP)",          self.menu_port_scan),
            ("2",  "Ping  (ICMP + statistics)",           self.menu_ping),
            ("3",  "DNS lookup  (A/MX/NS/TXT/…)",        self.menu_dns_lookup),
            ("4",  "Reverse DNS / PTR",                  self.menu_reverse_dns),
            ("5",  "Traceroute",                         self.menu_traceroute),
            ("6",  "Whois query",                        self.menu_whois),
            ("7",  "HTTP / HTTPS inspector  + TLS cert", self.menu_http_inspect),
            ("8",  "Subnet calculator  (CIDR)",          self.menu_subnet_calc),
            ("9",  "Network interfaces",                 self.menu_interfaces),
            ("10", "Active connections",                 self.menu_connections),
            ("11", "ARP table",                          self.menu_arp),
            ("0",  "← Back to main menu",                None),
        ]

        while True:
            if _RICH:
                table = Table(
                    title        = "🌐 Network Tools",
                    border_style = "cyan",
                    show_header  = True,
                    header_style = "bold cyan",
                )
                table.add_column("No.",     style="bold yellow", width=4)
                table.add_column("Feature", style="white")
                for key, label, _ in MENU:
                    table.add_row(key, label, style="dim" if key == "0" else "")
                _console.print(table)
            else:
                print("\n=== Network Tools ===")
                for key, label, _ in MENU:
                    print(f"  {key}. {label}")

            choice = _prompt("Select").strip()

            if choice == "0":
                break

            handler = next((fn for k, _, fn in MENU if k == choice and fn), None)
            if handler:
                try:
                    handler()
                except KeyboardInterrupt:
                    _print("\n[yellow]Cancelled.[/yellow]")
                except Exception as e:
                    _print(f"[red]✗ Unhandled error: {e}[/red]")
            else:
                _print("[red]Invalid option.[/red]")


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level entry point
# ─────────────────────────────────────────────────────────────────────────────

def run() -> None:
    """Called by core.terminal as: modules.network.run()"""
    NetworkModule().run()


if __name__ == "__main__":
    run()