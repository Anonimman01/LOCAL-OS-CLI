"""
log_analyzer.py — System Log Analysis Module
══════════════════════════════════════════════
Part of local_os toolkit.  Reads, filters, searches, and exports system
logs from /var/log/*, journald, and arbitrary user-supplied log files.

Architecture:
  LogSource        — dataclass describing a readable log file / journal unit
  LogEntry         — parsed, structured log line (timestamp, level, host, msg)
  LogReader        — low-level I/O: mmap for large files, gzip/bz2, journalctl
  LogFilter        — composable predicate pipeline (level, regex, time-range)
  LogAnalyzer      — business logic: search, stats, tail, export CSV/JSON
  LogUI            — terminal rendering (uses core.ui primitives)
  register()       — module entry point called by ModuleRegistry

Supports:
  • /var/log/syslog, auth.log, kern.log, dpkg.log, apt/history.log
  • /var/log/nginx/*, /var/log/apache2/*, /var/log/postgresql/*
  • journalctl (systemd) — per-unit, per-boot, priority filter
  • Any arbitrary .log / .log.gz / .log.bz2 file
  • Real-time tail (follow mode)
  • grep / regex search with context lines
  • Level-based filtering: ERROR, WARN, INFO, DEBUG, CRIT
  • Time-range filtering (--since / --until)
  • Top-N most frequent lines / IPs / errors
  • CSV and JSON export

Author  : local_os project
License : MIT
"""

from __future__ import annotations

# ── stdlib ─────────────────────────────────────────────────────────────────
import bz2
import collections
import contextlib
import csv
import gzip
import io
import json
import logging
import mmap
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
    Union,
)

# ── project imports (graceful standalone fallback) ─────────────────────────
try:
    from core.ui import Ansi, UI  # type: ignore
    from core.config import Config  # type: ignore
except ImportError:
    class Ansi:  # type: ignore  # noqa: E302
        RESET = RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = BOLD = DIM = ""
        WHITE = BRIGHT_WHITE = BRIGHT_GREEN = BRIGHT_RED = BRIGHT_CYAN = ""
        BRIGHT_YELLOW = BG_RED = BG_GREEN = BG_BLUE = ""

        @staticmethod
        def color(text: str, *_: str) -> str:
            return text

    class UI:  # type: ignore  # noqa: E302
        @staticmethod
        def header(title: str) -> None:
            print(f"\n{'═' * 60}\n  {title}\n{'═' * 60}")

        @staticmethod
        def success(msg: str) -> None:
            print(f"  ✓  {msg}")

        @staticmethod
        def error(msg: str) -> None:
            print(f"  ✗  {msg}", file=sys.stderr)

        @staticmethod
        def warning(msg: str) -> None:
            print(f"  ⚠  {msg}")

        @staticmethod
        def info(msg: str) -> None:
            print(f"  ·  {msg}")

        @staticmethod
        def prompt(msg: str) -> str:
            return input(f"  ▶  {msg} ")

        @staticmethod
        def confirm(msg: str) -> bool:
            return input(f"  ?  {msg} [y/N] ").strip().lower() == "y"

        @staticmethod
        def pause() -> None:
            input("  ⏎  Press Enter to continue… ")

    class Config:  # type: ignore  # noqa: E302
        LOG_TAIL_LINES: int = 200
        LOG_MAX_EXPORT_ROWS: int = 50_000
        LOG_CONTEXT_LINES: int = 2
        LOG_TOP_N: int = 20

# ── module logger ───────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════
# Constants & look-up tables
# ══════════════════════════════════════════════════════════════════════════

# Well-known log directories (tried in order; readable ones kept)
_LOG_DIRS: Tuple[str, ...] = (
    "/var/log",
    "/var/log/nginx",
    "/var/log/apache2",
    "/var/log/httpd",
    "/var/log/postgresql",
    "/var/log/mysql",
    "/var/log/redis",
    "/var/log/mongodb",
    "/var/log/docker",
    "/var/log/audit",
    "/var/log/apt",
    "/var/log/unattended-upgrades",
    "/var/log/cups",
    "/var/log/samba",
    "/var/log/sssd",
    "/var/log/openvpn",
)

# Canonical log files with friendly labels
_KNOWN_LOGS: Tuple[Tuple[str, str], ...] = (
    ("/var/log/syslog", "Syslog"),
    ("/var/log/messages", "Messages"),
    ("/var/log/auth.log", "Auth"),
    ("/var/log/kern.log", "Kernel"),
    ("/var/log/dmesg", "dmesg"),
    ("/var/log/dpkg.log", "dpkg"),
    ("/var/log/apt/history.log", "APT History"),
    ("/var/log/apt/term.log", "APT Terminal"),
    ("/var/log/nginx/access.log", "Nginx Access"),
    ("/var/log/nginx/error.log", "Nginx Error"),
    ("/var/log/apache2/access.log", "Apache Access"),
    ("/var/log/apache2/error.log", "Apache Error"),
    ("/var/log/postgresql/postgresql.log", "PostgreSQL"),
    ("/var/log/mysql/error.log", "MySQL Error"),
    ("/var/log/redis/redis-server.log", "Redis"),
    ("/var/log/mongodb/mongod.log", "MongoDB"),
    ("/var/log/audit/audit.log", "Audit"),
    ("/var/log/fail2ban.log", "fail2ban"),
    ("/var/log/ufw.log", "UFW Firewall"),
    ("/var/log/cloud-init.log", "cloud-init"),
    ("/var/log/cloud-init-output.log", "cloud-init output"),
)

# Syslog priority names → numeric (RFC-5424)
_SYSLOG_LEVELS: Dict[str, int] = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
    "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7,
}

# Severity colour map
_LEVEL_COLOUR: Dict[str, str] = {
    "EMERG":   Ansi.BG_RED + Ansi.WHITE,
    "ALERT":   Ansi.BG_RED + Ansi.WHITE,
    "CRIT":    Ansi.BRIGHT_RED,
    "ERR":     Ansi.RED,
    "ERROR":   Ansi.RED,
    "WARN":    Ansi.YELLOW,
    "WARNING": Ansi.YELLOW,
    "NOTICE":  Ansi.CYAN,
    "INFO":    Ansi.GREEN,
    "DEBUG":   Ansi.DIM,
    "UNKNOWN": Ansi.RESET,
}

# ── timestamp patterns (most-specific first) ───────────────────────────────
# Each entry: (compiled_re, strptime_format_or_None, handler_tag)
_TS_PATTERNS: List[Tuple[Pattern[str], Optional[str], str]] = [
    # ISO-8601 with tz:  2024-03-15T14:22:01+03:00
    (re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2})"),
     None, "iso_tz"),
    # ISO-8601 no tz:    2024-03-15T14:22:01
    (re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"),
     "%Y-%m-%dT%H:%M:%S", "iso"),
    # ISO date-space:    2024-03-15 14:22:01
    (re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
     "%Y-%m-%d %H:%M:%S", "iso_sp"),
    # syslog:            Mar 15 14:22:01
    (re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
     "%b %d %H:%M:%S", "syslog"),
    # nginx/apache:      15/Mar/2024:14:22:01 +0300
    (re.compile(r"^\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4})\]"),
     "%d/%b/%Y:%H:%M:%S %z", "clf"),
    # epoch seconds:     1710505321
    (re.compile(r"^(\d{10}(?:\.\d+)?)"),
     None, "epoch"),
]

# ── level detection regex ───────────────────────────────────────────────────
_LEVEL_RE = re.compile(
    r"\b(EMERG|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG)\b",
    re.IGNORECASE,
)

# ── IPv4 pattern ────────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ── journalctl availability ─────────────────────────────────────────────────
_JOURNALCTL_BIN: Optional[str] = shutil.which("journalctl")
_HAS_JOURNAL: bool = _JOURNALCTL_BIN is not None

_EXPORT_DIR = Path.home() / ".localos" / "exports"


# ══════════════════════════════════════════════════════════════════════════
# Exceptions
# ══════════════════════════════════════════════════════════════════════════

class LogAnalyzerError(RuntimeError):
    """Base exception."""


class LogAccessError(LogAnalyzerError):
    """File unreadable (permissions, missing)."""


class LogParseError(LogAnalyzerError):
    """Cannot parse log format."""


class LogExportError(LogAnalyzerError):
    """Export I/O failure."""


# ══════════════════════════════════════════════════════════════════════════
# Data-transfer objects
# ══════════════════════════════════════════════════════════════════════════

class LogLevel(str, Enum):
    EMERG   = "EMERG"
    ALERT   = "ALERT"
    CRIT    = "CRIT"
    ERROR   = "ERROR"
    WARN    = "WARN"
    NOTICE  = "NOTICE"
    INFO    = "INFO"
    DEBUG   = "DEBUG"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, s: str) -> "LogLevel":
        s = s.upper().rstrip("ING")  # WARNING→WARN, CRITICAL→CRITIC stripped
        mapping = {
            "EMERG": cls.EMERG, "ALERT": cls.ALERT,
            "CRIT": cls.CRIT, "CRITIC": cls.CRIT,
            "ERR": cls.ERROR, "ERROR": cls.ERROR,
            "WARN": cls.WARN,
            "NOTICE": cls.NOTICE,
            "INFO": cls.INFO,
            "DEBUG": cls.DEBUG,
        }
        return mapping.get(s, cls.UNKNOWN)

    def numeric(self) -> int:
        return _SYSLOG_LEVELS.get(self.value.lower(), 99)


@dataclass(slots=True)
class LogSource:
    path: str                    # absolute path or "journal:<unit>"
    label: str                   # friendly display name
    size_bytes: int = 0
    is_compressed: bool = False
    is_journal: bool = False
    readable: bool = True
    last_modified: str = ""

    @property
    def short_size(self) -> str:
        b = self.size_bytes
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"


@dataclass(slots=True)
class LogEntry:
    line_no: int
    raw: str
    timestamp: Optional[datetime]
    ts_str: str
    level: LogLevel
    host: str
    process: str
    message: str
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_no": self.line_no,
            "timestamp": self.ts_str,
            "level": self.level.value,
            "host": self.host,
            "process": self.process,
            "message": self.message,
            "source": self.source_path,
        }


@dataclass
class LogStats:
    source: str
    total_lines: int = 0
    parsed_lines: int = 0
    level_counts: Dict[str, int] = field(default_factory=dict)
    top_processes: List[Tuple[str, int]] = field(default_factory=list)
    top_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_errors: List[Tuple[str, int]] = field(default_factory=list)
    first_ts: str = ""
    last_ts: str = ""
    size_bytes: int = 0


@dataclass
class SearchResult:
    entries: List[LogEntry]
    total_scanned: int
    elapsed_ms: float
    pattern: str


# ══════════════════════════════════════════════════════════════════════════
# Parser helpers
# ══════════════════════════════════════════════════════════════════════════

def _parse_timestamp(line: str) -> Tuple[Optional[datetime], str]:
    """
    Try all known timestamp patterns against line.
    Returns (datetime_or_None, matched_string_or_empty).
    """
    for rx, fmt, tag in _TS_PATTERNS:
        m = rx.match(line.lstrip())
        if not m:
            continue
        ts_str = m.group(1)
        try:
            if tag == "iso_tz":
                dt = datetime.fromisoformat(ts_str)
                return dt, ts_str
            if tag == "epoch":
                dt = datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
                return dt, ts_str
            if fmt:
                dt = datetime.strptime(ts_str, fmt)
                # syslog has no year — assume current year
                if tag == "syslog":
                    dt = dt.replace(year=datetime.now().year)
                return dt, ts_str
        except (ValueError, OSError):
            continue
    return None, ""


def _parse_level(line: str) -> LogLevel:
    m = _LEVEL_RE.search(line)
    if not m:
        # heuristic: uppercase words like ERROR, FATAL
        upper = line.upper()
        for kw in ("FATAL", "CRITICAL", "CRIT"):
            if kw in upper:
                return LogLevel.CRIT
        return LogLevel.UNKNOWN
    return LogLevel.from_str(m.group(1))


# syslog: "Mar 15 14:22:01 hostname process[pid]: message"
_SYSLOG_HDR = re.compile(
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[^\[:]+)(?:\[\d+\])?\s*:\s*"
    r"(?P<msg>.*)",
    re.DOTALL,
)

# kernel / dmesg: "[123456.789] message"
_DMESG_HDR = re.compile(r"^\[\s*(?P<ts>\d+\.\d+)\]\s*(?P<msg>.*)")

# nginx combined: ip - user [ts] "request" status bytes "referer" "ua"
_NGINX_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]+)"\s+(?P<status>\d+)\s+(?P<bytes>\d+)'
)


def parse_line(raw: str, line_no: int, source_path: str = "") -> LogEntry:
    """
    Parse a single log line into a LogEntry.
    Never raises — always returns a valid object.
    """
    stripped = raw.strip()
    ts, ts_str = _parse_timestamp(stripped)
    level = _parse_level(stripped)
    host = ""
    process = ""
    message = stripped

    # syslog format
    m = _SYSLOG_HDR.match(stripped)
    if m:
        host = m.group("host")
        process = m.group("proc").strip()
        message = m.group("msg").strip()
    else:
        # dmesg
        m2 = _DMESG_HDR.match(stripped)
        if m2:
            process = "kernel"
            message = m2.group("msg").strip()
        else:
            # nginx access
            m3 = _NGINX_ACCESS.match(stripped)
            if m3:
                host = m3.group("ip")
                process = "nginx"
                message = stripped

    return LogEntry(
        line_no=line_no,
        raw=raw,
        timestamp=ts,
        ts_str=ts_str or (ts.isoformat() if ts else ""),
        level=level,
        host=host,
        process=process,
        message=message,
        source_path=source_path,
    )


# ══════════════════════════════════════════════════════════════════════════
# LogReader — low-level I/O layer
# ══════════════════════════════════════════════════════════════════════════

class LogReader:
    """
    Provides line-by-line iteration over:
      • plain text files (uses mmap for files > 1 MB)
      • gzip / bz2 compressed files
      • journalctl output (subprocess)
      • arbitrary file-like objects

    All methods are generators to keep memory usage O(1).
    """

    _MMAP_THRESHOLD = 1 * 1024 * 1024  # 1 MB

    @staticmethod
    def _check_readable(path: Path) -> None:
        if not path.exists():
            raise LogAccessError(f"File not found: {path}")
        if not os.access(str(path), os.R_OK):
            raise LogAccessError(
                f"Permission denied: {path}. Try running with sudo."
            )

    # ── file iterators ────────────────────────────────────────────────────

    @classmethod
    def iter_file(
        cls,
        path: Union[str, Path],
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> Generator[str, None, None]:
        """Yield lines from a plain, gz, or bz2 log file."""
        p = Path(path)
        cls._check_readable(p)

        suffix = "".join(p.suffixes).lower()

        if ".gz" in suffix:
            yield from cls._iter_gzip(p, encoding, errors)
        elif ".bz2" in suffix:
            yield from cls._iter_bz2(p, encoding, errors)
        else:
            yield from cls._iter_plain(p, encoding, errors)

    @classmethod
    def _iter_plain(
        cls, p: Path, encoding: str, errors: str
    ) -> Generator[str, None, None]:
        size = p.stat().st_size
        if size == 0:
            return
        if size >= cls._MMAP_THRESHOLD:
            yield from cls._iter_mmap(p, encoding, errors)
        else:
            with open(p, encoding=encoding, errors=errors) as fh:
                yield from fh

    @staticmethod
    def _iter_mmap(
        p: Path, encoding: str, errors: str
    ) -> Generator[str, None, None]:
        """Memory-mapped iteration for large files."""
        with open(p, "rb") as fh:
            try:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except (mmap.error, ValueError):
                # Fallback if mmap fails (e.g. empty file race)
                fh.seek(0)
                for raw_line in fh:
                    yield raw_line.decode(encoding, errors=errors)
                return
            try:
                buf = io.BytesIO(mm)
                for raw_line in buf:
                    yield raw_line.decode(encoding, errors=errors)
            finally:
                mm.close()

    @staticmethod
    def _iter_gzip(
        p: Path, encoding: str, errors: str
    ) -> Generator[str, None, None]:
        with gzip.open(str(p), "rt", encoding=encoding, errors=errors) as fh:
            yield from fh

    @staticmethod
    def _iter_bz2(
        p: Path, encoding: str, errors: str
    ) -> Generator[str, None, None]:
        with bz2.open(str(p), "rt", encoding=encoding, errors=errors) as fh:
            yield from fh

    # ── tail (last N lines) ───────────────────────────────────────────────

    @classmethod
    def tail(
        cls,
        path: Union[str, Path],
        n: int = 200,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> List[str]:
        """
        Return the last *n* lines efficiently using a circular deque.
        Works on compressed files too (no seek needed).
        """
        p = Path(path)
        cls._check_readable(p)
        buf: collections.deque[str] = collections.deque(maxlen=n)
        for line in cls.iter_file(p, encoding, errors):
            buf.append(line)
        return list(buf)

    # ── follow (live tail) ────────────────────────────────────────────────

    @classmethod
    def follow(
        cls,
        path: Union[str, Path],
        interval: float = 0.3,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> Generator[str, None, None]:
        """
        Yield new lines appended to *path* indefinitely (like `tail -f`).
        Handles log rotation: re-opens when inode changes.
        """
        p = Path(path)
        cls._check_readable(p)

        def _open() -> Tuple[Any, int]:
            fh = open(p, encoding=encoding, errors=errors)
            fh.seek(0, 2)  # seek to end
            ino = os.fstat(fh.fileno()).st_ino
            return fh, ino

        fh, ino = _open()
        try:
            while True:
                line = fh.readline()
                if line:
                    yield line
                else:
                    time.sleep(interval)
                    # detect rotation
                    with contextlib.suppress(OSError):
                        new_ino = p.stat().st_ino
                        if new_ino != ino:
                            fh.close()
                            fh, ino = _open()
        finally:
            fh.close()

    # ── journalctl ────────────────────────────────────────────────────────

    @staticmethod
    def iter_journal(
        unit: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        priority: Optional[str] = None,
        n: Optional[int] = None,
        follow: bool = False,
        boot: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """
        Yield lines from journalctl.
        Raises LogAccessError if journalctl is unavailable.
        """
        if not _HAS_JOURNAL:
            raise LogAccessError(
                "journalctl not found. System does not use systemd."
            )
        cmd = [_JOURNALCTL_BIN, "--no-pager", "--output=short-iso"]
        if unit:
            cmd += ["-u", unit]
        if since:
            cmd += ["--since", since]
        if until:
            cmd += ["--until", until]
        if priority:
            cmd += ["-p", priority]
        if n:
            cmd += ["-n", str(n)]
        if follow:
            cmd.append("-f")
        if boot:
            cmd += ["-b", boot]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise LogAccessError("journalctl not found") from exc

        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                yield line
        finally:
            proc.terminate()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)

    @staticmethod
    def list_journal_units() -> List[str]:
        """Return sorted list of systemd unit names with logs."""
        if not _HAS_JOURNAL:
            return []
        try:
            r = subprocess.run(
                [_JOURNALCTL_BIN, "--field=_SYSTEMD_UNIT", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            units = sorted(set(r.stdout.strip().splitlines()))
            return [u for u in units if u and u != ""]
        except Exception:
            return []


# ══════════════════════════════════════════════════════════════════════════
# LogFilter — composable predicate pipeline
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class LogFilter:
    """
    Immutable filter specification. All fields are optional (None = no filter).
    """
    pattern: Optional[str] = None           # regex or plain string
    level_min: Optional[LogLevel] = None    # minimum severity
    since: Optional[datetime] = None        # start of time window
    until: Optional[datetime] = None        # end of time window
    invert: bool = False                    # negate pattern match
    case_sensitive: bool = False            # regex case sensitivity
    host_filter: Optional[str] = None       # hostname substring
    process_filter: Optional[str] = None    # process name substring

    # compiled regex cache — set after first use
    _rx: Optional[Pattern[str]] = field(default=None, repr=False, compare=False)

    def _get_rx(self) -> Optional[Pattern[str]]:
        if self.pattern is None:
            return None
        if self._rx is None:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            object.__setattr__(self, "_rx", re.compile(self.pattern, flags))
        return self._rx

    def matches(self, entry: LogEntry) -> bool:
        # level
        if self.level_min is not None:
            if entry.level.numeric() > self.level_min.numeric():
                return False

        # time range
        if entry.timestamp:
            if self.since and entry.timestamp < self.since:
                return False
            if self.until and entry.timestamp > self.until:
                return False

        # host
        if self.host_filter and self.host_filter.lower() not in entry.host.lower():
            return False

        # process
        if self.process_filter and self.process_filter.lower() not in entry.process.lower():
            return False

        # regex / pattern
        rx = self._get_rx()
        if rx is not None:
            hit = bool(rx.search(entry.raw))
            return (not hit) if self.invert else hit

        return True

    def is_empty(self) -> bool:
        return (
            self.pattern is None
            and self.level_min is None
            and self.since is None
            and self.until is None
            and not self.host_filter
            and not self.process_filter
        )


# ══════════════════════════════════════════════════════════════════════════
# LogAnalyzer — business logic layer
# ══════════════════════════════════════════════════════════════════════════

class LogAnalyzer:
    """
    Core analysis engine.  Stateless — each method receives all context.
    Thread-safe (no shared mutable state).
    """

    # ── source discovery ──────────────────────────────────────────────────

    @staticmethod
    def discover_sources() -> List[LogSource]:
        """
        Return readable log sources: known files + all *.log* in /var/log.
        """
        sources: List[LogSource] = []
        seen: Set[str] = set()

        def _add(path_str: str, label: str) -> None:
            p = Path(path_str)
            if path_str in seen or not p.exists():
                return
            readable = os.access(str(p), os.R_OK)
            try:
                st = p.stat()
                size = st.st_size
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            except OSError:
                size = 0
                mtime = "—"
            suffix = "".join(p.suffixes).lower()
            sources.append(
                LogSource(
                    path=path_str,
                    label=label,
                    size_bytes=size,
                    is_compressed=".gz" in suffix or ".bz2" in suffix,
                    is_journal=False,
                    readable=readable,
                    last_modified=mtime,
                )
            )
            seen.add(path_str)

        # known logs first
        for path_str, label in _KNOWN_LOGS:
            _add(path_str, label)

        # scan /var/log for anything missed
        for log_dir in _LOG_DIRS:
            d = Path(log_dir)
            if not d.is_dir() or not os.access(str(d), os.R_OK):
                continue
            for p in sorted(d.iterdir()):
                if p.is_file() and any(
                    p.name.endswith(ext)
                    for ext in (".log", ".log.gz", ".log.bz2", ".log.1", ".txt")
                ):
                    _add(str(p), p.name)

        # journald virtual sources
        if _HAS_JOURNAL:
            sources.append(
                LogSource(
                    path="journal:_system_",
                    label="journald (system)",
                    is_journal=True,
                    readable=True,
                )
            )

        return sources

    # ── search ────────────────────────────────────────────────────────────

    @staticmethod
    def search(
        source: LogSource,
        flt: LogFilter,
        max_results: int = 1000,
        context_lines: int = 0,
    ) -> SearchResult:
        """
        Scan *source* and return all entries matching *flt*.
        context_lines: include N lines before/after each hit.
        """
        t0 = time.monotonic()
        entries: List[LogEntry] = []
        total = 0

        # raw line generator
        if source.is_journal:
            unit = source.path.replace("journal:", "").replace("_system_", "")
            raw_lines: Iterable[str] = LogReader.iter_journal(
                unit=unit or None,
                since=flt.since.strftime("%Y-%m-%d %H:%M:%S") if flt.since else None,
                until=flt.until.strftime("%Y-%m-%d %H:%M:%S") if flt.until else None,
            )
        else:
            try:
                raw_lines = LogReader.iter_file(source.path)
            except LogAccessError:
                raise

        # sliding window for context
        window: collections.deque[str] = collections.deque(maxlen=context_lines + 1)
        pending_context: List[Tuple[int, str]] = []   # lines after a hit
        post_ctx_remaining = 0
        hit_line_nos: Set[int] = set()

        for line_no, raw in enumerate(raw_lines, 1):
            total += 1
            entry = parse_line(raw, line_no, source.path)

            if context_lines > 0:
                window.append((line_no, raw))

            if flt.matches(entry):
                if len(entries) >= max_results:
                    break

                # pre-context: emit buffered lines (not already emitted)
                if context_lines > 0:
                    for prev_no, prev_raw in list(window)[:-1]:
                        if prev_no not in hit_line_nos:
                            pre_entry = parse_line(prev_raw, prev_no, source.path)
                            entries.append(pre_entry)
                            hit_line_nos.add(prev_no)

                entries.append(entry)
                hit_line_nos.add(line_no)
                post_ctx_remaining = context_lines
            elif post_ctx_remaining > 0 and line_no not in hit_line_nos:
                entries.append(entry)
                hit_line_nos.add(line_no)
                post_ctx_remaining -= 1

        elapsed = (time.monotonic() - t0) * 1000
        return SearchResult(
            entries=entries,
            total_scanned=total,
            elapsed_ms=round(elapsed, 1),
            pattern=flt.pattern or "",
        )

    # ── statistics ────────────────────────────────────────────────────────

    @staticmethod
    def compute_stats(
        source: LogSource,
        max_lines: int = 100_000,
    ) -> LogStats:
        """
        Compute level distribution, top processes, top IPs, top error messages.
        Capped at max_lines to stay interactive.
        """
        stats = LogStats(source=source.label or source.path)
        stats.size_bytes = source.size_bytes

        level_cnt: Dict[str, int] = collections.defaultdict(int)
        proc_cnt: Dict[str, int] = collections.defaultdict(int)
        ip_cnt: Dict[str, int] = collections.defaultdict(int)
        err_cnt: Dict[str, int] = collections.defaultdict(int)

        first_ts: Optional[datetime] = None
        last_ts: Optional[datetime] = None

        if source.is_journal:
            unit = source.path.replace("journal:", "").replace("_system_", "")
            raw_iter: Iterable[str] = LogReader.iter_journal(
                unit=unit or None, n=max_lines
            )
        else:
            try:
                raw_iter = LogReader.iter_file(source.path)
            except LogAccessError:
                raise

        for line_no, raw in enumerate(raw_iter, 1):
            stats.total_lines += 1
            if line_no > max_lines:
                break

            entry = parse_line(raw, line_no, source.path)
            stats.parsed_lines += 1

            level_cnt[entry.level.value] += 1

            if entry.process:
                proc_cnt[entry.process] += 1

            for ip in _IPV4_RE.findall(raw):
                ip_cnt[ip] += 1

            if entry.level in (LogLevel.ERROR, LogLevel.CRIT):
                # normalize: strip timestamps/numbers for grouping
                normalized = re.sub(r"\d+", "N", entry.message)[:120]
                err_cnt[normalized] += 1

            if entry.timestamp:
                if first_ts is None or entry.timestamp < first_ts:
                    first_ts = entry.timestamp
                if last_ts is None or entry.timestamp > last_ts:
                    last_ts = entry.timestamp

        n = getattr(Config, "LOG_TOP_N", 20)
        stats.level_counts = dict(level_cnt)
        stats.top_processes = collections.Counter(proc_cnt).most_common(n)
        stats.top_ips = collections.Counter(ip_cnt).most_common(n)
        stats.top_errors = collections.Counter(err_cnt).most_common(n)
        stats.first_ts = first_ts.isoformat() if first_ts else "—"
        stats.last_ts = last_ts.isoformat() if last_ts else "—"
        return stats

    # ── tail ──────────────────────────────────────────────────────────────

    @staticmethod
    def tail(source: LogSource, n: int = 200) -> List[LogEntry]:
        if source.is_journal:
            unit = source.path.replace("journal:", "").replace("_system_", "")
            lines = list(LogReader.iter_journal(unit=unit or None, n=n))
        else:
            lines = LogReader.tail(source.path, n=n)
        return [parse_line(raw, i + 1, source.path) for i, raw in enumerate(lines)]

    # ── export ────────────────────────────────────────────────────────────

    @staticmethod
    def export_csv(
        entries: List[LogEntry],
        dest: Path,
    ) -> int:
        """Write entries to CSV. Returns rows written."""
        _EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(dest, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=["line_no", "timestamp", "level",
                                 "host", "process", "message", "source"],
                )
                w.writeheader()
                for e in entries:
                    w.writerow(e.to_dict())
            return len(entries)
        except OSError as exc:
            raise LogExportError(f"CSV export failed: {exc}") from exc

    @staticmethod
    def export_json(
        entries: List[LogEntry],
        dest: Path,
    ) -> int:
        """Write entries to JSON (array). Returns rows written."""
        _EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(dest, "w", encoding="utf-8") as fh:
                json.dump([e.to_dict() for e in entries], fh, indent=2, ensure_ascii=False)
            return len(entries)
        except OSError as exc:
            raise LogExportError(f"JSON export failed: {exc}") from exc

    # ── follow ────────────────────────────────────────────────────────────

    @staticmethod
    def follow(
        source: LogSource,
        flt: Optional[LogFilter] = None,
    ) -> Generator[LogEntry, None, None]:
        """Yield new entries appended to source in real time."""
        if source.is_journal:
            unit = source.path.replace("journal:", "").replace("_system_", "")
            raw_iter = LogReader.iter_journal(unit=unit or None, follow=True, n=20)
        else:
            raw_iter = LogReader.follow(source.path)

        line_no = 0
        for raw in raw_iter:
            line_no += 1
            entry = parse_line(raw, line_no, source.path)
            if flt is None or flt.matches(entry):
                yield entry


# ══════════════════════════════════════════════════════════════════════════
# LogUI — terminal rendering
# ══════════════════════════════════════════════════════════════════════════

class LogUI:
    """All terminal I/O for the log analyzer module."""

    _analyzer = LogAnalyzer()

    # ── utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def _term_width() -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 100

    @classmethod
    def _divider(cls, char: str = "─") -> None:
        print(f"{Ansi.DIM}{char * cls._term_width()}{Ansi.RESET}")

    @staticmethod
    def _level_col(level: LogLevel) -> str:
        return _LEVEL_COLOUR.get(level.value, Ansi.RESET)

    @staticmethod
    def _highlight(text: str, pattern: Optional[str]) -> str:
        """Wrap regex matches in BOLD+YELLOW."""
        if not pattern:
            return text
        try:
            rx = re.compile(f"({re.escape(pattern)})", re.IGNORECASE)
            return rx.sub(
                lambda m: f"{Ansi.BOLD}{Ansi.BRIGHT_YELLOW}{m.group(0)}{Ansi.RESET}",
                text,
            )
        except re.error:
            return text

    @staticmethod
    def _format_entry(e: LogEntry, pattern: Optional[str] = None) -> str:
        col = _LEVEL_COLOUR.get(e.level.value, Ansi.RESET)
        lvl = f"{col}{e.level.value:<7}{Ansi.RESET}"
        ts = f"{Ansi.DIM}{e.ts_str[:19]:<19}{Ansi.RESET}" if e.ts_str else " " * 19
        proc = f"{Ansi.CYAN}{e.process[:18]:<18}{Ansi.RESET}" if e.process else " " * 18
        msg = LogUI._highlight(e.message or e.raw.strip(), pattern)
        return f"  {ts} {lvl} {proc} {msg}"

    @staticmethod
    def _parse_since_until(raw: str) -> Optional[datetime]:
        """Parse human time: 'now', '1h', '2d', 'YYYY-MM-DD HH:MM', etc."""
        raw = raw.strip()
        if not raw:
            return None
        if raw.lower() == "now":
            return datetime.now(timezone.utc)
        # relative: 1h, 30m, 2d, 7d
        m = re.fullmatch(r"(\d+)([mhdw])", raw.lower())
        if m:
            val, unit = int(m.group(1)), m.group(2)
            delta = {
                "m": timedelta(minutes=val),
                "h": timedelta(hours=val),
                "d": timedelta(days=val),
                "w": timedelta(weeks=val),
            }[unit]
            return datetime.now(timezone.utc) - delta
        # absolute
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            with contextlib.suppress(ValueError):
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        return None

    def _build_filter(self) -> LogFilter:
        """Interactive prompt to build a LogFilter."""
        print(f"\n  {Ansi.BOLD}Filter options{Ansi.RESET} (blank = skip)")

        pattern = UI.prompt("Regex/text pattern  :").strip() or None

        level_raw = UI.prompt("Min level (ERR/WARN/INFO/DEBUG …) :").strip()
        level_min: Optional[LogLevel] = None
        if level_raw:
            with contextlib.suppress(Exception):
                level_min = LogLevel.from_str(level_raw)

        since_raw = UI.prompt("Since (e.g. 1h, 2d, 2024-01-15 or blank) :").strip()
        since = self._parse_since_until(since_raw)

        until_raw = UI.prompt("Until (e.g. 30m, or blank=now)           :").strip()
        until = self._parse_since_until(until_raw)

        process_raw = UI.prompt("Process name filter  :").strip() or None
        invert = UI.confirm("Invert match (show NON-matching)?") if pattern else False

        return LogFilter(
            pattern=pattern,
            level_min=level_min,
            since=since,
            until=until,
            invert=invert,
            process_filter=process_raw,
        )

    # ── source picker ─────────────────────────────────────────────────────

    def _pick_source(self, sources: List[LogSource]) -> Optional[LogSource]:
        readable = [s for s in sources if s.readable]
        if not readable:
            UI.warning("No readable log sources found.")
            return None

        for i, s in enumerate(readable, 1):
            icon = "📓" if s.is_journal else ("🗜 " if s.is_compressed else "📄")
            locked = f"{Ansi.RED}[no read]{Ansi.RESET}" if not s.readable else ""
            size_str = s.short_size if not s.is_journal else ""
            print(
                f"  {Ansi.DIM}{i:>3}.{Ansi.RESET} {icon} "
                f"{Ansi.BOLD}{s.label:<30}{Ansi.RESET} "
                f"{Ansi.DIM}{size_str:<10}{Ansi.RESET} "
                f"{Ansi.DIM}{s.last_modified:<17}{Ansi.RESET} "
                f"{locked}"
            )
        self._divider()
        raw = UI.prompt("Choose source # (or path, blank=cancel):").strip()
        if not raw:
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(readable):
                return readable[idx]
            UI.error("Index out of range")
            return None
        # typed a path
        p = Path(raw)
        if p.exists() and os.access(str(p), os.R_OK):
            suffix = "".join(p.suffixes).lower()
            return LogSource(
                path=str(p),
                label=p.name,
                size_bytes=p.stat().st_size,
                is_compressed=".gz" in suffix or ".bz2" in suffix,
                readable=True,
                last_modified=datetime.fromtimestamp(
                    p.stat().st_mtime
                ).strftime("%Y-%m-%d %H:%M"),
            )
        UI.error(f"Cannot read: {raw}")
        return None

    # ══════════════════════════════════════════════════════════════════════
    # MAIN MENU
    # ══════════════════════════════════════════════════════════════════════

    def run(self) -> None:
        sources: Optional[List[LogSource]] = None

        while True:
            UI.header("📋  Log Analyzer")
            menu_items = [
                ("1", "Browse Sources"),
                ("2", "Tail  (last N lines)"),
                ("3", "Search / Filter"),
                ("4", "Statistics & Top-N"),
                ("5", "Live Follow  (tail -f)"),
                ("6", "Export  CSV / JSON"),
                ("7", "Journal Units  (systemd)"),
                ("0", "Back"),
            ]
            for key, label in menu_items:
                print(f"  {Ansi.CYAN}{key}{Ansi.RESET}  {label}")
            self._divider()
            choice = UI.prompt("Choose:").strip()

            dispatch = {
                "1": self._menu_browse,
                "2": self._menu_tail,
                "3": self._menu_search,
                "4": self._menu_stats,
                "5": self._menu_follow,
                "6": self._menu_export,
                "7": self._menu_journal_units,
                "0": None,
            }
            if choice == "0":
                break
            handler = dispatch.get(choice)
            if handler:
                # lazy source discovery
                if sources is None:
                    UI.info("Scanning log sources…")
                    sources = LogAnalyzer.discover_sources()
                try:
                    handler(sources)
                except LogAccessError as exc:
                    UI.error(str(exc))
                    UI.pause()
                except LogAnalyzerError as exc:
                    UI.error(str(exc))
                    UI.pause()
                except KeyboardInterrupt:
                    print()
                    UI.info("Interrupted.")
            else:
                if choice != "0":
                    UI.warning("Unknown option")

    # ══════════════════════════════════════════════════════════════════════
    # BROWSE
    # ══════════════════════════════════════════════════════════════════════

    def _menu_browse(self, sources: List[LogSource]) -> None:
        UI.header(f"Log Sources  ({len(sources)} found)")
        all_size = sum(s.size_bytes for s in sources if not s.is_journal)
        readable_n = sum(1 for s in sources if s.readable)

        header = (
            f"  {'#':>3}  {'LABEL':<30} {'SIZE':<10} {'MODIFIED':<17} {'PATH'}"
        )
        print(f"{Ansi.BOLD}{header}{Ansi.RESET}")
        self._divider()
        for i, s in enumerate(sources, 1):
            ok = Ansi.RESET if s.readable else Ansi.DIM
            lock = "🔒" if not s.readable else ""
            print(
                f"  {Ansi.DIM}{i:>3}.{Ansi.RESET}  "
                f"{ok}{s.label:<30}{Ansi.RESET} "
                f"{Ansi.DIM}{s.short_size:<10}{Ansi.RESET} "
                f"{Ansi.DIM}{s.last_modified:<17}{Ansi.RESET} "
                f"{Ansi.DIM}{s.path}{Ansi.RESET} {lock}"
            )
        self._divider()
        total_mb = all_size / (1024 ** 2)
        print(
            f"  Total: {len(sources)} sources  "
            f"({readable_n} readable)  "
            f"Disk: {total_mb:.1f} MB"
        )
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # TAIL
    # ══════════════════════════════════════════════════════════════════════

    def _menu_tail(self, sources: List[LogSource]) -> None:
        UI.header("Tail — Last N Lines")
        src = self._pick_source(sources)
        if src is None:
            return

        raw = UI.prompt(f"Lines to show [{getattr(Config, 'LOG_TAIL_LINES', 200)}]:").strip()
        n = int(raw) if raw.isdigit() else getattr(Config, "LOG_TAIL_LINES", 200)

        filter_yn = UI.confirm("Apply level/pattern filter?")
        flt = self._build_filter() if filter_yn else LogFilter()

        UI.header(f"Tail: {src.label}  (last {n})")
        self._divider()
        try:
            entries = LogAnalyzer.tail(src, n=n)
        except LogAccessError as exc:
            UI.error(str(exc))
            UI.pause()
            return

        shown = 0
        for e in entries:
            if flt.is_empty() or flt.matches(e):
                print(self._format_entry(e, flt.pattern))
                shown += 1

        self._divider()
        UI.info(f"Showed {shown} / {len(entries)} lines")
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # SEARCH
    # ══════════════════════════════════════════════════════════════════════

    def _menu_search(self, sources: List[LogSource]) -> None:
        UI.header("Search / Filter Logs")
        src = self._pick_source(sources)
        if src is None:
            return

        flt = self._build_filter()
        ctx_raw = UI.prompt(f"Context lines [{getattr(Config, 'LOG_CONTEXT_LINES', 2)}]:").strip()
        ctx = int(ctx_raw) if ctx_raw.isdigit() else getattr(Config, "LOG_CONTEXT_LINES", 2)
        max_raw = UI.prompt("Max results [1000]:").strip()
        max_results = int(max_raw) if max_raw.isdigit() else 1000

        UI.info("Scanning…")
        try:
            result = LogAnalyzer.search(src, flt, max_results=max_results, context_lines=ctx)
        except LogAccessError as exc:
            UI.error(str(exc))
            UI.pause()
            return

        UI.header(
            f"Results: {len(result.entries)}  "
            f"(scanned {result.total_scanned:,} lines in {result.elapsed_ms:.0f} ms)"
        )
        self._divider()

        if not result.entries:
            UI.info("No matches found.")
        else:
            for e in result.entries:
                print(self._format_entry(e, result.pattern))

        self._divider()
        UI.info(
            f"Pattern: {result.pattern!r}   "
            f"Matches: {len(result.entries)}   "
            f"Scanned: {result.total_scanned:,}"
        )

        if result.entries and UI.confirm("Export results?"):
            self._do_export(result.entries)
        else:
            UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # STATISTICS
    # ══════════════════════════════════════════════════════════════════════

    def _menu_stats(self, sources: List[LogSource]) -> None:
        UI.header("Log Statistics")
        src = self._pick_source(sources)
        if src is None:
            return

        max_raw = UI.prompt("Max lines to analyse [100000]:").strip()
        max_lines = int(max_raw) if max_raw.isdigit() else 100_000

        UI.info("Computing statistics… (this may take a moment for large files)")
        try:
            stats = LogAnalyzer.compute_stats(src, max_lines=max_lines)
        except LogAccessError as exc:
            UI.error(str(exc))
            UI.pause()
            return

        self._render_stats(stats)
        UI.pause()

    def _render_stats(self, s: LogStats) -> None:
        UI.header(f"Statistics: {s.source}")

        # overview
        fields = [
            ("Total lines",   f"{s.total_lines:,}"),
            ("Parsed lines",  f"{s.parsed_lines:,}"),
            ("File size",     _bytes_to_human(s.size_bytes) if s.size_bytes else "—"),
            ("First entry",   s.first_ts[:19]),
            ("Last entry",    s.last_ts[:19]),
        ]
        for label, val in fields:
            print(f"  {Ansi.CYAN}{label:<20}{Ansi.RESET} {val}")

        # level distribution with bar
        if s.level_counts:
            print(f"\n  {Ansi.BOLD}Level Distribution{Ansi.RESET}")
            self._divider("·")
            total = max(sum(s.level_counts.values()), 1)
            order = ["CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "UNKNOWN"]
            for lvl in order:
                cnt = s.level_counts.get(lvl, 0)
                if cnt == 0:
                    continue
                col = _LEVEL_COLOUR.get(lvl, Ansi.RESET)
                bar_w = int(30 * cnt / total)
                bar = "█" * bar_w + "░" * (30 - bar_w)
                pct = cnt / total * 100
                print(
                    f"  {col}{lvl:<9}{Ansi.RESET} "
                    f"{Ansi.DIM}{bar}{Ansi.RESET} "
                    f"{cnt:>8,} ({pct:5.1f}%)"
                )

        # top processes
        if s.top_processes:
            print(f"\n  {Ansi.BOLD}Top Processes{Ansi.RESET}")
            self._divider("·")
            for proc, cnt in s.top_processes[:10]:
                print(f"  {Ansi.CYAN}{proc:<30}{Ansi.RESET} {cnt:>8,}")

        # top IPs
        if s.top_ips:
            print(f"\n  {Ansi.BOLD}Top IP Addresses{Ansi.RESET}")
            self._divider("·")
            for ip, cnt in s.top_ips[:10]:
                print(f"  {Ansi.YELLOW}{ip:<20}{Ansi.RESET} {cnt:>8,}")

        # top errors
        if s.top_errors:
            print(f"\n  {Ansi.BOLD}Top Error Patterns{Ansi.RESET}")
            self._divider("·")
            for msg, cnt in s.top_errors[:10]:
                short = msg[:70] + "…" if len(msg) > 70 else msg
                print(f"  {Ansi.RED}{cnt:>6,}{Ansi.RESET}  {Ansi.DIM}{short}{Ansi.RESET}")

    # ══════════════════════════════════════════════════════════════════════
    # LIVE FOLLOW
    # ══════════════════════════════════════════════════════════════════════

    def _menu_follow(self, sources: List[LogSource]) -> None:
        UI.header("Live Follow  (Ctrl-C to stop)")
        src = self._pick_source(sources)
        if src is None:
            return

        filter_yn = UI.confirm("Apply level/pattern filter?")
        flt = self._build_filter() if filter_yn else None

        UI.info(f"Following {src.label}  — Ctrl-C to stop")
        self._divider()
        try:
            for entry in LogAnalyzer.follow(src, flt=flt):
                print(self._format_entry(entry, flt.pattern if flt else None))
        except KeyboardInterrupt:
            print()
            UI.info("Follow stopped.")
        except LogAccessError as exc:
            UI.error(str(exc))
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════════════════════════════════════

    def _menu_export(self, sources: List[LogSource]) -> None:
        UI.header("Export Logs")
        src = self._pick_source(sources)
        if src is None:
            return

        flt = self._build_filter()
        max_rows = getattr(Config, "LOG_MAX_EXPORT_ROWS", 50_000)

        UI.info("Collecting entries…")
        try:
            result = LogAnalyzer.search(src, flt, max_results=max_rows)
        except LogAccessError as exc:
            UI.error(str(exc))
            UI.pause()
            return

        UI.info(f"Found {len(result.entries):,} entries")
        self._do_export(result.entries)

    def _do_export(self, entries: List[LogEntry]) -> None:
        fmt = UI.prompt("Format  [1] CSV   [2] JSON :").strip()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        _EXPORT_DIR.mkdir(parents=True, exist_ok=True)

        try:
            if fmt == "2":
                dest = _EXPORT_DIR / f"log_export_{ts}.json"
                n = LogAnalyzer.export_json(entries, dest)
                UI.success(f"Exported {n:,} rows → {dest}")
            else:
                dest = _EXPORT_DIR / f"log_export_{ts}.csv"
                n = LogAnalyzer.export_csv(entries, dest)
                UI.success(f"Exported {n:,} rows → {dest}")
        except LogExportError as exc:
            UI.error(str(exc))
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # JOURNAL UNITS
    # ══════════════════════════════════════════════════════════════════════

    def _menu_journal_units(self, sources: List[LogSource]) -> None:
        if not _HAS_JOURNAL:
            UI.warning("journalctl not found — systemd not available on this system.")
            UI.pause()
            return

        UI.info("Loading systemd units…")
        units = LogReader.list_journal_units()
        UI.header(f"Systemd Units  ({len(units)} with logs)")

        if not units:
            UI.info("No units found.")
            UI.pause()
            return

        for i, u in enumerate(units[:60], 1):
            print(f"  {Ansi.DIM}{i:>3}.{Ansi.RESET}  {Ansi.CYAN}{u}{Ansi.RESET}")
        if len(units) > 60:
            UI.info(f"… {len(units) - 60} more. Type unit name directly.")
        self._divider()

        raw = UI.prompt("Unit # or name (blank=system):").strip()
        unit: Optional[str] = None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(units):
                unit = units[idx]
        elif raw:
            unit = raw

        virtual = LogSource(
            path=f"journal:{unit or '_system_'}",
            label=f"journal:{unit or 'system'}",
            is_journal=True,
            readable=True,
        )
        # inject into sources for sub-menus
        augmented = [virtual] + sources
        self._menu_tail(augmented)


# ══════════════════════════════════════════════════════════════════════════
# Utility reused internally
# ══════════════════════════════════════════════════════════════════════════

def _bytes_to_human(b: int) -> str:
    val = float(b)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(val) < 1024.0:
            return f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} PB"


# ══════════════════════════════════════════════════════════════════════════
# Module registry entry point
# ══════════════════════════════════════════════════════════════════════════

def register(registry: Any) -> None:
    """Called by modules/__init__.py ModuleRegistry."""
    registry.register(
        key="log_analyzer",
        label="Log Analyzer",
        description=(
            "Browse, search, filter and export system logs. "
            "/var/log/*, journald, gzip/bz2, live tail, CSV/JSON export."
        ),
        entry=run,
        health=health_check,
        tags=["logs", "syslog", "journald", "analysis"],
    )


def run() -> None:
    """Module entry point called by terminal router."""
    try:
        LogUI().run()
    except KeyboardInterrupt:
        print()
        UI.info("Log Analyzer closed.")


def health_check() -> Dict[str, Any]:
    """Called by ModuleRegistry. Quick sanity check."""
    result: Dict[str, Any] = {
        "status": "ok",
        "sources": 0,
        "journal": _HAS_JOURNAL,
        "error": None,
    }
    try:
        sources = LogAnalyzer.discover_sources()
        result["sources"] = len([s for s in sources if s.readable])
    except Exception as exc:
        result["status"] = "degraded"
        result["error"] = str(exc)
    return result


# ══════════════════════════════════════════════════════════════════════════
# Standalone execution
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    print("Log Analyzer — standalone mode")
    hc = health_check()
    print(f"Health: {hc}")
    if hc["status"] in ("ok", "degraded"):
        run()

# ══════════════════════════════════════════════════════════════════════════
# Plugin registry metadata (required by plugins/__init__.py PluginRegistry)
# ══════════════════════════════════════════════════════════════════════════

PLUGIN_NAME        = "Log Analyzer"
PLUGIN_VERSION     = "1.0.0"
PLUGIN_DESCRIPTION = "System log analysis: tail, filter, search, journald, error reports"
PLUGIN_AUTHOR      = "local_os project"
PLUGIN_TAGS: list  = ["logs", "monitoring", "sysadmin"]


def main() -> None:
    """Entry-point called by PluginRegistry.invoke()."""
    run()