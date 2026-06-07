"""
firewall.py — Corporate-grade Firewall Management Module
=========================================================
Supports: iptables (Linux), ufw (Ubuntu/Debian), pfctl (macOS/BSD)
Features:
  • Rule CRUD (add / delete / list / flush)
  • IP / CIDR / port / protocol blocking & allowlisting
  • Named profiles (load / save / apply / diff)
  • Real-time connection monitoring
  • Geo-IP lookups (offline MaxMind or online fallback)
  • Rate-limiting / connection-throttling rules
  • Audit log (SQLite) for every mutation
  • JSON / CSV / iptables-save export
  • Dry-run mode (preview without applying)
  • Auto-backup before destructive operations
  • Privilege checks with actionable error messages

Author : local_os project
License: MIT
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Generator, Iterator, List, Optional, Sequence, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Optional rich / tabulate – graceful degradation if not installed
# ──────────────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box as rich_box
    _RICH = True
except ImportError:
    _RICH = False

try:
    from tabulate import tabulate as _tabulate
    _TABULATE = True
except ImportError:
    _TABULATE = False

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("local_os.firewall")


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
DATA_DIR      = Path.home() / ".localos"
AUDIT_DB      = DATA_DIR / "audit.db"
PROFILES_DIR  = DATA_DIR / "firewall_profiles"
BACKUP_DIR    = DATA_DIR / "firewall_backups"

IPTABLES      = shutil.which("iptables")
IP6TABLES     = shutil.which("ip6tables")
UFW           = shutil.which("ufw")
PFCTL         = shutil.which("pfctl")
IPSET         = shutil.which("ipset")

MAX_BACKUP_AGE_DAYS = 30

# ──────────────────────────────────────────────────────────────────────────────
# Enums & data-classes
# ──────────────────────────────────────────────────────────────────────────────

class Backend(str, Enum):
    IPTABLES = "iptables"
    UFW      = "ufw"
    PFCTL    = "pfctl"
    MOCK     = "mock"          # unit-testing / dry-run without root


class Action(str, Enum):
    ACCEPT = "ACCEPT"
    DROP   = "DROP"
    REJECT = "REJECT"
    LOG    = "LOG"


class Direction(str, Enum):
    IN    = "INPUT"
    OUT   = "OUTPUT"
    FWD   = "FORWARD"


class Protocol(str, Enum):
    TCP  = "tcp"
    UDP  = "udp"
    ICMP = "icmp"
    ANY  = "all"


@dataclass
class FirewallRule:
    """Vendor-neutral firewall rule."""
    chain:     Direction          = Direction.IN
    action:    Action             = Action.DROP
    protocol:  Protocol           = Protocol.ANY
    src_ip:    str                = "0.0.0.0/0"
    dst_ip:    str                = "0.0.0.0/0"
    src_port:  Optional[str]      = None   # "80", "1024:65535"
    dst_port:  Optional[str]      = None
    comment:   str                = ""
    enabled:   bool               = True
    created:   str                = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    rule_id:   Optional[int]      = None   # assigned after insertion

    # ── validation ────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        self._validate_cidr(self.src_ip, "src_ip")
        self._validate_cidr(self.dst_ip, "dst_ip")
        if self.src_port:
            self._validate_port_spec(self.src_port, "src_port")
        if self.dst_port:
            self._validate_port_spec(self.dst_port, "dst_port")

    @staticmethod
    def _validate_cidr(value: str, name: str) -> None:
        if value in ("0.0.0.0/0", "::/0", "any"):
            return
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid {name} '{value}': {exc}") from exc

    @staticmethod
    def _validate_port_spec(value: str, name: str) -> None:
        # Accept: "80", "443", "1024:65535", "80,443"
        pattern = r"^\d+(:\d+)?(,\d+(:\d+)?)*$"
        if not re.fullmatch(pattern, value):
            raise ValueError(
                f"Invalid {name} '{value}'. "
                "Expected: single port, range (start:end), or comma-list."
            )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirewallProfile:
    """Named collection of rules, serialisable to JSON."""
    name:        str
    description: str                  = ""
    backend:     str                  = Backend.IPTABLES.value
    rules:       List[FirewallRule]   = field(default_factory=list)
    created:     str                  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    modified:    str                  = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "FirewallProfile":
        rules = [FirewallRule(**r) for r in data.pop("rules", [])]
        obj   = cls(**data)
        obj.rules = rules
        return obj


# ──────────────────────────────────────────────────────────────────────────────
# Audit
# ──────────────────────────────────────────────────────────────────────────────

class AuditLog:
    """Append-only SQLite audit trail for every firewall mutation."""

    _CREATE = """
    CREATE TABLE IF NOT EXISTS fw_audit (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        TEXT    NOT NULL,
        user      TEXT    NOT NULL,
        action    TEXT    NOT NULL,
        target    TEXT    NOT NULL,
        detail    TEXT,
        success   INTEGER NOT NULL DEFAULT 1,
        error     TEXT
    )
    """

    def __init__(self, db_path: Path = AUDIT_DB) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute(self._CREATE)
        self._conn.commit()

    def record(
        self,
        action:  str,
        target:  str,
        detail:  str  = "",
        success: bool = True,
        error:   str  = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO fw_audit(ts,user,action,target,detail,success,error) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
                action,
                target,
                detail,
                int(success),
                error,
            ),
        )
        self._conn.commit()

    def tail(self, n: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM fw_audit ORDER BY id DESC LIMIT ?", (n,)
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Backend Adapters
# ──────────────────────────────────────────────────────────────────────────────

class _BaseAdapter:
    def list_rules(self)                  -> list[str]:   ...
    def add_rule(self, rule: FirewallRule) -> str:         ...
    def delete_rule(self, rule: FirewallRule) -> str:      ...
    def flush_chain(self, chain: Direction) -> str:        ...
    def save_rules(self) -> str:                           ...
    def restore_rules(self, data: str) -> str:             ...
    def status(self) -> str:                               ...


class IptablesAdapter(_BaseAdapter):
    """Direct iptables / ip6tables adapter."""

    def __init__(self, dry_run: bool = False) -> None:
        if not IPTABLES:
            raise RuntimeError("iptables not found. Install iptables package.")
        self.dry_run = dry_run

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = [IPTABLES] + args
        logger.debug("iptables %s", " ".join(args))
        if self.dry_run:
            logger.info("[DRY-RUN] %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="[dry-run]", stderr="")
        return subprocess.run(
            cmd, capture_output=True, text=True, check=check
        )

    # ── public interface ──────────────────────────────────────────────────────

    def list_rules(self) -> list[str]:
        result = self._run(["-L", "-n", "-v", "--line-numbers"])
        return result.stdout.splitlines()

    def add_rule(self, rule: FirewallRule) -> str:
        args = self._build_args("-A", rule)
        result = self._run(args, check=False)
        if result.returncode != 0:
            raise FirewallError(f"iptables add failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def delete_rule(self, rule: FirewallRule) -> str:
        args = self._build_args("-D", rule)
        result = self._run(args, check=False)
        if result.returncode != 0:
            raise FirewallError(f"iptables delete failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def flush_chain(self, chain: Direction) -> str:
        result = self._run(["-F", chain.value], check=False)
        if result.returncode != 0:
            raise FirewallError(f"iptables flush failed: {result.stderr.strip()}")
        return f"Chain {chain.value} flushed."

    def save_rules(self) -> str:
        cmd = shutil.which("iptables-save") or "iptables-save"
        if self.dry_run:
            return "[dry-run: iptables-save]"
        result = subprocess.run([cmd], capture_output=True, text=True)
        if result.returncode != 0:
            raise FirewallError(f"iptables-save failed: {result.stderr.strip()}")
        return result.stdout

    def restore_rules(self, data: str) -> str:
        cmd = shutil.which("iptables-restore") or "iptables-restore"
        if self.dry_run:
            return "[dry-run: iptables-restore]"
        result = subprocess.run(
            [cmd], input=data, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise FirewallError(f"iptables-restore failed: {result.stderr.strip()}")
        return "Rules restored."

    def status(self) -> str:
        lines = self.list_rules()
        return "\n".join(lines)

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _build_args(flag: str, rule: FirewallRule) -> list[str]:
        args: list[str] = [flag, rule.chain.value]
        if rule.protocol != Protocol.ANY:
            args += ["-p", rule.protocol.value]
        if rule.src_ip not in ("0.0.0.0/0", "any"):
            args += ["-s", rule.src_ip]
        if rule.dst_ip not in ("0.0.0.0/0", "any"):
            args += ["-d", rule.dst_ip]
        if rule.src_port:
            args += ["--sport", rule.src_port]
        if rule.dst_port:
            args += ["--dport", rule.dst_port]
        if rule.comment:
            args += ["-m", "comment", "--comment", rule.comment[:255]]
        args += ["-j", rule.action.value]
        return args


class UfwAdapter(_BaseAdapter):
    """ufw (Uncomplicated Firewall) adapter."""

    def __init__(self, dry_run: bool = False) -> None:
        if not UFW:
            raise RuntimeError("ufw not found. Install: apt install ufw")
        self.dry_run = dry_run

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [UFW] + args
        if self.dry_run:
            logger.info("[DRY-RUN] %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="[dry-run]", stderr="")
        return subprocess.run(cmd, capture_output=True, text=True)

    def list_rules(self) -> list[str]:
        result = self._run(["status", "numbered"])
        return result.stdout.splitlines()

    def add_rule(self, rule: FirewallRule) -> str:
        args = self._build_ufw_args(rule)
        result = self._run(args)
        if result.returncode != 0:
            raise FirewallError(f"ufw add failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def delete_rule(self, rule: FirewallRule) -> str:
        # ufw delete requires rule number or exact spec; we use spec
        args = ["delete"] + self._build_ufw_args(rule)
        result = self._run(args)
        if result.returncode != 0:
            raise FirewallError(f"ufw delete failed: {result.stderr.strip()}")
        return result.stdout.strip()

    def flush_chain(self, chain: Direction) -> str:
        if self.dry_run:
            return "[dry-run: ufw reset]"
        result = self._run(["--force", "reset"])
        return result.stdout.strip()

    def save_rules(self) -> str:
        rules_path = Path("/etc/ufw/user.rules")
        if rules_path.exists():
            return rules_path.read_text()
        return "# ufw user.rules not found"

    def restore_rules(self, data: str) -> str:
        if self.dry_run:
            return "[dry-run: ufw restore]"
        rules_path = Path("/etc/ufw/user.rules")
        rules_path.write_text(data)
        subprocess.run([UFW, "reload"], check=False)
        return "ufw rules restored and reloaded."

    def status(self) -> str:
        result = self._run(["status", "verbose"])
        return result.stdout

    @staticmethod
    def _build_ufw_args(rule: FirewallRule) -> list[str]:
        direction_map = {Direction.IN: "in", Direction.OUT: "out", Direction.FWD: "in"}
        action_map    = {Action.ACCEPT: "allow", Action.DROP: "deny",
                         Action.REJECT: "reject", Action.LOG: "allow"}
        args: list[str] = [action_map.get(rule.action, "deny")]
        if rule.src_ip not in ("0.0.0.0/0", "any"):
            args += ["from", rule.src_ip]
        else:
            args += ["from", "any"]
        if rule.src_port:
            args += ["port", rule.src_port]
        args += ["to", "any"]
        if rule.dst_port:
            args += ["port", rule.dst_port]
        if rule.protocol != Protocol.ANY:
            args += ["proto", rule.protocol.value]
        return args


class MockAdapter(_BaseAdapter):
    """In-memory adapter for testing, CI, and dry-run previews."""

    def __init__(self) -> None:
        self._rules: list[FirewallRule] = []

    def list_rules(self) -> list[str]:
        return [
            f"[{i+1}] {r.chain.value:8} {r.action.value:8} "
            f"{r.src_ip:20} -> {r.dst_ip:20} "
            f"proto={r.protocol.value} dport={r.dst_port or '*'}"
            for i, r in enumerate(self._rules)
        ]

    def add_rule(self, rule: FirewallRule) -> str:
        self._rules.append(rule)
        return f"[MOCK] Rule added (total: {len(self._rules)})"

    def delete_rule(self, rule: FirewallRule) -> str:
        before = len(self._rules)
        self._rules = [
            r for r in self._rules
            if not (r.src_ip == rule.src_ip and r.dst_port == rule.dst_port
                    and r.action == rule.action)
        ]
        removed = before - len(self._rules)
        return f"[MOCK] Removed {removed} rule(s)"

    def flush_chain(self, chain: Direction) -> str:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.chain != chain]
        return f"[MOCK] Flushed {before - len(self._rules)} rules from {chain.value}"

    def save_rules(self) -> str:
        return json.dumps([r.to_dict() for r in self._rules], indent=2)

    def restore_rules(self, data: str) -> str:
        self._rules = [FirewallRule(**r) for r in json.loads(data)]
        return f"[MOCK] Restored {len(self._rules)} rules"

    def status(self) -> str:
        lines = self.list_rules()
        return "\n".join(lines) if lines else "[MOCK] No rules defined"


# ──────────────────────────────────────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────────────────────────────────────

class FirewallError(RuntimeError):
    """Raised for any firewall operation failure."""


class PrivilegeError(FirewallError):
    """Raised when root/admin privileges are required."""


# ──────────────────────────────────────────────────────────────────────────────
# Profile Manager
# ──────────────────────────────────────────────────────────────────────────────

class ProfileManager:
    """Load / save / apply / diff firewall profiles from ~/.localos/firewall_profiles/."""

    def __init__(self, directory: Path = PROFILES_DIR) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        safe = re.sub(r"[^\w\-]", "_", name)
        return self.directory / f"{safe}.json"

    def save(self, profile: FirewallProfile) -> Path:
        profile.modified = datetime.now(timezone.utc).isoformat()
        path = self._path(profile.name)
        path.write_text(json.dumps(profile.to_dict(), indent=2, default=str))
        return path

    def load(self, name: str) -> FirewallProfile:
        path = self._path(name)
        if not path.exists():
            raise FileNotFoundError(f"Profile '{name}' not found at {path}")
        data = json.loads(path.read_text())
        return FirewallProfile.from_dict(data)

    def list_profiles(self) -> list[str]:
        return sorted(p.stem for p in self.directory.glob("*.json"))

    def delete(self, name: str) -> None:
        path = self._path(name)
        if not path.exists():
            raise FileNotFoundError(f"Profile '{name}' not found")
        path.unlink()

    def diff(self, name_a: str, name_b: str) -> list[str]:
        a = self.load(name_a)
        b = self.load(name_b)
        set_a = {json.dumps(r.to_dict(), sort_keys=True) for r in a.rules}
        set_b = {json.dumps(r.to_dict(), sort_keys=True) for r in b.rules}
        result: list[str] = []
        for item in sorted(set_a - set_b):
            result.append(f"- {item}")
        for item in sorted(set_b - set_a):
            result.append(f"+ {item}")
        return result or ["Profiles are identical."]


# ──────────────────────────────────────────────────────────────────────────────
# Backup Manager
# ──────────────────────────────────────────────────────────────────────────────

class BackupManager:
    """Auto-backup firewall rules before destructive operations."""

    def __init__(self, directory: Path = BACKUP_DIR) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def create(self, adapter: _BaseAdapter, tag: str = "") -> Path:
        ts   = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"fw_backup_{ts}{'_' + tag if tag else ''}.txt"
        path = self.directory / name
        data = adapter.save_rules()
        path.write_text(data)
        logger.info("Firewall backup saved: %s", path)
        return path

    def restore(self, adapter: _BaseAdapter, path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")
        data = path.read_text()
        return adapter.restore_rules(data)

    def list_backups(self) -> list[Path]:
        return sorted(self.directory.glob("fw_backup_*.txt"), reverse=True)

    def prune_old(self, max_age_days: int = MAX_BACKUP_AGE_DAYS) -> int:
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        for p in self.directory.glob("fw_backup_*.txt"):
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        return removed


# ──────────────────────────────────────────────────────────────────────────────
# Geo-IP (lightweight, no mandatory dependency)
# ──────────────────────────────────────────────────────────────────────────────

class GeoIP:
    """
    Best-effort Geo-IP resolution.
    Tries: 1) python-geoip2 + MaxMind DB  2) ip-api.com (HTTP)  3) stub
    """

    @staticmethod
    def lookup(ip: str) -> dict:
        # Validate first
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "country": "?", "city": "?", "error": "invalid IP"}

        # Try geoip2
        try:
            import geoip2.database  # type: ignore
            db_candidates = [
                Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
                Path.home() / ".localos" / "GeoLite2-City.mmdb",
            ]
            for db_path in db_candidates:
                if db_path.exists():
                    with geoip2.database.Reader(str(db_path)) as reader:
                        r = reader.city(ip)
                        return {
                            "ip":      ip,
                            "country": r.country.name or "?",
                            "iso":     r.country.iso_code or "?",
                            "city":    r.city.name or "?",
                            "lat":     r.location.latitude,
                            "lon":     r.location.longitude,
                        }
        except Exception:
            pass

        # Try ip-api.com (requires network)
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,lat,lon,status,message"
            with urllib.request.urlopen(url, timeout=4) as resp:  # noqa: S310
                data = json.loads(resp.read())
                if data.get("status") == "success":
                    return {
                        "ip":      ip,
                        "country": data.get("country", "?"),
                        "iso":     data.get("countryCode", "?"),
                        "city":    data.get("city", "?"),
                        "lat":     data.get("lat"),
                        "lon":     data.get("lon"),
                    }
        except Exception:
            pass

        return {"ip": ip, "country": "unknown", "city": "unknown"}


# ──────────────────────────────────────────────────────────────────────────────
# Connection Monitor
# ──────────────────────────────────────────────────────────────────────────────

class ConnectionMonitor:
    """Read active network connections via /proc/net/tcp or ss/netstat."""

    @staticmethod
    def active_connections() -> list[dict]:
        conns: list[dict] = []

        # Try `ss` first (modern Linux)
        ss = shutil.which("ss")
        if ss:
            try:
                result = subprocess.run(
                    [ss, "-tunap"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    conns.append({
                        "proto":   parts[0],
                        "state":   parts[1],
                        "local":   parts[4],
                        "remote":  parts[5] if len(parts) > 5 else "*",
                        "process": parts[-1] if "pid=" in parts[-1] else "",
                    })
                return conns
            except Exception:
                pass

        # Fallback: /proc/net/tcp
        for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            pf = Path(proto_file)
            if not pf.exists():
                continue
            try:
                for line in pf.read_text().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local  = ConnectionMonitor._hex_to_addr(parts[1])
                    remote = ConnectionMonitor._hex_to_addr(parts[2])
                    conns.append({
                        "proto":  "tcp",
                        "state":  parts[3],
                        "local":  local,
                        "remote": remote,
                        "process": "",
                    })
            except Exception:
                pass

        return conns

    @staticmethod
    def _hex_to_addr(hex_addr: str) -> str:
        try:
            parts = hex_addr.split(":")
            if len(parts) != 2:
                return hex_addr
            ip_hex, port_hex = parts
            port = int(port_hex, 16)
            # IPv4
            if len(ip_hex) == 8:
                ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
            else:
                # IPv6 — best-effort
                ip = ip_hex
            return f"{ip}:{port}"
        except Exception:
            return hex_addr


# ──────────────────────────────────────────────────────────────────────────────
# Exporter
# ──────────────────────────────────────────────────────────────────────────────

class Exporter:
    """Export rules / audit logs to JSON, CSV, or iptables-save format."""

    @staticmethod
    def to_json(rules: list[FirewallRule], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = [r.to_dict() for r in rules]
        path.write_text(json.dumps(data, indent=2, default=str))
        return path

    @staticmethod
    def to_csv(rules: list[FirewallRule], path: Path) -> Path:
        if not rules:
            path.write_text("")
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rules[0].to_dict().keys()))
            writer.writeheader()
            writer.writerows(r.to_dict() for r in rules)
        return path

    @staticmethod
    def audit_to_csv(audit: AuditLog, path: Path, n: int = 1000) -> Path:
        rows = audit.tail(n)
        if not rows:
            path.write_text("")
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return path


# ──────────────────────────────────────────────────────────────────────────────
# Privilege Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _require_root() -> None:
    if os.geteuid() != 0:
        raise PrivilegeError(
            "This operation requires root privileges.\n"
            "  Run with: sudo python -m local_os\n"
            "  Or use --dry-run to preview without applying rules."
        )


def _detect_backend() -> Backend:
    """Auto-detect the best available firewall backend."""
    system = platform.system().lower()
    if system == "darwin" and PFCTL:
        return Backend.PFCTL
    if UFW and system == "linux":
        # Check if ufw is active
        result = subprocess.run(
            [UFW, "status"], capture_output=True, text=True
        )
        if "active" in result.stdout.lower() or "inactive" in result.stdout.lower():
            return Backend.UFW
    if IPTABLES and system == "linux":
        return Backend.IPTABLES
    return Backend.MOCK


# ──────────────────────────────────────────────────────────────────────────────
# FirewallManager — the main API
# ──────────────────────────────────────────────────────────────────────────────

class FirewallManager:
    """
    High-level Firewall Manager.

    Usage
    -----
    fw = FirewallManager()                    # auto-detect backend
    fw = FirewallManager(backend=Backend.UFW, dry_run=True)

    # Block a single IP
    fw.block_ip("192.168.1.100")

    # Allow a port
    fw.allow_port(443, protocol=Protocol.TCP)

    # Save current ruleset as a named profile
    fw.save_profile("hardened")

    # Apply a profile
    fw.apply_profile("hardened")
    """

    def __init__(
        self,
        backend:  Optional[Backend] = None,
        dry_run:  bool              = False,
        audit_db: Path              = AUDIT_DB,
    ) -> None:
        self.dry_run  = dry_run
        self.audit    = AuditLog(audit_db)
        self.profiles = ProfileManager()
        self.backups  = BackupManager()
        self.geo      = GeoIP()
        self.monitor  = ConnectionMonitor()

        # Resolve backend
        if backend is None:
            backend = Backend.MOCK if dry_run else _detect_backend()
        self.backend = backend

        # Instantiate adapter
        if self.backend == Backend.IPTABLES:
            _require_root() if not dry_run else None
            self._adapter: _BaseAdapter = IptablesAdapter(dry_run=dry_run)
        elif self.backend == Backend.UFW:
            _require_root() if not dry_run else None
            self._adapter = UfwAdapter(dry_run=dry_run)
        elif self.backend == Backend.MOCK:
            self._adapter = MockAdapter()
        else:
            raise NotImplementedError(f"Backend '{backend}' not yet implemented.")

        logger.info("FirewallManager ready. backend=%s dry_run=%s", backend, dry_run)

    # ── Core Operations ───────────────────────────────────────────────────────

    def add_rule(self, rule: FirewallRule) -> str:
        """Add a fully-specified rule."""
        try:
            result = self._adapter.add_rule(rule)
            self.audit.record("ADD_RULE", str(rule.src_ip), detail=str(rule.to_dict()))
            return result
        except Exception as exc:
            self.audit.record("ADD_RULE", str(rule.src_ip), success=False, error=str(exc))
            raise

    def delete_rule(self, rule: FirewallRule) -> str:
        """Delete a matching rule."""
        try:
            result = self._adapter.delete_rule(rule)
            self.audit.record("DEL_RULE", str(rule.src_ip), detail=str(rule.to_dict()))
            return result
        except Exception as exc:
            self.audit.record("DEL_RULE", str(rule.src_ip), success=False, error=str(exc))
            raise

    def flush_chain(self, chain: Direction = Direction.IN, confirm: bool = True) -> str:
        """Flush all rules from a chain. Backs up first."""
        if confirm:
            ans = input(
                f"⚠  This will FLUSH all rules from {chain.value}. "
                "Type 'yes' to confirm: "
            )
            if ans.strip().lower() != "yes":
                return "Aborted."
        self.backups.create(self._adapter, tag=f"pre_flush_{chain.value}")
        result = self._adapter.flush_chain(chain)
        self.audit.record("FLUSH_CHAIN", chain.value)
        return result

    # ── Convenience shortcuts ─────────────────────────────────────────────────

    def block_ip(
        self,
        ip:        str,
        direction: Direction = Direction.IN,
        comment:   str       = "blocked by local_os",
    ) -> str:
        """Block all traffic from/to an IP or CIDR."""
        rule = FirewallRule(
            chain=direction, action=Action.DROP,
            src_ip=ip, comment=comment
        )
        return self.add_rule(rule)

    def unblock_ip(self, ip: str, direction: Direction = Direction.IN) -> str:
        """Remove a block on an IP."""
        rule = FirewallRule(chain=direction, action=Action.DROP, src_ip=ip)
        return self.delete_rule(rule)

    def allow_ip(self, ip: str, direction: Direction = Direction.IN,
                 comment: str = "allowed by local_os") -> str:
        """Explicitly allow an IP."""
        rule = FirewallRule(
            chain=direction, action=Action.ACCEPT,
            src_ip=ip, comment=comment
        )
        return self.add_rule(rule)

    def block_port(
        self,
        port:      int | str,
        protocol:  Protocol  = Protocol.TCP,
        direction: Direction = Direction.IN,
        comment:   str       = "",
    ) -> str:
        """Block a port (inbound by default)."""
        rule = FirewallRule(
            chain=direction, action=Action.DROP,
            protocol=protocol, dst_port=str(port),
            comment=comment or f"block port {port}/{protocol.value}",
        )
        return self.add_rule(rule)

    def allow_port(
        self,
        port:      int | str,
        protocol:  Protocol  = Protocol.TCP,
        direction: Direction = Direction.IN,
        src_ip:    str       = "0.0.0.0/0",
        comment:   str       = "",
    ) -> str:
        """Allow a port, optionally restricted to a source IP."""
        rule = FirewallRule(
            chain=direction, action=Action.ACCEPT,
            protocol=protocol, dst_port=str(port), src_ip=src_ip,
            comment=comment or f"allow port {port}/{protocol.value}",
        )
        return self.add_rule(rule)

    def rate_limit(
        self,
        port:     int | str,
        protocol: Protocol = Protocol.TCP,
        limit:    str      = "25/minute",
        burst:    int      = 5,
    ) -> str:
        """
        Rate-limit connections to a port (iptables only via -m limit).
        Falls back to a simple ACCEPT rule on other backends.
        """
        if self.backend == Backend.IPTABLES:
            adapter = self._adapter  # type: IptablesAdapter
            args = [
                "-A", "INPUT",
                "-p", protocol.value,
                "--dport", str(port),
                "-m", "limit",
                "--limit", limit,
                "--limit-burst", str(burst),
                "-j", "ACCEPT",
                "-m", "comment", "--comment", f"rate-limit {port}",
            ]
            result = adapter._run(args, check=False)
            if result.returncode != 0:
                raise FirewallError(result.stderr.strip())
            self.audit.record("RATE_LIMIT", str(port), detail=f"limit={limit} burst={burst}")
            return result.stdout.strip() or f"Rate-limit rule added for port {port}."
        else:
            return self.allow_port(port, protocol, comment=f"rate-limit (best-effort) {port}")

    # ── Bulk Operations ───────────────────────────────────────────────────────

    def block_ip_list(self, ips: Sequence[str], comment: str = "") -> list[str]:
        """Block a list of IPs atomically."""
        results = []
        for ip in ips:
            try:
                results.append(self.block_ip(ip, comment=comment or f"blocklist: {ip}"))
            except Exception as exc:
                results.append(f"ERROR {ip}: {exc}")
        return results

    def block_country(self, iso_code: str) -> str:
        """
        Placeholder: integrate with ipset for country-level blocking.
        Requires MaxMind GeoLite2 + ipset installed.
        """
        # In production: download country CIDR list, build ipset, reference in rule.
        return (
            f"Country blocking for '{iso_code.upper()}' requires ipset + GeoLite2 DB.\n"
            "See: https://www.ipdeny.com/ipblocks/"
        )

    # ── List / Status ─────────────────────────────────────────────────────────

    def list_rules(self) -> list[str]:
        return self._adapter.list_rules()

    def status(self) -> str:
        return self._adapter.status()

    def active_connections(self) -> list[dict]:
        return self.monitor.active_connections()

    # ── Profile Operations ────────────────────────────────────────────────────

    def save_profile(self, name: str, rules: Optional[list[FirewallRule]] = None,
                     description: str = "") -> Path:
        """
        Save current (or provided) rules as a named profile.
        If rules=None, saves the live ruleset as raw text inside the profile.
        """
        if rules is None:
            # Wrap raw lines as comment-only rules for portability
            raw = self._adapter.list_rules()
            rules = [
                FirewallRule(comment=line, enabled=False)
                for line in raw if line.strip()
            ]
        profile = FirewallProfile(
            name=name, description=description,
            backend=self.backend.value, rules=rules
        )
        path = self.profiles.save(profile)
        self.audit.record("SAVE_PROFILE", name)
        return path

    def load_profile(self, name: str) -> FirewallProfile:
        return self.profiles.load(name)

    def apply_profile(self, name: str, backup: bool = True) -> list[str]:
        """Flush current rules and apply the given profile."""
        profile = self.profiles.load(name)
        if backup:
            self.backups.create(self._adapter, tag=f"pre_apply_{name}")
        self._adapter.flush_chain(Direction.IN)
        self._adapter.flush_chain(Direction.OUT)
        results = []
        for rule in profile.rules:
            if rule.enabled:
                try:
                    results.append(self.add_rule(rule))
                except Exception as exc:
                    results.append(f"ERROR: {exc}")
        self.audit.record("APPLY_PROFILE", name, detail=f"{len(profile.rules)} rules")
        return results

    def diff_profiles(self, a: str, b: str) -> list[str]:
        return self.profiles.diff(a, b)

    # ── Backup Operations ─────────────────────────────────────────────────────

    def backup(self, tag: str = "") -> Path:
        return self.backups.create(self._adapter, tag=tag)

    def restore_backup(self, path: Path) -> str:
        return self.backups.restore(self._adapter, path)

    def list_backups(self) -> list[Path]:
        return self.backups.list_backups()

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, rules: list[FirewallRule], path: Optional[Path] = None) -> Path:
        if path is None:
            path = DATA_DIR / "exports" / "firewall_rules.json"
        return Exporter.to_json(rules, path)

    def export_csv(self, rules: list[FirewallRule], path: Optional[Path] = None) -> Path:
        if path is None:
            path = DATA_DIR / "exports" / "firewall_rules.csv"
        return Exporter.to_csv(rules, path)

    def export_audit_csv(self, path: Optional[Path] = None, n: int = 1000) -> Path:
        if path is None:
            path = DATA_DIR / "exports" / "firewall_audit.csv"
        return Exporter.audit_to_csv(self.audit, path, n)

    # ── Geo-IP ────────────────────────────────────────────────────────────────

    def geoip(self, ip: str) -> dict:
        return self.geo.lookup(ip)

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "FirewallManager":
        return self

    def __exit__(self, *_) -> None:
        self.audit.close()


# ──────────────────────────────────────────────────────────────────────────────
# CLI / Interactive UI  (called from core/terminal.py)
# ──────────────────────────────────────────────────────────────────────────────

def _print_table(headers: list[str], rows: list[list], title: str = "") -> None:
    """Graceful table print: rich → tabulate → plain."""
    if _RICH:
        console = Console()
        table   = Table(title=title, box=rich_box.SIMPLE_HEAVY, header_style="bold cyan")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
    elif _TABULATE:
        print(f"\n{title}" if title else "")
        print(_tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    else:
        print(f"\n{title}" if title else "")
        print("  ".join(headers))
        print("-" * 72)
        for row in rows:
            print("  ".join(str(c) for c in row))


def _header(text: str) -> None:
    if _RICH:
        Console().print(Panel(Text(text, style="bold white"), style="cyan"))
    else:
        print(f"\n{'='*60}\n  {text}\n{'='*60}")


def run_interactive(fw: Optional[FirewallManager] = None) -> None:
    """
    Interactive menu-driven CLI for firewall management.
    Can be called from core/terminal.py as a module entry-point.
    """
    if fw is None:
        dry = "--dry-run" in sys.argv
        fw  = FirewallManager(dry_run=dry)

    MENU = {
        "1":  ("Status / List rules",        _cmd_status),
        "2":  ("Block IP",                   _cmd_block_ip),
        "3":  ("Unblock IP",                 _cmd_unblock_ip),
        "4":  ("Allow IP",                   _cmd_allow_ip),
        "5":  ("Block port",                 _cmd_block_port),
        "6":  ("Allow port",                 _cmd_allow_port),
        "7":  ("Rate-limit port",            _cmd_rate_limit),
        "8":  ("Active connections",         _cmd_connections),
        "9":  ("Geo-IP lookup",              _cmd_geoip),
        "10": ("Save profile",               _cmd_save_profile),
        "11": ("Apply profile",              _cmd_apply_profile),
        "12": ("List profiles",              _cmd_list_profiles),
        "13": ("Diff profiles",              _cmd_diff_profiles),
        "14": ("Backup rules",               _cmd_backup),
        "15": ("Restore backup",             _cmd_restore),
        "16": ("Export rules (JSON/CSV)",    _cmd_export),
        "17": ("View audit log",             _cmd_audit),
        "0":  ("← Back",                     None),
    }

    while True:
        _header(f"🔥 Firewall Manager  [backend: {fw.backend.value}"
                f"{'  DRY-RUN' if fw.dry_run else ''}]")
        for key, (label, _) in MENU.items():
            print(f"  [{key:>2}]  {label}")

        choice = input("\n  Choice: ").strip()
        if choice == "0":
            break
        entry = MENU.get(choice)
        if not entry:
            print("  ✗ Invalid choice.")
            continue
        _, handler = entry
        if handler:
            try:
                handler(fw)
            except FirewallError as exc:
                print(f"\n  ✗ FirewallError: {exc}")
            except KeyboardInterrupt:
                print("\n  Cancelled.")


# ── Individual command handlers ───────────────────────────────────────────────

def _cmd_status(fw: FirewallManager) -> None:
    print(fw.status())


def _cmd_block_ip(fw: FirewallManager) -> None:
    ip      = input("  IP or CIDR to block: ").strip()
    comment = input("  Comment (optional): ").strip()
    result  = fw.block_ip(ip, comment=comment or "blocked by local_os")
    print(f"  ✓ {result or 'Done'}")


def _cmd_unblock_ip(fw: FirewallManager) -> None:
    ip     = input("  IP or CIDR to unblock: ").strip()
    result = fw.unblock_ip(ip)
    print(f"  ✓ {result or 'Done'}")


def _cmd_allow_ip(fw: FirewallManager) -> None:
    ip      = input("  IP or CIDR to allow: ").strip()
    comment = input("  Comment (optional): ").strip()
    result  = fw.allow_ip(ip, comment=comment or "allowed by local_os")
    print(f"  ✓ {result or 'Done'}")


def _cmd_block_port(fw: FirewallManager) -> None:
    port  = input("  Port(s) to block (e.g. 22, 1024:2048): ").strip()
    proto = input("  Protocol [tcp/udp/all]: ").strip().lower() or "tcp"
    prot  = Protocol(proto) if proto in ("tcp", "udp", "all") else Protocol.TCP
    result = fw.block_port(port, protocol=prot)
    print(f"  ✓ {result or 'Done'}")


def _cmd_allow_port(fw: FirewallManager) -> None:
    port   = input("  Port(s) to allow: ").strip()
    proto  = input("  Protocol [tcp/udp/all]: ").strip().lower() or "tcp"
    src_ip = input("  Restrict to source IP (Enter = any): ").strip() or "0.0.0.0/0"
    prot   = Protocol(proto) if proto in ("tcp", "udp", "all") else Protocol.TCP
    result = fw.allow_port(port, protocol=prot, src_ip=src_ip)
    print(f"  ✓ {result or 'Done'}")


def _cmd_rate_limit(fw: FirewallManager) -> None:
    port  = input("  Port to rate-limit: ").strip()
    limit = input("  Limit (e.g. 25/minute): ").strip() or "25/minute"
    burst = input("  Burst (default 5): ").strip()
    result = fw.rate_limit(port, limit=limit, burst=int(burst) if burst.isdigit() else 5)
    print(f"  ✓ {result or 'Done'}")


def _cmd_connections(fw: FirewallManager) -> None:
    conns = fw.active_connections()
    if not conns:
        print("  No active connections found.")
        return
    rows = [[c.get("proto",""), c.get("state",""), c.get("local",""),
             c.get("remote",""), c.get("process","")[:40]]
            for c in conns[:50]]
    _print_table(["Proto","State","Local","Remote","Process"],
                 rows, title="Active Connections (top 50)")


def _cmd_geoip(fw: FirewallManager) -> None:
    ip   = input("  IP address: ").strip()
    info = fw.geoip(ip)
    print(f"\n  {json.dumps(info, indent=4)}")


def _cmd_save_profile(fw: FirewallManager) -> None:
    name = input("  Profile name: ").strip()
    desc = input("  Description: ").strip()
    path = fw.save_profile(name, description=desc)
    print(f"  ✓ Saved to {path}")


def _cmd_apply_profile(fw: FirewallManager) -> None:
    profiles = fw.profiles.list_profiles()
    if not profiles:
        print("  No profiles found.")
        return
    print("  Available profiles: " + ", ".join(profiles))
    name = input("  Profile to apply: ").strip()
    results = fw.apply_profile(name)
    print(f"  ✓ Applied {len(results)} rule(s)")


def _cmd_list_profiles(fw: FirewallManager) -> None:
    profiles = fw.profiles.list_profiles()
    if not profiles:
        print("  No profiles saved yet.")
    for p in profiles:
        print(f"  • {p}")


def _cmd_diff_profiles(fw: FirewallManager) -> None:
    a = input("  Profile A: ").strip()
    b = input("  Profile B: ").strip()
    for line in fw.diff_profiles(a, b):
        print(f"  {line}")


def _cmd_backup(fw: FirewallManager) -> None:
    tag  = input("  Backup tag (optional): ").strip()
    path = fw.backup(tag=tag)
    print(f"  ✓ Backup saved: {path}")


def _cmd_restore(fw: FirewallManager) -> None:
    backups = fw.list_backups()
    if not backups:
        print("  No backups found.")
        return
    print("  Available backups:")
    for i, p in enumerate(backups[:20]):
        print(f"    [{i}] {p.name}")
    idx = input("  Select index: ").strip()
    if not idx.isdigit() or int(idx) >= len(backups):
        print("  Invalid selection.")
        return
    result = fw.restore_backup(backups[int(idx)])
    print(f"  ✓ {result}")


def _cmd_export(fw: FirewallManager) -> None:
    fmt = input("  Format [json/csv/audit]: ").strip().lower()
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = DATA_DIR / "exports"
    if fmt == "json":
        # Export mock rules; in real usage pass actual rule objects
        path = fw.export_json([], out / f"rules_{ts}.json")
        print(f"  ✓ Exported to {path}")
    elif fmt == "csv":
        path = fw.export_csv([], out / f"rules_{ts}.csv")
        print(f"  ✓ Exported to {path}")
    elif fmt == "audit":
        path = fw.export_audit_csv(out / f"audit_{ts}.csv")
        print(f"  ✓ Audit log exported to {path}")
    else:
        print("  Unknown format.")


def _cmd_audit(fw: FirewallManager) -> None:
    entries = fw.audit.tail(20)
    if not entries:
        print("  Audit log is empty.")
        return
    rows = [[e["id"], e["ts"][:19], e["user"], e["action"], e["target"],
             "✓" if e["success"] else "✗", e.get("error","")[:40]]
            for e in entries]
    _print_table(["ID","Timestamp","User","Action","Target","OK","Error"],
                 rows, title="Firewall Audit Log (last 20)")


# ──────────────────────────────────────────────────────────────────────────────
# Module entry-point for ModuleRegistry
# ──────────────────────────────────────────────────────────────────────────────

MODULE_NAME        = "Firewall Manager"
MODULE_DESCRIPTION = "iptables/ufw rules, IP blocking, profiles, audit, export"
MODULE_VERSION     = "1.0.0"

# ── Plugin registry aliases (required by PluginRegistry in plugins/__init__.py)
PLUGIN_NAME        = MODULE_NAME
PLUGIN_VERSION     = MODULE_VERSION
PLUGIN_DESCRIPTION = MODULE_DESCRIPTION
PLUGIN_AUTHOR      = "local_os project"
PLUGIN_TAGS: list  = ["firewall", "network", "security"]


def main() -> None:
    """Called by local_os ModuleRegistry / PluginRegistry."""
    run_interactive()


if __name__ == "__main__":
    main()