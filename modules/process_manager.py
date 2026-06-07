"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Process Manager Module                               ║
║              modules/process_manager.py                                      ║
║                                                                              ║
║  Responsibilities:                                                           ║
║    • Real-time process listing with rich metadata                            ║
║    • Process search / filtering (name, PID, user, status, CPU, MEM)         ║
║    • Safe process termination (SIGTERM → SIGKILL escalation)                 ║
║    • Process tree view (parent → children)                                   ║
║    • Process suspension / resumption                                         ║
║    • Top-N resource consumers                                                ║
║    • Continuous live monitor (refresh loop)                                  ║
║    • Process details deep-dive (open files, threads, environment)           ║
║    • Nice / renice (priority management)                                     ║
║    • Batch kill by pattern                                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import re
import sys
import time
import signal
import threading
import platform
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Iterator, Optional

try:
    import psutil
except ImportError:
    class _MissingPsutil:
        def __getattr__(self, name):
            raise ImportError("Missing dependency 'psutil'. Install with: pip install psutil")
    psutil = _MissingPsutil()

# ── Local imports (project structure) ─────────────────────────────────────────
try:
    from core.ui import UI
    from core.config import Config
except ImportError:
    # Standalone fallback — lets the module be tested independently
    class UI:  # type: ignore
        @staticmethod
        def header(t: str) -> None: print(f"\n{'═'*60}\n  {t}\n{'═'*60}")
        @staticmethod
        def success(m: str) -> None: print(f"  ✔  {m}")
        @staticmethod
        def error(m: str) -> None:   print(f"  ✘  {m}", file=sys.stderr)
        @staticmethod
        def warn(m: str) -> None:    print(f"  ⚠  {m}")
        @staticmethod
        def info(m: str) -> None:    print(f"  ℹ  {m}")
        @staticmethod
        def prompt(p: str) -> str:   return input(f"  › {p}: ").strip()
        @staticmethod
        def table(rows: list[list], headers: list[str]) -> None:
            col_w = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
            sep = "─┼─".join("─" * w for w in col_w)
            fmt = " │ ".join(f"{{:<{w}}}" for w in col_w)
            print("  " + fmt.format(*headers))
            print("  " + sep)
            for row in rows:
                print("  " + fmt.format(*[str(v) for v in row]))
        @staticmethod
        def confirm(prompt: str) -> bool:
            return input(f"  › {prompt} [y/N]: ").strip().lower() == "y"

    class Config:  # type: ignore
        PROCESS_REFRESH_INTERVAL: float = 2.0
        PROCESS_TOP_N: int = 15
        KILL_ESCALATION_TIMEOUT: int = 5   # seconds before SIGKILL
        MAX_CMDLINE_LEN: int = 60


# ═══════════════════════════════════════════════════════════════════════════════
#  Enumerations & Constants
# ═══════════════════════════════════════════════════════════════════════════════

class SortKey(Enum):
    PID    = "pid"
    NAME   = "name"
    CPU    = "cpu_percent"
    MEM    = "memory_percent"
    USER   = "username"
    STATUS = "status"

class KillResult(Enum):
    SUCCESS        = auto()
    NOT_FOUND      = auto()
    PERMISSION     = auto()
    ALREADY_DEAD   = auto()
    ESCALATED      = auto()   # Had to use SIGKILL
    FAILED         = auto()

_WINDOWS = platform.system() == "Windows"

# ANSI helpers (used even when ui.py is available, for inline colouring)
_C = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "magenta":"\033[95m",
    "white":  "\033[97m",
}

def _c(colour: str, text: str) -> str:
    """Wrap *text* with ANSI colour, then reset."""
    return f"{_C.get(colour, '')}{text}{_C['reset']}"


# ═══════════════════════════════════════════════════════════════════════════════
#  Data Model
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ProcessSnapshot:
    """Immutable snapshot of a single process at a point in time."""

    pid:            int
    name:           str
    status:         str
    username:       str
    cpu_percent:    float
    memory_percent: float
    memory_rss:     int          # bytes
    num_threads:    int
    create_time:    float        # Unix timestamp
    ppid:           Optional[int]
    cmdline:        list[str]    = field(default_factory=list)
    nice:           Optional[int] = None

    # ── Derived helpers ────────────────────────────────────────────────────────

    @property
    def age_seconds(self) -> float:
        return time.time() - self.create_time

    @property
    def age_str(self) -> str:
        s = int(self.age_seconds)
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m{s % 60:02d}s"
        h = s // 3600
        m = (s % 3600) // 60
        return f"{h}h{m:02d}m"

    @property
    def rss_str(self) -> str:
        for unit, divisor in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
            if self.memory_rss >= divisor:
                return f"{self.memory_rss / divisor:.1f} {unit}"
        return f"{self.memory_rss} B"

    @property
    def short_cmd(self) -> str:
        raw = " ".join(self.cmdline) if self.cmdline else self.name
        limit = getattr(Config, "MAX_CMDLINE_LEN", 60)
        return raw if len(raw) <= limit else raw[: limit - 1] + "…"

    @property
    def status_coloured(self) -> str:
        palette = {
            "running":  "green",
            "sleeping": "cyan",
            "idle":     "blue",
            "stopped":  "yellow",
            "zombie":   "red",
            "dead":     "red",
            "disk-sleep": "magenta",
            "tracing-stop": "yellow",
        }
        colour = palette.get(self.status.lower(), "white")
        return _c(colour, self.status)

    @property
    def cpu_coloured(self) -> str:
        v = self.cpu_percent
        colour = "green" if v < 30 else "yellow" if v < 70 else "red"
        return _c(colour, f"{v:5.1f}%")

    @property
    def mem_coloured(self) -> str:
        v = self.memory_percent
        colour = "green" if v < 10 else "yellow" if v < 40 else "red"
        return _c(colour, f"{v:5.1f}%")


# ═══════════════════════════════════════════════════════════════════════════════
#  Core Engine
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessEngine:
    """
    Low-level process data access layer.

    All psutil interaction is isolated here so the rest of the module
    never imports psutil directly — making unit-testing trivial.
    """

    # Attributes fetched in a single psutil.process_iter() call
    _ITER_ATTRS = [
        "pid", "name", "status", "username",
        "cpu_percent", "memory_percent", "memory_info",
        "num_threads", "create_time", "ppid", "cmdline", "nice",
    ]

    @classmethod
    def snapshot_all(cls, *, sort: SortKey = SortKey.CPU) -> list[ProcessSnapshot]:
        """
        Return a sorted list of ProcessSnapshot objects for every running process.

        A first ``cpu_percent`` call always returns 0.0 (psutil limitation).
        The engine performs a small warm-up sleep on the first invocation so
        subsequent calls return meaningful values.
        """
        snapshots: list[ProcessSnapshot] = []

        for proc in psutil.process_iter(cls._ITER_ATTRS):
            try:
                info = proc.info  # type: ignore[attr-defined]
                mem  = info["memory_info"]
                snap = ProcessSnapshot(
                    pid            = info["pid"],
                    name           = info["name"] or "<unknown>",
                    status         = info["status"] or "unknown",
                    username       = info["username"] or "unknown",
                    cpu_percent    = info["cpu_percent"] or 0.0,
                    memory_percent = info["memory_percent"] or 0.0,
                    memory_rss     = mem.rss if mem else 0,
                    num_threads    = info["num_threads"] or 0,
                    create_time    = info["create_time"] or time.time(),
                    ppid           = info["ppid"],
                    cmdline        = info["cmdline"] or [],
                    nice           = info.get("nice"),
                )
                snapshots.append(snap)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        reverse = sort in (SortKey.CPU, SortKey.MEM)
        return sorted(snapshots, key=lambda p: getattr(p, sort.value), reverse=reverse)

    @classmethod
    def get_one(cls, pid: int) -> Optional[ProcessSnapshot]:
        """Return a single ProcessSnapshot for *pid*, or None."""
        try:
            p    = psutil.Process(pid)
            info = p.as_dict(attrs=cls._ITER_ATTRS)
            mem  = info["memory_info"]
            return ProcessSnapshot(
                pid            = info["pid"],
                name           = info["name"] or "<unknown>",
                status         = info["status"] or "unknown",
                username       = info["username"] or "unknown",
                cpu_percent    = p.cpu_percent(interval=0.2),
                memory_percent = info["memory_percent"] or 0.0,
                memory_rss     = mem.rss if mem else 0,
                num_threads    = info["num_threads"] or 0,
                create_time    = info["create_time"] or time.time(),
                ppid           = info["ppid"],
                cmdline        = info["cmdline"] or [],
                nice           = info.get("nice"),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @classmethod
    def children_of(cls, pid: int, *, recursive: bool = True) -> list[psutil.Process]:
        try:
            return psutil.Process(pid).children(recursive=recursive)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    @classmethod
    def build_tree(cls) -> dict[int, list[int]]:
        """Return {parent_pid: [child_pid, …]} mapping."""
        tree: dict[int, list[int]] = {}
        for proc in psutil.process_iter(["pid", "ppid"]):
            try:
                ppid = proc.info["ppid"]  # type: ignore[index]
                pid  = proc.info["pid"]   # type: ignore[index]
                tree.setdefault(ppid, []).append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return tree

    @classmethod
    def open_files_of(cls, pid: int) -> list[str]:
        try:
            return [f.path for f in psutil.Process(pid).open_files()]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    @classmethod
    def connections_of(cls, pid: int) -> list[dict]:
        try:
            result = []
            for c in psutil.Process(pid).net_connections(kind="inet"):
                result.append({
                    "fd":     c.fd,
                    "family": str(c.family),
                    "type":   str(c.type),
                    "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                    "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                    "status": c.status,
                })
            return result
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            return []

    @classmethod
    def environ_of(cls, pid: int) -> dict[str, str]:
        try:
            return psutil.Process(pid).environ()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}


# ═══════════════════════════════════════════════════════════════════════════════
#  Kill / Signal Logic
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessTerminator:
    """
    Safe, escalating process termination.

    Strategy
    ────────
    1.  Send SIGTERM (graceful shutdown request).
    2.  Wait up to *timeout* seconds for the process to exit.
    3.  If still alive → send SIGKILL (immediate).
    4.  Return a KillResult enum that the UI can translate.
    """

    def __init__(self, escalation_timeout: int | None = None) -> None:
        self._timeout = escalation_timeout or getattr(
            Config, "KILL_ESCALATION_TIMEOUT", 5
        )

    def kill(self, pid: int, *, force: bool = False) -> KillResult:
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return KillResult.NOT_FOUND

        try:
            if force or _WINDOWS:
                proc.kill()   # SIGKILL / TerminateProcess
                return KillResult.SUCCESS

            proc.terminate()   # SIGTERM
            try:
                proc.wait(timeout=self._timeout)
                return KillResult.SUCCESS
            except psutil.TimeoutExpired:
                proc.kill()    # Escalate → SIGKILL
                proc.wait(timeout=3)
                return KillResult.ESCALATED

        except psutil.NoSuchProcess:
            return KillResult.ALREADY_DEAD
        except psutil.AccessDenied:
            return KillResult.PERMISSION
        except Exception:
            return KillResult.FAILED

    def suspend(self, pid: int) -> bool:
        try:
            psutil.Process(pid).suspend()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def resume(self, pid: int) -> bool:
        try:
            psutil.Process(pid).resume()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def renice(self, pid: int, nice: int) -> bool:
        """Set process niceness (priority). Range: -20 (highest) … 19 (lowest)."""
        try:
            psutil.Process(pid).nice(nice)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
            return False

    def kill_pattern(self, pattern: str, *, force: bool = False) -> dict[int, KillResult]:
        """Kill every process whose name matches *pattern* (case-insensitive regex)."""
        regex   = re.compile(pattern, re.IGNORECASE)
        results: dict[int, KillResult] = {}
        for snap in ProcessEngine.snapshot_all():
            if regex.search(snap.name):
                results[snap.pid] = self.kill(snap.pid, force=force)
        return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Live Monitor (background thread)
# ═══════════════════════════════════════════════════════════════════════════════

class LiveMonitor:
    """
    Runs ProcessEngine.snapshot_all() in a background thread and stores the
    most recent snapshot list.  The UI calls ``get()`` to read the latest data
    without blocking.
    """

    def __init__(
        self,
        *,
        refresh: float | None = None,
        sort: SortKey = SortKey.CPU,
        on_update: Callable[[list[ProcessSnapshot]], None] | None = None,
    ) -> None:
        self._interval  = refresh or getattr(Config, "PROCESS_REFRESH_INTERVAL", 2.0)
        self._sort      = sort
        self._on_update = on_update
        self._data:  list[ProcessSnapshot] = []
        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="pm-live")

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> "LiveMonitor":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=self._interval + 1)

    def get(self) -> list[ProcessSnapshot]:
        with self._lock:
            return list(self._data)

    def change_sort(self, sort: SortKey) -> None:
        self._sort = sort

    # ── Internal ───────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        # Warm-up: first cpu_percent call returns 0; sleep briefly
        psutil.cpu_percent(interval=None)
        time.sleep(0.3)

        while not self._stop.is_set():
            snaps = ProcessEngine.snapshot_all(sort=self._sort)
            with self._lock:
                self._data = snaps
            if self._on_update:
                self._on_update(snaps)
            self._stop.wait(self._interval)


# ═══════════════════════════════════════════════════════════════════════════════
#  Formatting Helpers
# ═══════════════════════════════════════════════════════════════════════════════

class Formatter:
    """Renders ProcessSnapshot objects into various human-readable representations."""

    _COLS = [
        ("PID",     6),
        ("NAME",   20),
        ("USER",   12),
        ("STATUS",  9),
        ("CPU%",    6),
        ("MEM%",    6),
        ("RSS",     9),
        ("THR",     4),
        ("AGE",     8),
        ("COMMAND", 0),   # 0 = fill remaining width
    ]

    @classmethod
    def _terminal_width(cls) -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 120

    @classmethod
    def header_line(cls) -> str:
        parts = []
        for name, w in cls._COLS:
            if w == 0:
                parts.append(name)
            else:
                parts.append(f"{name:<{w}}")
        return _c("bold", "  " + "  ".join(parts))

    @classmethod
    def separator(cls) -> str:
        width = cls._terminal_width()
        return _c("dim", "  " + "─" * (width - 2))

    @classmethod
    def row(cls, s: ProcessSnapshot) -> str:
        tw = cls._terminal_width()
        # Fixed columns
        pid_s  = f"{s.pid:<6}"
        name_s = s.name[:20].ljust(20)
        user_s = (s.username or "")[:12].ljust(12)
        # Status & metrics with colour
        stat_s = s.status_coloured.ljust(9 + 9)   # +9 for ANSI escape overhead
        cpu_s  = s.cpu_coloured.ljust(6 + 9)
        mem_s  = s.mem_coloured.ljust(6 + 9)
        rss_s  = s.rss_str[:9].ljust(9)
        thr_s  = f"{s.num_threads:<4}"
        age_s  = s.age_str[:8].ljust(8)
        # Command: fill remaining terminal width
        used = 6 + 20 + 12 + 9 + 6 + 6 + 9 + 4 + 8 + (2 * 9) + 20  # approx
        cmd_w = max(10, tw - used)
        cmd_s = s.short_cmd[:cmd_w]
        return "  " + "  ".join([
            pid_s, name_s, user_s, stat_s,
            cpu_s, mem_s, rss_s, thr_s, age_s, cmd_s,
        ])

    @classmethod
    def detail_block(cls, s: ProcessSnapshot) -> str:
        lines = [
            _c("bold", f"\n  ┌─ Process Detail: {s.name} (PID {s.pid}) "),
            f"  │  {'Status':<16}: {s.status_coloured}",
            f"  │  {'User':<16}: {s.username}",
            f"  │  {'CPU':<16}: {s.cpu_coloured}",
            f"  │  {'Memory %':<16}: {s.mem_coloured}",
            f"  │  {'Memory RSS':<16}: {s.rss_str}",
            f"  │  {'Threads':<16}: {s.num_threads}",
            f"  │  {'Nice':<16}: {s.nice if s.nice is not None else 'n/a'}",
            f"  │  {'Parent PID':<16}: {s.ppid}",
            f"  │  {'Uptime':<16}: {s.age_str}",
            f"  │  {'Command':<16}: {' '.join(s.cmdline) if s.cmdline else s.name}",
            f"  └{'─' * 58}",
        ]
        return "\n".join(lines)

    @classmethod
    def tree_lines(
        cls,
        pid: int,
        tree: dict[int, list[int]],
        names: dict[int, str],
        *,
        prefix: str = "",
        is_last: bool = True,
    ) -> Iterator[str]:
        connector = "└─ " if is_last else "├─ "
        name = names.get(pid, "?")
        yield f"  {prefix}{connector}{_c('cyan', str(pid))} {name}"
        children = tree.get(pid, [])
        extension = "   " if is_last else "│  "
        for i, child in enumerate(children):
            yield from cls.tree_lines(
                child, tree, names,
                prefix=prefix + extension,
                is_last=(i == len(children) - 1),
            )


# ═══════════════════════════════════════════════════════════════════════════════
#  Menu Controller  (called by terminal.py)
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessManager:
    """
    High-level orchestrator — the only class that terminal.py needs to import.

    Usage in terminal.py
    ────────────────────
        from modules.process_manager import ProcessManager
        pm = ProcessManager()
        pm.menu()
    """

    _SORT_MAP: dict[str, SortKey] = {
        "1": SortKey.CPU,
        "2": SortKey.MEM,
        "3": SortKey.PID,
        "4": SortKey.NAME,
        "5": SortKey.USER,
        "6": SortKey.STATUS,
    }

    def __init__(self) -> None:
        self._terminator = ProcessTerminator()
        self._sort       = SortKey.CPU
        self._monitor:   Optional[LiveMonitor] = None

    # ══════════════════════════════════════════════════════════════════════════
    #  Public entry point
    # ══════════════════════════════════════════════════════════════════════════

    def menu(self) -> None:
        """Display the Process Manager sub-menu and dispatch user choices."""
        while True:
            UI.header("⚙  Process Manager")
            self._print_menu()
            choice = UI.prompt("Select option").lower()

            dispatch = {
                "1":  self._list_processes,
                "2":  self._search_processes,
                "3":  self._kill_by_pid,
                "4":  self._kill_by_pattern,
                "5":  self._process_detail,
                "6":  self._process_tree,
                "7":  self._top_consumers,
                "8":  self._live_monitor,
                "9":  self._suspend_resume,
                "10": self._renice_process,
                "0":  None,
            }

            if choice == "0":
                break
            handler = dispatch.get(choice)
            if handler is None:
                UI.warn("Invalid option.")
            else:
                try:
                    handler()
                except KeyboardInterrupt:
                    UI.info("Interrupted.")
                except Exception as exc:
                    UI.error(f"Unexpected error: {exc}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Menu Handlers
    # ══════════════════════════════════════════════════════════════════════════

    def _list_processes(self) -> None:
        UI.header("📋  Process List")
        self._print_sort_menu()
        sort_choice = UI.prompt("Sort by (1-6, Enter=keep)").strip()
        if sort_choice in self._SORT_MAP:
            self._sort = self._SORT_MAP[sort_choice]

        top_n = getattr(Config, "PROCESS_TOP_N", 15)
        raw   = UI.prompt(f"Show top N (Enter={top_n})").strip()
        n     = int(raw) if raw.isdigit() else top_n

        snaps = ProcessEngine.snapshot_all(sort=self._sort)[:n]
        self._render_table(snaps)
        UI.info(f"Showing {len(snaps)} of {self._total_count()} processes  │  "
                f"Sort: {self._sort.value}")
        self._pause()

    def _search_processes(self) -> None:
        UI.header("🔍  Search Processes")
        term = UI.prompt("Search (name / PID / user / status)")
        if not term:
            UI.warn("Empty query.")
            return

        snaps = ProcessEngine.snapshot_all(sort=self._sort)
        results = [
            s for s in snaps
            if (term.lower() in s.name.lower()
                or term.lower() in (s.username or "").lower()
                or term.lower() in s.status.lower()
                or (term.isdigit() and s.pid == int(term)))
        ]

        if not results:
            UI.warn(f"No processes matched '{term}'.")
            return

        UI.info(f"Found {len(results)} matching process(es):")
        self._render_table(results)
        self._pause()

    def _kill_by_pid(self) -> None:
        UI.header("💀  Kill Process by PID")
        raw = UI.prompt("Enter PID")
        if not raw.isdigit():
            UI.error("Invalid PID.")
            return
        pid = int(raw)

        snap = ProcessEngine.get_one(pid)
        if snap is None:
            UI.error(f"No process with PID {pid}.")
            return

        print(Formatter.detail_block(snap))
        force = UI.confirm("Force kill (SIGKILL immediately)?")
        if not UI.confirm(f"Terminate {snap.name} (PID {pid})?"):
            UI.info("Aborted.")
            return

        result = self._terminator.kill(pid, force=force)
        self._report_kill_result(pid, snap.name, result)
        self._pause()

    def _kill_by_pattern(self) -> None:
        UI.header("💀  Kill by Name Pattern")
        pattern = UI.prompt("Regex pattern (e.g. chrome|firefox)")
        if not pattern:
            return

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            UI.error(f"Invalid regex: {e}")
            return

        snaps   = ProcessEngine.snapshot_all(sort=SortKey.NAME)
        matches = [s for s in snaps if regex.search(s.name)]

        if not matches:
            UI.warn("No matching processes found.")
            return

        UI.warn(f"About to kill {len(matches)} process(es):")
        self._render_table(matches)

        force = UI.confirm("Force kill (SIGKILL)?")
        if not UI.confirm("Proceed?"):
            UI.info("Aborted.")
            return

        results = self._terminator.kill_pattern(pattern, force=force)
        ok = sum(1 for r in results.values() if r in (KillResult.SUCCESS, KillResult.ESCALATED))
        UI.success(f"Sent kill signal to {ok}/{len(results)} processes.")
        for pid, res in results.items():
            sym = "✔" if res in (KillResult.SUCCESS, KillResult.ESCALATED) else "✘"
            print(f"    {sym}  PID {pid}: {res.name}")
        self._pause()

    def _process_detail(self) -> None:
        UI.header("🔬  Process Detail")
        raw = UI.prompt("Enter PID")
        if not raw.isdigit():
            UI.error("Invalid PID.")
            return
        pid  = int(raw)
        snap = ProcessEngine.get_one(pid)
        if snap is None:
            UI.error(f"No process with PID {pid}.")
            return

        print(Formatter.detail_block(snap))

        # Open files
        files = ProcessEngine.open_files_of(pid)
        if files:
            print(f"\n  {_c('bold', 'Open files')} ({len(files)}):")
            for f in files[:20]:
                print(f"    • {f}")
            if len(files) > 20:
                print(f"    … and {len(files) - 20} more")

        # Network connections
        conns = ProcessEngine.connections_of(pid)
        if conns:
            print(f"\n  {_c('bold', 'Network connections')} ({len(conns)}):")
            UI.table(
                [[c["laddr"], c["raddr"], c["status"], c["type"]] for c in conns],
                ["LOCAL ADDR", "REMOTE ADDR", "STATUS", "TYPE"],
            )

        self._pause()

    def _process_tree(self) -> None:
        UI.header("🌳  Process Tree")
        raw   = UI.prompt("Root PID (Enter = system root 0/1)")
        tree  = ProcessEngine.build_tree()

        # Build name lookup
        names: dict[int, str] = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                names[p.info["pid"]] = p.info["name"] or "?"  # type: ignore[index]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        root_pid = int(raw) if raw.isdigit() else (1 if not _WINDOWS else 0)
        print()
        for line in Formatter.tree_lines(root_pid, tree, names):
            print(line)
        self._pause()

    def _top_consumers(self) -> None:
        UI.header("🏆  Top Resource Consumers")
        # CPU top-N
        cpu_top = ProcessEngine.snapshot_all(sort=SortKey.CPU)[:10]
        print(f"\n  {_c('bold', 'Top 10 by CPU')}")
        self._render_table(cpu_top)

        # MEM top-N
        mem_top = ProcessEngine.snapshot_all(sort=SortKey.MEM)[:10]
        print(f"\n  {_c('bold', 'Top 10 by Memory')}")
        self._render_table(mem_top)
        self._pause()

    def _live_monitor(self) -> None:
        UI.header("📡  Live Process Monitor")
        interval_raw = UI.prompt("Refresh interval seconds (Enter=2.0)")
        interval     = float(interval_raw) if interval_raw else 2.0
        top_n_raw    = UI.prompt(f"Show top N (Enter=15)")
        top_n        = int(top_n_raw) if top_n_raw.isdigit() else 15

        UI.info("Starting live monitor  │  Press Ctrl+C to stop")
        time.sleep(0.8)

        monitor = LiveMonitor(refresh=interval, sort=self._sort)
        monitor.start()

        try:
            while True:
                snaps = monitor.get()
                self._clear_screen()
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                print(_c("bold", f"  ⚡ Live Monitor  │  {ts}  │  "
                          f"Sort: {self._sort.value}  │  Ctrl+C to exit\n"))
                self._render_table(snaps[:top_n])
                cpu_g = psutil.cpu_percent(interval=None)
                mem_g = psutil.virtual_memory()
                print(
                    f"\n  System  CPU: {self._bar(cpu_g, 20)}  {cpu_g:.1f}%  │  "
                    f"RAM: {self._bar(mem_g.percent, 20)}  {mem_g.percent:.1f}%  "
                    f"({mem_g.used >> 20} MB / {mem_g.total >> 20} MB)"
                )
                time.sleep(interval)
        except KeyboardInterrupt:
            monitor.stop()
            UI.info("Live monitor stopped.")

    def _suspend_resume(self) -> None:
        UI.header("⏸  Suspend / Resume Process")
        raw = UI.prompt("Enter PID")
        if not raw.isdigit():
            UI.error("Invalid PID.")
            return
        pid  = int(raw)
        snap = ProcessEngine.get_one(pid)
        if snap is None:
            UI.error(f"No process with PID {pid}.")
            return
        print(Formatter.detail_block(snap))
        action = UI.prompt("Action: (s)uspend / (r)esume").lower()
        if action.startswith("s"):
            ok = self._terminator.suspend(pid)
            UI.success(f"Process {pid} suspended.") if ok else UI.error("Failed.")
        elif action.startswith("r"):
            ok = self._terminator.resume(pid)
            UI.success(f"Process {pid} resumed.") if ok else UI.error("Failed.")
        else:
            UI.warn("Unknown action.")
        self._pause()

    def _renice_process(self) -> None:
        UI.header("🎚  Renice Process")
        raw = UI.prompt("Enter PID")
        if not raw.isdigit():
            UI.error("Invalid PID.")
            return
        pid  = int(raw)
        snap = ProcessEngine.get_one(pid)
        if snap is None:
            UI.error(f"No process with PID {pid}.")
            return
        print(Formatter.detail_block(snap))
        UI.info("Nice range: -20 (highest priority) … 19 (lowest priority)")
        nice_raw = UI.prompt("New nice value")
        if not nice_raw.lstrip("-").isdigit():
            UI.error("Invalid value.")
            return
        nice = int(nice_raw)
        if not (-20 <= nice <= 19):
            UI.error("Nice must be between -20 and 19.")
            return
        ok = self._terminator.renice(pid, nice)
        UI.success(f"PID {pid} nice → {nice}") if ok else UI.error("Failed (permission?).")
        self._pause()

    # ══════════════════════════════════════════════════════════════════════════
    #  Internal Helpers
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _print_menu() -> None:
        items = [
            ("1",  "List processes"),
            ("2",  "Search processes"),
            ("3",  "Kill by PID"),
            ("4",  "Kill by pattern (regex)"),
            ("5",  "Process detail (files, connections)"),
            ("6",  "Process tree"),
            ("7",  "Top CPU / MEM consumers"),
            ("8",  "Live monitor"),
            ("9",  "Suspend / Resume"),
            ("10", "Renice (priority)"),
            ("0",  "Back"),
        ]
        print()
        for key, label in items:
            bullet = _c("cyan", f"[{key}]")
            print(f"    {bullet}  {label}")
        print()

    @staticmethod
    def _print_sort_menu() -> None:
        keys = ["1=CPU", "2=MEM", "3=PID", "4=NAME", "5=USER", "6=STATUS"]
        print("  " + _c("dim", "Sort: " + "  ".join(keys)))

    @staticmethod
    def _render_table(snaps: list[ProcessSnapshot]) -> None:
        if not snaps:
            UI.warn("No processes to display.")
            return
        print()
        print(Formatter.header_line())
        print(Formatter.separator())
        for s in snaps:
            print(Formatter.row(s))

    @staticmethod
    def _report_kill_result(pid: int, name: str, result: KillResult) -> None:
        msg = f"{name} (PID {pid})"
        if result == KillResult.SUCCESS:
            UI.success(f"Terminated {msg}.")
        elif result == KillResult.ESCALATED:
            UI.warn(f"SIGTERM ignored — escalated to SIGKILL: {msg}.")
        elif result == KillResult.NOT_FOUND:
            UI.error(f"Process not found: {msg}.")
        elif result == KillResult.PERMISSION:
            UI.error(f"Permission denied for {msg}. Try with elevated privileges.")
        elif result == KillResult.ALREADY_DEAD:
            UI.warn(f"Process {msg} already exited.")
        else:
            UI.error(f"Kill failed for {msg}.")

    @staticmethod
    def _total_count() -> int:
        return sum(1 for _ in psutil.process_iter())

    @staticmethod
    def _clear_screen() -> None:
        os.system("cls" if _WINDOWS else "clear")

    @staticmethod
    def _bar(percent: float, width: int = 20) -> str:
        filled = int(percent / 100 * width)
        colour = "green" if percent < 60 else "yellow" if percent < 85 else "red"
        bar    = "█" * filled + "░" * (width - filled)
        return _c(colour, bar)

    @staticmethod
    def _pause() -> None:
        input(_c("dim", "\n  Press Enter to continue…"))


# ═══════════════════════════════════════════════════════════════════════════════
#  Standalone smoke-test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Run directly for a quick smoke-test without the full terminal.py stack:
        python modules/process_manager.py
    """
    pm = ProcessManager()
    pm.menu()