"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Terminal Controller                                  ║
║              core/terminal.py                                                ║
║                                                                              ║
║  Single point of orchestration between the user, UI layer, and modules.     ║
║                                                                              ║
║  Responsibilities:                                                           ║
║    • Application lifecycle: init → main loop → graceful shutdown            ║
║    • Main menu rendering and input routing                                   ║
║    • Per-module sub-menu dispatch (adapts to each module's API style)       ║
║    • Global command handling: help, settings, diagnostics, quit             ║
║    • Plugin discovery and invocation via PluginRegistry                     ║
║    • Exception isolation — a crashed module never kills the session         ║
║    • Keyboard-interrupt handling at every level                              ║
║    • Session statistics (uptime, commands executed)                          ║
║    • Startup health-check with dependency diagnostics                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import re
import sys
import signal
import traceback
import datetime
import platform
import time
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Core imports ───────────────────────────────────────────────────────────────
from core.config import Config
from core.ui import UI, Ansi, _term_width, _clear, _pause


# ═══════════════════════════════════════════════════════════════════════════════
#  Sentinel — returned by _get_choice() when the user hits Ctrl+C
# ═══════════════════════════════════════════════════════════════════════════════

class _Interrupted(Exception):
    """Raised when the user presses Ctrl+C during an input() call."""


# ═══════════════════════════════════════════════════════════════════════════════
#  Session statistics
# ═══════════════════════════════════════════════════════════════════════════════

class _Session:
    """Lightweight struct tracking per-run statistics."""

    def __init__(self) -> None:
        self.started_at:   datetime.datetime = datetime.datetime.now()
        self.commands_run: int               = 0
        self.errors:       int               = 0
        self.last_module:  Optional[str]     = None

    @property
    def uptime(self) -> str:
        delta = datetime.datetime.now() - self.started_at
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def record(self, module_key: str) -> None:
        self.commands_run += 1
        self.last_module   = module_key

    def record_error(self) -> None:
        self.errors += 1


# ═══════════════════════════════════════════════════════════════════════════════
#  Module adapter layer
#
#  Each module was written independently with its own menu style.
#  These thin adapters normalise the differences so terminal.py can call a
#  single  module_adapter(key)  without knowing how each module works.
# ═══════════════════════════════════════════════════════════════════════════════

# ── Original adapters (unchanged) ─────────────────────────────────────────────

def _adapt_system_info(instance: Any) -> None:
    instance.menu()


def _adapt_process_manager(instance: Any) -> None:
    instance.menu()


def _adapt_network(instance: Any) -> None:
    ITEMS: List[Tuple[str, str, Callable]] = [
        ("1",  "Port Scanner",          instance.menu_port_scan),
        ("2",  "Ping Host",             instance.menu_ping),
        ("3",  "DNS Lookup",            instance.menu_dns_lookup),
        ("4",  "Reverse DNS",           instance.menu_reverse_dns),
        ("5",  "Traceroute",            instance.menu_traceroute),
        ("6",  "Whois",                 instance.menu_whois),
        ("7",  "HTTP Inspector",        instance.menu_http_inspect),
        ("8",  "Subnet Calculator",     instance.menu_subnet_calc),
        ("9",  "Network Interfaces",    instance.menu_interfaces),
        ("10", "Active Connections",    instance.menu_connections),
        ("11", "ARP Table",             instance.menu_arp),
    ]
    _generic_sub_menu("🌐  Network Tools", ITEMS)


def _adapt_crypto(instance: Any) -> None:
    ITEMS: List[Tuple[str, str, Callable]] = [
        ("1",  "Hash File",             instance.menu_hash_file),
        ("2",  "Hash Multiple Files",   instance.menu_hash_multi),
        ("3",  "Verify Hash",           instance.menu_verify_hash),
        ("4",  "Encrypt File (Fernet)", instance.menu_encrypt_file),
        ("5",  "Decrypt File (Fernet)", instance.menu_decrypt_file),
        ("6",  "RSA Key Generation",    instance.menu_rsa_keygen),
        ("7",  "RSA Sign / Verify",     instance.menu_rsa_sign_verify),
        ("8",  "HMAC",                  instance.menu_hmac),
        ("9",  "Password Generator",    instance.menu_password_generator),
        ("10", "Secure Token",          instance.menu_token_generator),
        ("11", "Create Manifest",       instance.menu_manifest_create),
        ("12", "Verify Manifest",       instance.menu_manifest_verify),
        ("13", "Base64 Encode/Decode",  instance.menu_encode_decode),
    ]
    _generic_sub_menu("🔐  Crypto Tools", ITEMS)


def _adapt_vault(instance: Any) -> None:
    from modules.vault import run_vault  # type: ignore
    run_vault()


def _adapt_file_tools(instance: Any) -> None:
    from modules.file_tools import run_file_tools  # type: ignore
    run_file_tools()


def _adapt_sqlite(instance: Any) -> None:
    instance.run()


def _adapt_scheduler(instance: Any) -> None:
    _scheduler_menu(instance)


# ── New module adapters ────────────────────────────────────────────────────────

def _adapt_docker(instance: Any) -> None:
    """docker_manager.py exposes a main() entry-point."""
    from modules.docker_manager import main as docker_main  # type: ignore
    docker_main()


def _adapt_log_analyzer(instance: Any) -> None:
    """log_analyzer.py exposes a main() entry-point."""
    from modules.log_analyzer import main as log_main  # type: ignore
    log_main()


def _adapt_git_tools(instance: Any) -> None:
    """git_tools.py exposes a main() entry-point."""
    from modules.git_tools import main as git_main  # type: ignore
    git_main()


def _adapt_firewall(instance: Any) -> None:
    """
    firewall.py exposes run_interactive(fw).
    We instantiate FirewallManager here so the adapter decides dry-run mode.
    """
    from modules.firewall import FirewallManager, run_interactive  # type: ignore
    dry = os.environ.get("LOCAL_OS_FIREWALL_DRY", "").lower() in ("1", "true")
    with FirewallManager(dry_run=dry) as fw:
        run_interactive(fw)


# ── Adapter registry  (key → callable) ────────────────────────────────────────

_ADAPTERS: Dict[str, Callable[[Any], None]] = {
    # original
    "system_info":     _adapt_system_info,
    "process_manager": _adapt_process_manager,
    "network":         _adapt_network,
    "crypto":          _adapt_crypto,
    "vault":           _adapt_vault,
    "file_tools":      _adapt_file_tools,
    "sqlite_shell":    _adapt_sqlite,
    "scheduler":       _adapt_scheduler,
    # new
    "docker_manager":  _adapt_docker,
    "log_analyzer":    _adapt_log_analyzer,
    "git_tools":       _adapt_git_tools,
    "firewall":        _adapt_firewall,
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Generic sub-menu helper
# ═══════════════════════════════════════════════════════════════════════════════

def _generic_sub_menu(
    title: str,
    items: List[Tuple[str, str, Callable]],
    *,
    back_key: str = "0",
) -> None:
    dispatch: Dict[str, Callable] = {key: fn for key, _, fn in items}
    menu_rows: List[Tuple[str, str, str]] = [
        (key, "", label) for key, label, _ in items
    ]
    menu_rows.append((back_key, "", "Back"))

    while True:
        _clear()
        UI.header(title)
        UI.main_menu(menu_rows)

        choice = _get_choice()
        if isinstance(choice, _Interrupted) or choice == back_key:
            return

        fn = dispatch.get(choice)
        if fn is None:
            UI.warn(f"Unknown option: {choice!r}")
            time.sleep(0.6)
            continue

        try:
            fn()
            _pause()
        except KeyboardInterrupt:
            UI.info("Interrupted — returning to sub-menu.")
            time.sleep(0.3)
        except Exception as exc:
            _handle_module_exception(exc, title)


# ═══════════════════════════════════════════════════════════════════════════════
#  Scheduler sub-menu  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def _scheduler_menu(mod: Any) -> None:
    mod.cmd_start()
    ITEMS_STATIC: List[Tuple[str, str, Callable]] = [
        ("1", "List all tasks",      lambda: _sched_list(mod)),
        ("2", "Add demo task",       lambda: _sched_add_demo(mod)),
        ("3", "Remove task",         lambda: _sched_remove(mod)),
        ("4", "Run task now",        lambda: _sched_run_now(mod)),
        ("5", "Enable task",         lambda: _sched_enable(mod)),
        ("6", "Disable task",        lambda: _sched_disable(mod)),
        ("7", "View task history",   lambda: _sched_history(mod)),
        ("8", "Scheduler stats",     lambda: _sched_stats(mod)),
        ("9", "Stop scheduler",      lambda: _sched_stop(mod)),
    ]
    _generic_sub_menu("🕑  Task Scheduler", ITEMS_STATIC)


def _sched_list(mod: Any) -> None:
    UI.header("📋  All Tasks")
    tasks = mod.cmd_list()
    if not tasks:
        UI.info("No tasks registered.")
        _pause()
        return
    rows = []
    for t in tasks:
        rows.append([
            str(t.get("id", ""))[:12],
            t.get("name", ""),
            t.get("status", ""),
            t.get("trigger", ""),
            str(t.get("run_count", 0)),
            t.get("last_run", "") or "—",
        ])
    UI.table(rows, ["ID", "NAME", "STATUS", "TRIGGER", "RUNS", "LAST RUN"],
             zebra=True, max_col_width=30)
    _pause()


def _sched_add_demo(mod: Any) -> None:
    UI.header("➕  Add Demo Task")
    tid = mod.cmd_add_demo()
    UI.success(f"Demo task created — ID: {Ansi.bold(tid)}")
    _pause()


def _sched_remove(mod: Any) -> None:
    UI.header("🗑  Remove Task")
    tid = UI.prompt("Task ID")
    if not tid:
        UI.warn("Aborted — no ID entered.")
        _pause()
        return
    if not UI.confirm(f"Delete task {tid!r}?"):
        _pause()
        return
    try:
        mod.cmd_remove(tid)
        UI.success(f"Task {tid!r} removed.")
    except Exception as e:
        UI.error(str(e))
    _pause()


def _sched_run_now(mod: Any) -> None:
    UI.header("▶  Run Task Now")
    tid = UI.prompt("Task ID")
    if not tid:
        UI.warn("Aborted.")
        _pause()
        return
    try:
        rec = mod.cmd_run_now(tid)
        if rec:
            UI.success(f"Task completed — status: {rec.status}  "
                       f"duration: {rec.duration_ms} ms")
        else:
            UI.warn("Task returned no record.")
    except Exception as e:
        UI.error(str(e))
    _pause()


def _sched_enable(mod: Any) -> None:
    tid = UI.prompt("Task ID to enable")
    if tid:
        mod.cmd_enable(tid)
        UI.success(f"Task {tid!r} enabled.")
    _pause()


def _sched_disable(mod: Any) -> None:
    tid = UI.prompt("Task ID to disable")
    if tid:
        mod.cmd_disable(tid)
        UI.success(f"Task {tid!r} disabled.")
    _pause()


def _sched_history(mod: Any) -> None:
    UI.header("📜  Task Run History")
    tid   = UI.prompt("Task ID")
    limit = UI.prompt("Max records (Enter=10)")
    try:
        n = int(limit) if limit else 10
    except ValueError:
        n = 10
    records = mod.cmd_history(tid, n)
    if not records:
        UI.info("No history found.")
        _pause()
        return
    rows = []
    for r in records:
        rows.append([
            r.get("started_at", ""),
            r.get("status", ""),
            f"{r.get('duration_ms', 0)} ms",
            str(r.get("output", ""))[:50],
        ])
    UI.table(rows, ["STARTED", "STATUS", "DURATION", "OUTPUT"], zebra=True)
    _pause()


def _sched_stats(mod: Any) -> None:
    UI.header("📊  Scheduler Statistics")
    stats  = mod.cmd_stats()
    status = mod.status()
    UI.kv_block([
        ("Scheduler",  "Running" if status.get("running") else "Stopped"),
        ("Tasks",      str(status.get("task_count", 0))),
        ("Active now", str(status.get("active", 0))),
    ])
    if stats:
        rows = []
        for s in stats:
            rows.append([
                s.get("name", ""),
                str(s.get("total_runs", 0)),
                str(s.get("successes", 0)),
                str(s.get("failures", 0)),
                f"{s.get('avg_duration_ms', 0):.0f} ms",
            ])
        UI.table(rows, ["TASK", "RUNS", "OK", "FAIL", "AVG TIME"], zebra=True)
    _pause()


def _sched_stop(mod: Any) -> None:
    if UI.confirm("Stop the scheduler background thread?"):
        mod.cmd_stop()
        UI.success("Scheduler stopped.")
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Plugin sub-menu
# ═══════════════════════════════════════════════════════════════════════════════

def _plugins_menu(plugin_registry: Any) -> None:
    """
    Interactive plugin browser.
    Lists discovered plugins, shows metadata, invokes on selection.
    """
    while True:
        _clear()
        UI.header("🧩  Plugins")

        plugins = plugin_registry.list()

        if not plugins:
            UI.info("No plugins discovered.")
            UI.info(f"Drop a .py file into  ~/.localos/plugins/  to add one.")
            _pause()
            return

        # Build menu items dynamically from discovered plugins
        items: List[Tuple[str, str, str]] = []
        for i, meta in enumerate(plugins, start=1):
            status = Ansi.green("✓") if meta.loaded else (
                Ansi.red("✗") if meta.load_error else Ansi.dim("○")
            )
            src = Ansi.dim("builtin") if meta.builtin else Ansi.cyan("user")
            label = f"{meta.name}  v{meta.version}  [{src}]  {status}"
            items.append((str(i), "🔌", label))

        items.append(("r", "🔄", "Rescan plugin directories"))
        items.append(("h", "🩺", "Plugin health check"))  # FIX: was "H", _get_choice() lowercases input
        items.append(("0", "←",  "Back"))

        UI.main_menu(items, title="Plugins — select to run  ·  [r] rescan  ·  [h] health")
        UI.separator()
        print()

        choice = _get_choice()
        if isinstance(choice, _Interrupted) or choice == "0":
            return

        if choice == "r":
            added, removed = plugin_registry.rescan()
            UI.success(f"Rescan complete — +{added} added, -{removed} removed.")
            time.sleep(1.0)
            continue

        if choice == "h":  # FIX: was "h" check but label was "H" — now consistent
            _plugins_health(plugin_registry, plugins)
            continue

        # Numeric selection
        try:
            idx = int(choice) - 1
        except ValueError:
            UI.warn(f"Unknown option: {choice!r}")
            time.sleep(0.5)
            continue

        if not (0 <= idx < len(plugins)):
            UI.warn("Out of range.")
            time.sleep(0.5)
            continue

        meta = plugins[idx]
        _run_plugin(plugin_registry, meta)


def _run_plugin(plugin_registry: Any, meta: Any) -> None:
    """Show plugin details and run it."""
    _clear()
    UI.header(f"🔌  {meta.name}")
    UI.kv_block([
        ("Version",     meta.version),
        ("Author",      meta.author),
        ("Description", meta.description),
        ("Tags",        ", ".join(meta.tags) or "—"),
        ("Source",      "built-in" if meta.builtin else "user plugin"),
        ("File",        str(meta.source_path)),
        ("Status",      "loaded" if meta.loaded else ("error" if meta.load_error else "not loaded")),
    ])

    if meta.load_error:
        UI.error("This plugin failed to load:")
        for line in meta.load_error.splitlines()[-6:]:
            print(Ansi.dim(f"  {line}"))
        UI.info("Fix the error above, then use [r] to reload.")
        _pause()
        return

    print()
    if not UI.confirm(f"Run  {meta.name!r}  now?"):
        return

    try:
        from plugins import PluginInvokeError, PluginLoadError
        plugin_registry.invoke(meta.name)
    except (PluginLoadError, PluginInvokeError) as exc:
        UI.error(f"Plugin error: {exc}")
        if os.environ.get("LOCAL_OS_DEBUG"):
            traceback.print_exc()
    except KeyboardInterrupt:
        UI.info("Plugin interrupted.")
    except Exception as exc:
        UI.error(f"Unexpected error: {exc}")
        if os.environ.get("LOCAL_OS_DEBUG"):
            traceback.print_exc()
    finally:
        _pause()


def _plugins_health(plugin_registry: Any, plugins: list) -> None:
    _clear()
    UI.header("🩺  Plugin Health Check")
    results = plugin_registry.health()
    rows = []
    for meta in plugins:
        status = results.get(meta.name, "not checked")
        if status is True:
            ok_str = Ansi.green("✔  ok")
        elif status == "not loaded":
            ok_str = Ansi.dim("○  not loaded")
        else:
            ok_str = Ansi.red(f"✘  {status}"[:50])
        rows.append([meta.name, meta.version, ok_str])
    UI.table(rows, ["PLUGIN", "VERSION", "HEALTH"], zebra=True)
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Input helper
# ═══════════════════════════════════════════════════════════════════════════════

def _get_choice(prompt: str = "choice") -> str | _Interrupted:
    ind    = getattr(Config, "UI_INDENT", "  ")
    glyph  = getattr(Config, "UI_PROMPT_GLYPH", "›")
    styled = Ansi.style(f"{ind}{glyph} ", "bold", "cyan")
    try:
        return input(styled).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return _Interrupted()


# ═══════════════════════════════════════════════════════════════════════════════
#  Exception handler for module errors
# ═══════════════════════════════════════════════════════════════════════════════

def _handle_module_exception(exc: Exception, context: str = "") -> None:
    UI.error(f"Unhandled error in {context!r}: {type(exc).__name__}: {exc}")
    if os.environ.get("LOCAL_OS_DEBUG", "").lower() in ("1", "true", "yes"):
        ind = getattr(Config, "UI_INDENT", "  ")
        tb  = traceback.format_exc()
        print(Ansi.dim(f"\n{ind}── Traceback ──"))
        for line in tb.splitlines():
            print(Ansi.dim(f"{ind}{line}"))
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Startup diagnostics
# ═══════════════════════════════════════════════════════════════════════════════

def _run_diagnostics(plugin_registry: Any = None) -> None:
    from modules import registry  # lazy import

    UI.header("🩺  Startup Diagnostics")

    # ── Module health ──────────────────────────────────────────────────────────
    UI.subheader("Modules")
    report = registry.health_report()
    rows   = []
    for item in report:
        ok_str      = Ansi.green("✔") if item["deps_ok"] else Ansi.red("✘")
        loaded_str  = Ansi.green("loaded") if item["loaded"] else Ansi.dim("lazy")
        failed_str  = Ansi.red("FAILED") if item["failed"] else ""
        missing_str = ", ".join(item["missing_req"]) if item["missing_req"] else "—"
        opt_str     = ", ".join(item["missing_opt"]) if item["missing_opt"] else "—"
        rows.append([
            item["key"],
            ok_str,
            loaded_str + (f" {failed_str}" if failed_str else ""),
            missing_str,
            opt_str,
        ])
    UI.table(
        rows,
        ["MODULE", "DEPS", "STATE", "MISSING (req)", "MISSING (opt)"],
        zebra=True,
    )

    # ── Plugin health ──────────────────────────────────────────────────────────
    if plugin_registry is not None:
        plugins = plugin_registry.list()
        if plugins:
            UI.subheader(f"Plugins  ({len(plugins)} discovered)")
            p_rows = []
            p_health = plugin_registry.health()
            for meta in plugins:
                st = p_health.get(meta.name, "—")
                ok = Ansi.green("✔") if st is True else Ansi.red("✘")
                p_rows.append([meta.name, meta.version,
                                "built-in" if meta.builtin else "user",
                                ok, str(st) if st is not True else "ok"])
            UI.table(p_rows, ["PLUGIN", "VER", "SOURCE", "OK", "DETAIL"],
                     zebra=True)

    # ── Runtime info ───────────────────────────────────────────────────────────
    UI.subheader("Runtime")
    UI.kv_block([
        ("Python",   sys.version.split()[0]),
        ("Platform", platform.platform()),
        ("OS",       platform.system()),
        ("Arch",     platform.machine()),
        ("PID",      str(os.getpid())),
    ])

    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Settings screen  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def _show_settings() -> None:
    while True:
        _clear()
        UI.header("⚙  Settings")
        UI.show_config()

        print()
        UI.main_menu([
            ("e", "✏", "Edit a config value"),
            ("s", "💾", "Save config to file"),
            ("r", "🔄", "Reload config from file"),
            ("0", "←", "Back"),
        ])

        choice = _get_choice()
        if isinstance(choice, _Interrupted) or choice == "0":
            return

        if choice == "e":
            _edit_config_value()
        elif choice == "s":
            Config.save()
            UI.success("Config saved.")
            time.sleep(0.8)
        elif choice == "r":
            Config.load()
            UI.success("Config reloaded.")
            time.sleep(0.8)


def _edit_config_value() -> None:
    key = UI.prompt("Config key (uppercase, e.g. NET_SCAN_TIMEOUT)").upper()
    if not key:
        return
    if not hasattr(Config, key):
        UI.error(f"Unknown config key: {key!r}")
        _pause()
        return
    current = getattr(Config, key)
    UI.info(f"Current value: {current!r}  (type: {type(current).__name__})")
    raw = UI.prompt("New value (Enter to cancel)")
    if not raw:
        return
    try:
        if isinstance(current, bool):
            new_val = raw.lower() in ("1", "true", "yes", "on")
        elif isinstance(current, int):
            new_val = int(raw)
        elif isinstance(current, float):
            new_val = float(raw)
        else:
            new_val = raw
        setattr(Config, key, new_val)
        UI.success(f"{key} → {new_val!r}")
    except (ValueError, TypeError) as e:
        UI.error(f"Invalid value: {e}")
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Help screen  — updated with new modules + plugins
# ═══════════════════════════════════════════════════════════════════════════════

_HELP_TEXT = """
  GLOBAL COMMANDS
  ───────────────
  [0]     ·  Return to main menu / exit sub-menu
  [q]     ·  Quit the application
  [h]     ·  Show this help
  [diag]  ·  Run module + plugin dependency diagnostics
  [set]   ·  Open settings panel
  [cls]   ·  Clear the screen
  [stat]  ·  Show session statistics

  NAVIGATION
  ──────────
  In any menu, type the number or letter shown in [brackets].
  Ctrl+C cancels the current action and returns one level up.
  Ctrl+D (EOF) is treated as 'quit'.

  MODULES
  ───────
  1  · System Information   —  OS, CPU, RAM, Disk, GPU, Battery
  2  · Process Manager      —  List, kill, renice, live monitor
  3  · Network Tools        —  Port scan, ping, DNS, whois, ARP
  4  · Crypto Tools         —  Hashing, encryption, RSA, HMAC
  5  · Password Vault       —  Fernet-encrypted secret store
  6  · File Tools           —  Duplicates, integrity, diff, rename
  7  · SQLite Shell         —  Interactive SQLite CLI
  8  · Task Scheduler       —  Background job runner with history
  9  · Docker Manager       —  Containers, images, logs, stats
  10 · Log Analyzer         —  /var/log/*, grep, filter, CSV export
  11 · Git Tools            —  Status, log, diff, stash, cherry-pick
  12 · Firewall             —  iptables/ufw, IP blocking, profiles
  p  · Plugins              —  Browse and run installed plugins

  PLUGINS
  ───────
  Drop any .py file with PLUGIN_NAME/PLUGIN_VERSION/main() into:
    ~/.localos/plugins/      ← personal plugins (never committed)
    <repo>/plugins/          ← project plugins
  Use [p] → [r] to rescan without restarting.
  Use LOCAL_OS_FIREWALL_DRY=1 to run Firewall in dry-run mode.

  ENVIRONMENT VARIABLES
  ─────────────────────
  LOCAL_OS_DEBUG=1               Show full tracebacks on errors
  LOCAL_OS_CONFIG=<path>         Override config file location
  LOCAL_OS_NET_THREADS=N         Port scanner thread count
  LOCAL_OS_PM_TOP_N=N            Default top-N processes
  LOCAL_OS_FIREWALL_DRY=1        Run Firewall in dry-run (preview) mode
"""


def _show_help() -> None:
    _clear()
    UI.header("❓  Help")
    UI.paginate(_HELP_TEXT.splitlines())
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Session stats screen  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def _show_session_stats(session: _Session) -> None:
    _clear()
    UI.header("📈  Session Statistics")
    UI.kv_block([
        ("Started at",   session.started_at.strftime("%Y-%m-%d %H:%M:%S")),
        ("Uptime",       session.uptime),
        ("Commands run", str(session.commands_run)),
        ("Errors",       str(session.errors)),
        ("Last module",  session.last_module or "—"),
        ("PID",          str(os.getpid())),
        ("Python",       sys.version.split()[0]),
    ])
    _pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  Main menu — updated with new modules + plugins entry
# ═══════════════════════════════════════════════════════════════════════════════

_MAIN_MENU_ITEMS: List[Tuple[str, str, str]] = [
    # ── original modules ──────────────────────────────────────────────────────
    ("1",  "🖥",  "System Information"),
    ("2",  "⚙",  "Process Manager"),
    ("3",  "🌐", "Network Tools"),
    ("4",  "🔐", "Crypto Tools"),
    ("5",  "🔑", "Password Vault"),
    ("6",  "📁", "File Tools"),
    ("7",  "🗄",  "SQLite Shell"),
    ("8",  "🕑", "Task Scheduler"),
    # ── new modules ───────────────────────────────────────────────────────────
    ("9",  "🐳", "Docker Manager"),
    ("10", "📋", "Log Analyzer"),
    ("11", "🌿", "Git Tools"),
    ("12", "🔥", "Firewall"),
    # ── plugins ───────────────────────────────────────────────────────────────
    ("p",  "🧩", "Plugins"),
]

_MODULE_KEY_MAP: Dict[str, str] = {
    "1":  "system_info",
    "2":  "process_manager",
    "3":  "network",
    "4":  "crypto",
    "5":  "vault",
    "6":  "file_tools",
    "7":  "sqlite_shell",
    "8":  "scheduler",
    "9":  "docker_manager",
    "10": "log_analyzer",
    "11": "git_tools",
    "12": "firewall",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Terminal — main orchestrator class
# ═══════════════════════════════════════════════════════════════════════════════

class Terminal:
    """
    Application controller.

    Instantiated once in main.py.  Call .run() to start the interactive loop.

    Internal flow
    ─────────────
    run()
      ├── _startup()          load config, print banner, check health
      ├── _main_loop()        read input → dispatch → repeat
      │    ├── _dispatch_module(key)   lazy-load + adapt each module
      │    ├── _dispatch_plugin()      open plugin browser
      │    └── _dispatch_global(cmd)  handle built-in commands
      └── _shutdown()         cleanup, print goodbye
    """

    def __init__(self) -> None:
        self._session:        _Session  = _Session()
        self._running:        bool      = False
        self._registry        = None    # modules registry, set in _startup
        self._plugin_registry = None    # plugins registry, set in _startup

    # ══════════════════════════════════════════════════════════════════════════
    #  Lifecycle
    # ══════════════════════════════════════════════════════════════════════════

    def run(self) -> None:
        """Public entry point. Called from main.py."""
        self._install_signal_handlers()
        try:
            self._startup()
            self._running = True
            self._main_loop()
        except SystemExit:
            pass
        except Exception as exc:
            print(f"\n[FATAL] Unhandled exception: {exc}", file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)
        finally:
            self._shutdown()

    def _startup(self) -> None:
        """Initialise config, import registries, display banner."""
        # 1. Load configuration
        Config.load()

        # 2. Show splash banner first so the screen is never blank
        UI.banner()

        # 3. Module registry — isolated so a broken modules/__init__ doesn't
        #    kill the whole session.
        try:
            from modules import registry as reg
            self._registry = reg
        except Exception as exc:
            UI.warn(f"Module registry failed to load: {exc}")
            if os.environ.get("LOCAL_OS_DEBUG"):
                traceback.print_exc()
            self._registry = None

        # 4. Plugin registry — equally isolated
        try:
            from plugins import PluginRegistry
            self._plugin_registry = PluginRegistry()
            n = len(self._plugin_registry)
            if n:
                UI.info(f"🧩  {n} plugin(s) discovered.")
        except Exception as exc:
            UI.warn(f"Plugin registry failed to load: {exc}")
            if os.environ.get("LOCAL_OS_DEBUG"):
                traceback.print_exc()
            self._plugin_registry = None

        # 5. Quick health summary (non-blocking, warn only)
        self._print_health_summary()

    def _main_loop(self) -> None:
        """Read input and dispatch until the user quits."""
        while self._running:
            self._render_main_menu()
            choice = _get_choice()

            if isinstance(choice, _Interrupted):
                if UI.confirm("Exit Local OS?"):
                    self._running = False
                continue

            if not choice:
                continue

            if self._dispatch_global(choice):
                continue

            # Plugin entry-point
            if choice == "p":
                if self._plugin_registry is not None:
                    self._session.record("plugins")
                    _plugins_menu(self._plugin_registry)
                else:
                    UI.warn("Plugin system not available.")
                    time.sleep(0.8)
                continue

            module_key = _MODULE_KEY_MAP.get(choice)
            if module_key:
                self._dispatch_module(module_key)
            else:
                UI.warn(f"Unknown command: {choice!r}  — type [h] for help.")
                time.sleep(0.5)

    def _shutdown(self) -> None:
        """Graceful teardown: stop background threads, print goodbye."""
        # FIX: self._registry is a module object, not a dict — use try/except
        # instead of `"scheduler" in self._registry` which raises TypeError.
        if self._registry is not None:
            try:
                desc = self._registry.get("scheduler")
                if desc.loaded:
                    inst = desc.get_instance()
                    if hasattr(inst, "cmd_stop"):
                        inst.cmd_stop()
            except Exception:
                pass

        # Unload all plugins cleanly
        if self._plugin_registry is not None:
            for meta in list(self._plugin_registry):
                if meta.loaded:
                    try:
                        self._plugin_registry.unload(meta.name)
                    except Exception:
                        pass

        _clear()
        ind = getattr(Config, "UI_INDENT", "  ")
        tw  = _term_width()
        print(Ansi.style("\n" + " " * len(ind) + "═" * (tw - len(ind) * 2), "dim"))
        print(Ansi.style(
            f"{ind}  Local OS — session ended  "
            f"· uptime {self._session.uptime} "
            f"· {self._session.commands_run} commands",
            "dim"
        ))
        print(Ansi.style(" " * len(ind) + "═" * (tw - len(ind) * 2) + "\n", "dim"))

    # ══════════════════════════════════════════════════════════════════════════
    #  Rendering
    # ══════════════════════════════════════════════════════════════════════════

    def _render_main_menu(self) -> None:
        _clear()
        UI.banner()

        ind = getattr(Config, "UI_INDENT", "  ")
        tw  = _term_width()

        # Status bar — top-right aligned
        plugin_count = (
            len(self._plugin_registry) if self._plugin_registry else 0
        )
        plugin_str = (
            f"  {Ansi.dim('plugins')} {Ansi.cyan(str(plugin_count))}"
            if plugin_count else ""
        )
        status = (
            f"{Ansi.dim('uptime')} {Ansi.cyan(self._session.uptime)}  "
            f"{Ansi.dim('cmds')} {Ansi.cyan(str(self._session.commands_run))}"
            f"{plugin_str}"
        )
        # FIX: import re moved to top of file — removed inline import here
        status_plain = re.sub(r"\033\[[0-9;]*m", "", status)
        pad = max(0, tw - len(ind) - len(status_plain))
        print(f"{ind}{' ' * pad}{status}")

        UI.main_menu(
            _MAIN_MENU_ITEMS,
            title=(
                "Select a module  ·  [p] plugins  ·  "
                "[h] help  ·  [diag] diagnostics  ·  [q] quit"
            ),
        )

        UI.separator()
        print()

    def _print_health_summary(self) -> None:
        if not self._registry:
            return
        report = self._registry.health_report()
        broken = [r for r in report if not r["deps_ok"]]
        if not broken:
            return
        UI.warn(f"{len(broken)} module(s) have missing dependencies:")
        for item in broken:
            pkg_list = ", ".join(item["missing_req"])
            UI.info(f"  {item['key']}: pip install {pkg_list}")
        print()
        time.sleep(1.5)

    # ══════════════════════════════════════════════════════════════════════════
    #  Dispatch — modules
    # ══════════════════════════════════════════════════════════════════════════

    def _dispatch_module(self, key: str) -> None:
        self._session.record(key)

        adapter = _ADAPTERS.get(key)
        if adapter is None:
            UI.error(f"No adapter registered for module {key!r}.")
            _pause()
            return

        try:
            from modules import registry
            desc     = registry.get(key)
            instance = desc.get_instance()
        except (ImportError, AttributeError, KeyError) as exc:
            UI.error(f"Failed to load module {key!r}: {exc}")
            self._session.record_error()
            _pause()
            return

        try:
            adapter(instance)
        except KeyboardInterrupt:
            UI.info("Returning to main menu…")
            time.sleep(0.3)
        except Exception as exc:
            self._session.record_error()
            _handle_module_exception(exc, context=key)

    # ══════════════════════════════════════════════════════════════════════════
    #  Dispatch — global commands
    # ══════════════════════════════════════════════════════════════════════════

    def _dispatch_global(self, choice: str) -> bool:
        if choice in ("q", "quit", "exit"):
            if UI.confirm("Exit Local OS?"):
                self._running = False
            return True

        if choice in ("h", "help", "?"):
            _show_help()
            return True

        if choice in ("diag", "d"):
            _run_diagnostics(self._plugin_registry)
            return True

        # FIX: removed "s" alias for settings — it conflicted with "stat"
        # and confused users expecting "s" to mean stats.
        if choice in ("set", "settings"):
            _show_settings()
            return True

        if choice in ("cls", "clear"):
            _clear()
            return True

        if choice in ("stat", "stats"):
            _show_session_stats(self._session)
            return True

        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  Signal handling  (unchanged)
    # ══════════════════════════════════════════════════════════════════════════

    def _install_signal_handlers(self) -> None:
        def _sigint_handler(sig: int, frame: Any) -> None:
            raise KeyboardInterrupt

        def _sigterm_handler(sig: int, frame: Any) -> None:
            self._running = False
            raise SystemExit(0)

        signal.signal(signal.SIGINT, _sigint_handler)

        if hasattr(signal, "SIGTERM"):
            try:
                signal.signal(signal.SIGTERM, _sigterm_handler)
            except (OSError, ValueError):
                pass