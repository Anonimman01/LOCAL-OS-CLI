"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Modules Package                                      ║
║              modules/__init__.py                                             ║
║                                                                              ║
║  Responsibilities:                                                           ║
║    • Lazy-loading registry — модули импортируются только при обращении       ║
║    • Единый реестр всех модулей с метаданными                                ║
║    • Health-check: проверка зависимостей каждого модуля при старте           ║
║    • Wrapper-классы для модулей без единого класса (vault, file_tools)      ║
║    • Публичный API пакета — terminal.py работает только с этим файлом       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import importlib
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

__version__ = "1.0.0"
__author__  = "Local OS Project"
__all__     = ["ModuleRegistry", "ModuleDescriptor", "registry", "get_module"]


# ═══════════════════════════════════════════════════════════════════════════════
#  install-name → import-name for packages whose names differ
# ═══════════════════════════════════════════════════════════════════════════════

_INSTALL_TO_IMPORT: dict[str, str] = {
    "Pillow":          "PIL",
    "py-cpuinfo":      "cpuinfo",
    "python-dateutil": "dateutil",
    "pycryptodome":    "Crypto",
    "cryptography":    "cryptography",
    "GPUtil":          "GPUtil",
    "psutil":          "psutil",
    "prettytable":     "prettytable",
    "rich":            "rich",
    "dnspython":       "dns",
    "xxhash":          "xxhash",
    "schedule":        "schedule",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Wrapper classes for modules that expose run_*() functions, not a class
# ═══════════════════════════════════════════════════════════════════════════════

class _VaultWrapper:
    """Thin wrapper so terminal.py can treat vault like any other module."""
    def menu(self) -> None:
        from modules.vault import run_vault  # type: ignore
        run_vault()


class _FileToolsWrapper:
    """Thin wrapper so terminal.py can treat file_tools like any other module."""
    def menu(self) -> None:
        from modules.file_tools import run_file_tools  # type: ignore
        run_file_tools()


class _DockerWrapper:
    """Thin wrapper for docker_manager.py which exposes run()."""
    def menu(self) -> None:
        from modules.docker_manager import run  # type: ignore
        run()


class _LogAnalyzerWrapper:
    """Thin wrapper for log_analyzer.py which exposes run()."""
    def menu(self) -> None:
        from modules.log_analyzer import run  # type: ignore
        run()


class _GitToolsWrapper:
    """Thin wrapper for git_tools.py which exposes run()."""
    def menu(self) -> None:
        from modules.git_tools import run  # type: ignore
        run()


class _FirewallWrapper:
    """Thin wrapper for firewall.py which exposes run_interactive()."""
    def menu(self) -> None:
        import os
        from modules.firewall import FirewallManager, run_interactive  # type: ignore

        # Auto-detect root; fall back to dry-run if not privileged
        has_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        dry = (
            os.environ.get("LOCAL_OS_FIREWALL_DRY", "").lower() in ("1", "true")
            or not has_root
        )
        if dry and not has_root:
            print("\n  ⚠  Not running as root — starting in DRY-RUN mode (read-only preview).")
            print("     Run with: sudo python main.py  to apply real rules.\n")

        fw = FirewallManager(dry_run=dry)
        run_interactive(fw)


# ═══════════════════════════════════════════════════════════════════════════════
#  ModuleDescriptor
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ModuleDescriptor:
    """
    Metadata + lazy loader for a single Local OS module.

    Fields
    ──────
    key           : short identifier used in menus and routing
    label         : human-readable name shown in the main menu
    description   : one-line description
    module_path   : dotted import path — None when a wrapper_class is given
    class_name    : class inside that module to instantiate — None for wrappers
    wrapper_class : pre-built class to instantiate instead (vault, file_tools)
    icon          : emoji shown next to the menu label
    requires      : pip packages that must be importable
    optional_deps : packages that enrich functionality but aren't required
    """

    key:           str
    label:         str
    description:   str
    icon:          str                      = "🔧"
    module_path:   Optional[str]            = None
    class_name:    Optional[str]            = None
    wrapper_class: Optional[type]           = None
    requires:      list[str]                = field(default_factory=list)
    optional_deps: list[str]                = field(default_factory=list)

    # ── internal ──────────────────────────────────────────────────────────────
    _instance:   Optional[Any]              = field(default=None, repr=False, compare=False)
    _load_error: Optional[str]              = field(default=None, repr=False, compare=False)

    # ── dependency checks ─────────────────────────────────────────────────────

    def check_deps(self) -> tuple[bool, list[str]]:
        """Returns (all_ok, missing_required_list)."""
        missing = []
        for pkg in self.requires:
            import_name = _INSTALL_TO_IMPORT.get(pkg, pkg.replace("-", "_"))
            try:
                importlib.import_module(import_name)
            except ImportError:
                missing.append(pkg)
        return (len(missing) == 0), missing

    def check_optional(self) -> list[str]:
        """Returns list of missing optional packages (not fatal)."""
        missing = []
        for pkg in self.optional_deps:
            import_name = _INSTALL_TO_IMPORT.get(pkg, pkg.replace("-", "_"))
            try:
                importlib.import_module(import_name)
            except ImportError:
                missing.append(pkg)
        return missing

    # ── lazy instantiation ────────────────────────────────────────────────────

    def get_instance(self) -> Any:
        """
        Return a singleton instance of this module's main class.
        Supports three modes:
          1. wrapper_class  — instantiate the local wrapper directly
          2. module_path + class_name  — import and instantiate
          3. neither → raise
        """
        if self._instance is not None:
            return self._instance

        # Mode 1: local wrapper (vault, file_tools)
        if self.wrapper_class is not None:
            self._instance = self.wrapper_class()
            return self._instance

        # Mode 2: import from module file
        if not self.module_path or not self.class_name:
            raise ValueError(
                f"ModuleDescriptor '{self.key}' has neither wrapper_class "
                "nor module_path + class_name."
            )

        try:
            mod = importlib.import_module(self.module_path)
        except ImportError as exc:
            self._load_error = str(exc)
            pkgs = " ".join(self.requires) if self.requires else "(none required)"
            raise ImportError(
                f"Cannot load module '{self.key}': {exc}\n"
                f"  Required packages: pip install {pkgs}"
            ) from exc

        cls = getattr(mod, self.class_name, None)
        if cls is None:
            raise AttributeError(
                f"Module '{self.module_path}' has no class '{self.class_name}'."
            )

        self._instance = cls()
        return self._instance

    @property
    def loaded(self) -> bool:
        return self._instance is not None

    @property
    def failed(self) -> bool:
        return self._load_error is not None


# ═══════════════════════════════════════════════════════════════════════════════
#  ModuleRegistry
# ═══════════════════════════════════════════════════════════════════════════════

class ModuleRegistry:
    """Central registry of all Local OS modules."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleDescriptor] = {}

    def register(self, descriptor: ModuleDescriptor) -> None:
        if descriptor.key in self._modules:
            raise KeyError(f"Module key '{descriptor.key}' is already registered.")
        self._modules[descriptor.key] = descriptor

    def get(self, key: str) -> ModuleDescriptor:
        try:
            return self._modules[key]
        except KeyError:
            raise KeyError(f"No module registered with key '{key}'.")

    def all(self) -> list[ModuleDescriptor]:
        return list(self._modules.values())

    def keys(self) -> list[str]:
        return list(self._modules.keys())

    def health_report(self) -> list[dict]:
        report = []
        for desc in self.all():
            ok, missing_req = desc.check_deps()
            missing_opt     = desc.check_optional()
            report.append({
                "key":         desc.key,
                "label":       desc.label,
                "deps_ok":     ok,
                "missing_req": missing_req,
                "missing_opt": missing_opt,
                "loaded":      desc.loaded,
                "failed":      desc.failed,
                "error":       desc._load_error,
            })
        return report

    def __len__(self) -> int:
        return len(self._modules)

    def __contains__(self, key: str) -> bool:
        return key in self._modules

    def __repr__(self) -> str:
        return f"<ModuleRegistry modules={list(self._modules.keys())}>"


# ═══════════════════════════════════════════════════════════════════════════════
#  Module definitions — single source of truth
#  class_name values verified against actual module files:
#    system_info.py  → SystemInfo
#    process_manager.py → ProcessManager
#    network.py      → NetworkModule
#    crypto.py       → CryptoModule
#    vault.py        → no class → _VaultWrapper
#    file_tools.py   → no class → _FileToolsWrapper
#    sqlite_shell.py → SQLiteShell
#    scheduler.py    → SchedulerModule
# ═══════════════════════════════════════════════════════════════════════════════

registry = ModuleRegistry()

registry.register(ModuleDescriptor(
    key         = "system_info",
    label       = "System Information",
    description = "OS, CPU, RAM, Disk, GPU, Network, Battery, Temperatures",
    icon        = "🖥",
    module_path = "modules.system_info",
    class_name  = "SystemInfo",
    requires    = ["psutil"],
    optional_deps = ["GPUtil", "py-cpuinfo"],
))

registry.register(ModuleDescriptor(
    key         = "process_manager",
    label       = "Process Manager",
    description = "List, search, kill, renice, suspend, live monitor",
    icon        = "⚙",
    module_path = "modules.process_manager",
    class_name  = "ProcessManager",
    requires    = ["psutil"],
))

registry.register(ModuleDescriptor(
    key         = "network",
    label       = "Network Tools",
    description = "Port scanner, DNS lookup, ping, whois, traceroute",
    icon        = "🌐",
    module_path = "modules.network",
    class_name  = "NetworkModule",       # ← was incorrectly "NetworkTools"
    requires    = ["psutil"],
    optional_deps = ["dnspython"],
))

registry.register(ModuleDescriptor(
    key         = "crypto",
    label       = "Crypto Tools",
    description = "Hashing, encryption, RSA, HMAC, passwords, manifests",
    icon        = "🔐",
    module_path = "modules.crypto",
    class_name  = "CryptoModule",        # ← was incorrectly "CryptoTools"
    requires    = ["cryptography"],
))

registry.register(ModuleDescriptor(
    key           = "vault",
    label         = "Password Vault",
    description   = "Fernet-encrypted vault, PBKDF2 master key, TOTP, audit",
    icon          = "🔑",
    wrapper_class = _VaultWrapper,       # ← vault.py has no single class; uses run_vault()
    requires      = ["cryptography"],
))

registry.register(ModuleDescriptor(
    key           = "file_tools",
    label         = "File Tools",
    description   = "Duplicate finder, integrity checker, diff, bulk rename",
    icon          = "📁",
    wrapper_class = _FileToolsWrapper,   # ← file_tools.py uses run_file_tools()
    optional_deps = ["xxhash"],
))

registry.register(ModuleDescriptor(
    key         = "sqlite_shell",
    label       = "SQLite Shell",
    description = "Interactive SQLite CLI — query, browse, export",
    icon        = "🗄",
    module_path = "modules.sqlite_shell",
    class_name  = "SQLiteShell",
))

registry.register(ModuleDescriptor(
    key         = "scheduler",
    label       = "Task Scheduler",
    description = "Cron-like background job runner with history",
    icon        = "🕑",
    module_path = "modules.scheduler",
    class_name  = "SchedulerModule",     # ← was incorrectly "TaskScheduler"
    optional_deps = ["schedule"],
))


# ── New modules (9–12) ────────────────────────────────────────────────────────

registry.register(ModuleDescriptor(
    key           = "docker_manager",
    label         = "Docker Manager",
    description   = "Container and image management: start, stop, logs, stats",
    icon          = "🐳",
    wrapper_class = _DockerWrapper,
    optional_deps = ["docker"],
))

registry.register(ModuleDescriptor(
    key           = "log_analyzer",
    label         = "Log Analyzer",
    description   = "System log analysis: tail, filter, search, journald, export",
    icon          = "📋",
    wrapper_class = _LogAnalyzerWrapper,
))

registry.register(ModuleDescriptor(
    key           = "git_tools",
    label         = "Git Tools",
    description   = "Git repository management: log, diff, branches, stash, blame",
    icon          = "🌿",
    wrapper_class = _GitToolsWrapper,
))

registry.register(ModuleDescriptor(
    key           = "firewall",
    label         = "Firewall",
    description   = "iptables/ufw rules, IP blocking, profiles, audit, export",
    icon          = "🔥",
    wrapper_class = _FirewallWrapper,
))


# ═══════════════════════════════════════════════════════════════════════════════
#  Convenience accessor
# ═══════════════════════════════════════════════════════════════════════════════

def get_module(key: str) -> Any:
    """
    Shorthand: key → descriptor → lazy-load → instance.

        from modules import get_module
        get_module("system_info").menu()
    """
    return registry.get(key).get_instance()