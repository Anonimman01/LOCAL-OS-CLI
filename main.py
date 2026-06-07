"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Entry Point                                          ║
║              main.py                                                         ║
║                                                                              ║
║  Responsibilities:                                                           ║
║    • Python version guard (≥ 3.10)                                          ║
║    • sys.path bootstrap — makes the project root importable from anywhere   ║
║    • CLI argument parsing (--version, --debug, --no-color, --config)        ║
║    • Environment variable injection before any core import                  ║
║    • Instantiate Terminal and hand off control                               ║
║    • Top-level exception handler — human-readable crash report              ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage
─────
    python main.py                        # normal start
    python main.py --version              # print version and exit
    python main.py --debug                # show full tracebacks on errors
    python main.py --no-color             # disable ANSI colour output
    python main.py --config PATH          # override config file location
    python main.py --module system_info   # jump directly to a module
"""

from __future__ import annotations

import os
import sys

# ── Python version guard — must run before any other import ───────────────────
if sys.version_info < (3, 10):
    sys.exit(
        f"Local OS requires Python 3.10 or newer.\n"
        f"Current version: {sys.version}\n"
        f"Upgrade at: https://python.org/downloads/"
    )

# ── sys.path bootstrap ────────────────────────────────────────────────────────
# Ensure the project root is always on sys.path regardless of how main.py is
# launched (python main.py / python local_os/main.py / python -m local_os).
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# ── stdlib-only imports (safe before core/) ───────────────────────────────────
import argparse
import traceback


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI argument parser
# ═══════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "local_os",
        description = "Local OS — System Administration Toolkit",
        epilog      = "Environment variables: LOCAL_OS_DEBUG, LOCAL_OS_CONFIG",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", "-v",
        action  = "store_true",
        help    = "Print version and exit",
    )
    parser.add_argument(
        "--debug", "-d",
        action  = "store_true",
        help    = "Enable full tracebacks on errors (sets LOCAL_OS_DEBUG=1)",
    )
    parser.add_argument(
        "--no-color",
        action  = "store_true",
        help    = "Disable ANSI colour output",
    )
    parser.add_argument(
        "--config", "-c",
        metavar = "PATH",
        help    = "Path to JSON config file (overrides ~/.localos/config.json)",
    )
    parser.add_argument(
        "--module", "-m",
        metavar = "KEY",
        help    = (
            "Jump directly to a module on startup. "
            "Keys: system_info, process_manager, network, crypto, "
            "vault, file_tools, sqlite_shell, scheduler"
        ),
    )
    return parser


# ═══════════════════════════════════════════════════════════════════════════════
#  Environment injection
#  Must happen before core/ is imported so Config picks up the values.
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_args_to_env(args: argparse.Namespace) -> None:
    if args.debug:
        os.environ["LOCAL_OS_DEBUG"] = "1"
    if args.no_color:
        os.environ["LOCAL_OS_NO_COLOR"] = "1"
    if args.config:
        os.environ["LOCAL_OS_CONFIG"] = args.config


# ═══════════════════════════════════════════════════════════════════════════════
#  Version printer
# ═══════════════════════════════════════════════════════════════════════════════

def _print_version() -> None:
    try:
        from core.config import Config
        name    = Config.APP_NAME
        version = Config.APP_VERSION
        author  = Config.APP_AUTHOR
    except Exception:
        name, version, author = "Local OS", "1.0.0", "Local OS Project"

    print(f"{name} v{version}")
    print(f"Author  : {author}")
    print(f"Python  : {sys.version.split()[0]}")
    print(f"Platform: {sys.platform}")


# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.version:
        _print_version()
        sys.exit(0)

    # Inject env-vars BEFORE any core import so Config picks them up
    _apply_args_to_env(args)

    # ── Import core.terminal directly — NOT via core package ──────────────────
    # core/__init__.py intentionally does NOT export Terminal to avoid the
    # circular import chain:
    #   core/__init__ → core.terminal → core.config → core (already loading)
    from core.terminal import Terminal

    # ── --no-color: patch Config after it is loaded ───────────────────────────
    if args.no_color:
        from core.config import Config
        Config.ANSI_ENABLED = False

    # ── --module: jump directly to one module, skip main menu ─────────────────
    if args.module:
        from core.config import Config
        Config.load()
        from core.ui import UI
        UI.banner()
        try:
            from modules import get_module
            from core.terminal import _ADAPTERS
            instance = get_module(args.module)
            adapter  = _ADAPTERS.get(args.module)
            if adapter:
                adapter(instance)
            else:
                UI.error(f"No adapter for module: {args.module!r}")
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            UI.error(f"{type(exc).__name__}: {exc}")
            if os.environ.get("LOCAL_OS_DEBUG"):
                traceback.print_exc()
        sys.exit(0)

    # ── Normal startup ────────────────────────────────────────────────────────
    try:
        terminal = Terminal()
        terminal.run()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    except Exception as exc:
        print(f"\n[FATAL] {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.environ.get("LOCAL_OS_DEBUG"):
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()