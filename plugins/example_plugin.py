"""
example_plugin.py — Template for local_os plugins
===================================================
Copy this file to one of:

  <repo>/plugins/my_plugin.py          ← ships with the project
  ~/.localos/plugins/my_plugin.py      ← personal / not committed

Rename it, fill in the metadata constants, implement `main()`,
and it will be auto-discovered by PluginRegistry on next startup
(or immediately after `registry.rescan()`).

This file is intentionally excluded from auto-discovery
(PluginRegistry skips files named "example_plugin").

──────────────────────────────────────────────────────────────
QUICK-START CHECKLIST
──────────────────────────────────────────────────────────────
 [x] 1. Copy & rename this file
 [ ] 2. Fill in PLUGIN_* constants below
 [ ] 3. Implement main()
 [ ] 4. Implement health_check() — return False if deps missing
 [ ] 5. (optional) Implement on_load() / on_unload()
 [ ] 6. (optional) Add unit tests in tests/plugins/
──────────────────────────────────────────────────────────────
"""

from __future__ import annotations

# ══════════════════════════════════════════════════════════════
#  REQUIRED — fill these in for every plugin
# ══════════════════════════════════════════════════════════════

PLUGIN_NAME        = "Example Plugin"        # shown in menus
PLUGIN_VERSION     = "1.0.0"                 # semver
PLUGIN_DESCRIPTION = "A template plugin — replace this text"
PLUGIN_AUTHOR      = "Your Name <you@example.com>"

# ── Optional metadata ─────────────────────────────────────────
# Tags are used for filtering: registry.list(tag="network")
PLUGIN_TAGS: list[str] = ["example", "template"]

# Minimum Python version this plugin supports
PLUGIN_MIN_PYTHON = (3, 10)

# ══════════════════════════════════════════════════════════════
#  MODULE-LEVEL IMPORTS
# ══════════════════════════════════════════════════════════════
# Keep this section LIGHT.
# - stdlib modules: fine here
# - heavy third-party (torch, PIL, pandas…): import inside main()
#   so startup stays fast even when the plugin is not invoked.

import sys
import logging

# Access other local_os modules like this:
# from core.config import Config
# from core.ui import UI, Ansi
# from data import PORTS, HTTP_STATUSES

logger = logging.getLogger(f"local_os.plugin.{PLUGIN_NAME}")

# ══════════════════════════════════════════════════════════════
#  LIFECYCLE HOOKS  (all optional)
# ══════════════════════════════════════════════════════════════

def on_load() -> None:
    """
    Called once by PluginRegistry immediately after import.

    Good for:
    - One-time setup (create dirs, init DB tables, warm caches)
    - Logging that the plugin is ready
    - Checking optional feature flags

    Must NOT block or raise — errors here are logged but don't
    prevent the plugin from being registered.
    """
    logger.debug("%s v%s loaded.", PLUGIN_NAME, PLUGIN_VERSION)
    # Example: create a data directory
    # from pathlib import Path
    # (Path.home() / ".localos" / "my_plugin").mkdir(parents=True, exist_ok=True)


def on_unload() -> None:
    """
    Called by PluginRegistry before the plugin is removed from
    sys.modules (e.g. on hot-reload or clean shutdown).

    Good for: flushing buffers, closing DB connections, saving state.
    """
    logger.debug("%s unloaded.", PLUGIN_NAME)


# ══════════════════════════════════════════════════════════════
#  HEALTH CHECK  (optional but strongly recommended)
# ══════════════════════════════════════════════════════════════

def health_check() -> bool:
    """
    Return True if all runtime dependencies are satisfied.
    Return False (or raise) if something is missing.

    Called by `registry.health()` and the startup health-check
    system.  Should be fast (< 100 ms) and side-effect free.

    Examples of things to check:
    - required third-party packages are importable
    - required binaries exist on PATH (shutil.which)
    - required config keys are set
    - required data files exist
    """
    # ── Example: check that 'requests' is importable ──────────
    # try:
    #     import requests  # noqa: F401
    # except ImportError:
    #     logger.warning("%s: 'requests' not installed.", PLUGIN_NAME)
    #     return False

    # ── Example: check that 'ffmpeg' is on PATH ───────────────
    # import shutil
    # if not shutil.which("ffmpeg"):
    #     logger.warning("%s: 'ffmpeg' not found in PATH.", PLUGIN_NAME)
    #     return False

    return True


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT  (required)
# ══════════════════════════════════════════════════════════════

def main() -> None:
    """
    Called by PluginRegistry.invoke("Example Plugin").
    This is where your interactive UI or logic lives.

    Patterns
    ────────
    A) Interactive menu loop (most common)

        while True:
            choice = input("  Choice: ").strip()
            if choice == "0":
                break
            handlers[choice]()

    B) One-shot command (no interaction needed)

        result = do_something()
        print(result)

    C) Rich UI using core helpers

        from core.ui import UI, Ansi
        UI.header("My Plugin")
        ...

    D) Heavy import inside main() so startup stays fast

        import pandas as pd        # imported only when invoked
        import torch               # same

    Tips
    ────
    - Use try/except for all I/O; never let main() crash the host
    - Print a short help message at the top of the menu
    - Honour Ctrl-C (KeyboardInterrupt) by catching it gracefully
    - Write to logger, not bare print(), for debug output
    """

    # ── Demo: a minimal interactive menu ──────────────────────
    _print_header()

    MENU = {
        "1": ("Say hello",   _cmd_hello),
        "2": ("Show info",   _cmd_info),
        "0": ("← Back",      None),
    }

    while True:
        print()
        for key, (label, _) in MENU.items():
            print(f"  [{key}]  {label}")
        print()

        try:
            choice = input("  Choice: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelled.")
            break

        if choice == "0":
            break

        handler_entry = MENU.get(choice)
        if not handler_entry:
            print("  ✗ Unknown choice.")
            continue

        _, fn = handler_entry
        if fn is None:
            break
        try:
            fn()
        except KeyboardInterrupt:
            print("\n  Cancelled.")
        except Exception as exc:
            logger.exception("Unhandled error in %s", PLUGIN_NAME)
            print(f"\n  ✗ Error: {exc}")


# ══════════════════════════════════════════════════════════════
#  PRIVATE HELPERS
# ══════════════════════════════════════════════════════════════
# Prefix private functions with _ so they don't pollute the
# module's public namespace and aren't mistaken for hooks.

def _print_header() -> None:
    """Print a simple banner.  Replace with UI.header() if available."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        Console().print(
            Panel(
                f"[bold]{PLUGIN_NAME}[/bold]  v{PLUGIN_VERSION}\n"
                f"[dim]{PLUGIN_DESCRIPTION}[/dim]",
                style="cyan",
            )
        )
    except ImportError:
        width = 60
        print(f"\n{'='*width}")
        print(f"  {PLUGIN_NAME}  v{PLUGIN_VERSION}")
        print(f"  {PLUGIN_DESCRIPTION}")
        print(f"{'='*width}")


def _cmd_hello() -> None:
    """Example command — replace or delete."""
    name = input("  Your name: ").strip() or "world"
    print(f"\n  Hello, {name}! 👋")
    print(f"  Running on Python {sys.version.split()[0]}")


def _cmd_info() -> None:
    """Show plugin metadata."""
    print(f"\n  Name:    {PLUGIN_NAME}")
    print(f"  Version: {PLUGIN_VERSION}")
    print(f"  Author:  {PLUGIN_AUTHOR}")
    print(f"  Tags:    {', '.join(PLUGIN_TAGS)}")
    print(f"  Healthy: {health_check()}")


# ══════════════════════════════════════════════════════════════
#  STANDALONE RUN  (for development / quick testing)
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Allows:  python plugins/example_plugin.py
    # without going through the full local_os menu system.
    logging.basicConfig(level=logging.DEBUG)
    on_load()
    main()
    on_unload()