"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Core Package                                         ║
║              core/__init__.py                                                ║
║                                                                              ║
║  Single import surface for the core layer.                                  ║
║  Exports Config, Ansi, UI and ui helpers.                                   ║
║  Terminal is intentionally NOT exported here — it must be imported          ║
║  directly from core.terminal to avoid circular imports at package load.     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

# ── 1. Config (no deps — must come first) ─────────────────────────────────────
from core.config import Config

# ── 2. UI primitives (depends on Config) ──────────────────────────────────────
from core.ui import (
    Ansi,
    UI,
    _term_width,
    _clear,
    _pause,
)

# ── NOTE: Terminal is NOT imported here. ──────────────────────────────────────
# core.terminal imports from core.config and core.ui at module level.
# Importing it inside core/__init__.py creates a circular import chain:
#   core/__init__ → core.terminal → core.config → (already loading) → boom
# Correct usage in main.py:
#   from core.terminal import Terminal

__version__: str = "1.0.0"
__author__:  str = "Local OS Project"

__all__: list[str] = [
    "Config",
    "Ansi",
    "UI",
    "_term_width",
    "_clear",
    "_pause",
]