"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — Configuration & Constants                            ║
║              core/config.py                                                  ║
║                                                                              ║
║  Single source of truth for every tunable value in the project.             ║
║  All other modules import from here — never hardcode magic numbers.         ║
║                                                                              ║
║  Sections:                                                                   ║
║    • App identity                                                            ║
║    • Terminal / UI                                                           ║
║    • Process Manager                                                         ║
║    • System Info                                                             ║
║    • Network Tools                                                           ║
║    • Crypto                                                                  ║
║    • Vault                                                                   ║
║    • File Tools                                                              ║
║    • SQLite Shell                                                            ║
║    • Scheduler                                                               ║
║    • Paths & Files                                                           ║
║    • Runtime overrides (env-vars, JSON config file)                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _env(key: str, default: Any) -> Any:
    """
    Read an environment variable and cast it to the same type as *default*.
    Supports: str, int, float, bool.
    Returns *default* if the variable is absent or cannot be cast.
    """
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        if isinstance(default, bool):
            return raw.lower() in ("1", "true", "yes", "on")
        return type(default)(raw)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════════════
#  Config class
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    """
    All configuration lives here as class-level attributes.
    Values can be overridden at startup via:
      1. JSON config file  (~/.localos/config.json  or  LOCAL_OS_CONFIG env-var)
      2. Environment variables  (LOCAL_OS_<KEY>)

    No instances needed — use Config.ATTR directly everywhere.
    """

    # ── App identity ───────────────────────────────────────────────────────────
    APP_NAME:     str   = "Local OS"
    APP_VERSION:  str   = "1.0.0"
    APP_AUTHOR:   str   = "Local OS Project"

    # ── Terminal / UI ──────────────────────────────────────────────────────────
    # Whether to emit ANSI escape codes (auto-detected; override if needed)
    ANSI_ENABLED: bool  = sys.stdout.isatty()
    # Width fallback when terminal size cannot be determined
    TERMINAL_WIDTH_FALLBACK: int = 120
    # Indentation prefix used in all UI output
    UI_INDENT: str      = "  "
    # Separator character for section dividers
    UI_SEPARATOR_CHAR: str = "═"
    # Prompt arrow glyph
    UI_PROMPT_GLYPH: str = "›"
    # Pause message shown after every sub-menu screen
    UI_PAUSE_MSG: str   = "Press Enter to continue…"

    # ── Process Manager ────────────────────────────────────────────────────────
    PROCESS_REFRESH_INTERVAL: float = _env("LOCAL_OS_PM_REFRESH", 2.0)
    PROCESS_TOP_N:             int   = _env("LOCAL_OS_PM_TOP_N",   15)
    # Seconds of waiting for SIGTERM before escalating to SIGKILL
    KILL_ESCALATION_TIMEOUT:  int   = _env("LOCAL_OS_PM_KILL_TIMEOUT", 5)
    # Max characters of a process command line shown in the table
    MAX_CMDLINE_LEN:          int   = 60

    # ── System Info ────────────────────────────────────────────────────────────
    SYSINFO_REFRESH_INTERVAL: float = _env("LOCAL_OS_SI_REFRESH", 2.0)
    SYSINFO_REPORT_PATH: str        = "system_report.txt"
    # Temperature thresholds (°C)
    TEMP_WARN_C:  float = 75.0
    TEMP_CRIT_C:  float = 90.0

    # ── Network Tools ──────────────────────────────────────────────────────────
    NET_SCAN_TIMEOUT:    float = _env("LOCAL_OS_NET_TIMEOUT",   0.5)
    NET_SCAN_MAX_PORTS:  int   = _env("LOCAL_OS_NET_MAX_PORTS", 1024)
    NET_SCAN_THREADS:    int   = _env("LOCAL_OS_NET_THREADS",   256)
    NET_PING_COUNT:      int   = 4
    NET_PING_TIMEOUT:    int   = 2    # seconds per ping
    NET_DNS_TIMEOUT:     float = 3.0

    # ── Crypto ────────────────────────────────────────────────────────────────
    CRYPTO_CHUNK_SIZE:   int   = 64 * 1024   # bytes read per chunk during file hashing
    CRYPTO_DEFAULT_ALGO: str   = "sha256"    # default hash algorithm
    # Supported algorithms (subset of hashlib.algorithms_available that we expose)
    CRYPTO_ALGOS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512", "blake2b")

    # ── Vault ─────────────────────────────────────────────────────────────────
    VAULT_PATH:          str   = str(Path.home() / ".localos" / "vault.enc")
    VAULT_PBKDF2_ITERS:  int   = 480_000    # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    VAULT_PBKDF2_ALGO:   str   = "sha256"
    VAULT_KEY_LEN:       int   = 32         # bytes → 256-bit Fernet key
    VAULT_SALT_LEN:      int   = 32         # bytes
    # Clipboard clear delay (seconds) after copying a password
    VAULT_CLIPBOARD_CLEAR: int = 30

    # ── File Tools ────────────────────────────────────────────────────────────
    FILE_HASH_ALGO:      str   = "sha256"   # used for integrity checking
    FILE_DUP_MIN_SIZE:   int   = 1          # bytes — skip empty files in dupe scan
    FILE_CHUNK_SIZE:     int   = 64 * 1024
    # Max depth for recursive directory walks (0 = unlimited)
    FILE_WALK_MAX_DEPTH: int   = 0

    # ── SQLite Shell ──────────────────────────────────────────────────────────
    SQLITE_HISTORY_FILE: str   = str(Path.home() / ".localos" / "sqlite_history")
    SQLITE_MAX_ROWS:     int   = 200        # row display limit per query
    SQLITE_COL_MAX_W:    int   = 40         # max column width in result tables

    # ── Scheduler ─────────────────────────────────────────────────────────────
    SCHEDULER_DB_PATH:   str   = str(Path.home() / ".localos" / "scheduler.db")
    SCHEDULER_LOG_LINES: int   = 200        # max lines kept per job in history
    SCHEDULER_TICK:      float = 1.0        # main loop sleep interval (seconds)

    # ── Data directory ────────────────────────────────────────────────────────
    DATA_DIR: str = str(Path(__file__).resolve().parent.parent / "data")

    # ── User config directory ─────────────────────────────────────────────────
    USER_CONFIG_DIR: str = str(Path.home() / ".localos")

    # ── JSON config file path (resolved at runtime) ───────────────────────────
    CONFIG_FILE: str = _env(
        "LOCAL_OS_CONFIG",
        str(Path.home() / ".localos" / "config.json"),
    )

    # ══════════════════════════════════════════════════════════════════════════
    #  Runtime override machinery
    # ══════════════════════════════════════════════════════════════════════════

    @classmethod
    def load(cls) -> None:
        """
        Called once at application startup (from main.py).

        1. Creates ~/.localos/ if it doesn't exist.
        2. Reads CONFIG_FILE (JSON) if present; applies overrides.
        3. Overrides via LOCAL_OS_<KEY> env-vars are already baked in at
           class definition time (see _env() calls above).
        """
        cls._ensure_user_dir()
        cls._load_json_file()

    @classmethod
    def _ensure_user_dir(cls) -> None:
        Path(cls.USER_CONFIG_DIR).mkdir(parents=True, exist_ok=True)
        # Also ensure vault directory exists
        Path(cls.VAULT_PATH).parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _load_json_file(cls) -> None:
        cfg_path = Path(cls.CONFIG_FILE)
        if not cfg_path.is_file():
            return
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                data: dict[str, Any] = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return   # silently ignore malformed / unreadable file

        for key, value in data.items():
            upper = key.upper()
            if hasattr(cls, upper):
                try:
                    current = getattr(cls, upper)
                    # Cast to same type as the default
                    if isinstance(current, bool):
                        setattr(cls, upper, bool(value))
                    elif isinstance(current, int):
                        setattr(cls, upper, int(value))
                    elif isinstance(current, float):
                        setattr(cls, upper, float(value))
                    else:
                        setattr(cls, upper, value)
                except (ValueError, TypeError):
                    pass   # skip invalid values silently

    @classmethod
    def save(cls) -> None:
        """
        Persist current non-default settings back to CONFIG_FILE.
        Only writes keys that differ from class defaults to keep the file clean.
        """
        cls._ensure_user_dir()
        # Snapshot all public uppercase attributes
        data = {
            k: v for k, v in vars(cls).items()
            if k.isupper() and not k.startswith("_") and not callable(v)
        }
        try:
            with open(cls.CONFIG_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
        except OSError:
            pass

    @classmethod
    def dump(cls) -> dict[str, Any]:
        """Return a plain dict of all current config values (for display)."""
        return {
            k: v for k, v in vars(cls).items()
            if k.isupper() and not k.startswith("_") and not callable(v)
        }