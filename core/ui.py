"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — User Interface Layer                                 ║
║              core/ui.py                                                      ║
║                                                                              ║
║  ALL terminal output in the project goes through this file.                 ║
║  No module ever calls print() for user-facing content directly.             ║
║                                                                              ║
║  Sections:                                                                   ║
║    • ANSI colour / style engine                                              ║
║    • Primitive output (header, info, success, warn, error, prompt)          ║
║    • Table renderer (auto-fit columns, colour rows, pagination)             ║
║    • Progress bar                                                            ║
║    • Spinner (blocking + threaded)                                           ║
║    • Boxed panels                                                            ║
║    • Key-value block renderer                                                ║
║    • Paginator for long text                                                 ║
║    • Main menu renderer                                                      ║
║    • Startup banner                                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import time
import threading
import itertools
from typing import Any, Callable, Iterator, Optional, Sequence

try:
    from core.config import Config
except ImportError:
    class Config:  # type: ignore
        ANSI_ENABLED:          bool = sys.stdout.isatty()
        TERMINAL_WIDTH_FALLBACK: int = 120
        UI_INDENT:             str  = "  "
        UI_SEPARATOR_CHAR:     str  = "═"
        UI_PROMPT_GLYPH:       str  = "›"
        UI_PAUSE_MSG:          str  = "Press Enter to continue…"
        APP_NAME:              str  = "Local OS"
        APP_VERSION:           str  = "1.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI engine
# ═══════════════════════════════════════════════════════════════════════════════

class Ansi:
    """
    Centralised ANSI escape code factory.
    All colour / style logic lives here — the rest of ui.py calls Ansi methods.
    When Config.ANSI_ENABLED is False every method returns the plain text unchanged.
    """

    # 256-colour palette indices used throughout the UI
    PALETTE = {
        # Foreground
        "reset":     "\033[0m",
        "bold":      "\033[1m",
        "dim":       "\033[2m",
        "italic":    "\033[3m",
        "underline": "\033[4m",
        "blink":     "\033[5m",
        "reverse":   "\033[7m",
        "strike":    "\033[9m",
        # Standard colours
        "black":     "\033[30m",
        "red":       "\033[91m",
        "green":     "\033[92m",
        "yellow":    "\033[93m",
        "blue":      "\033[94m",
        "magenta":   "\033[95m",
        "cyan":      "\033[96m",
        "white":     "\033[97m",
        "grey":      "\033[90m",
        # Background
        "bg_red":    "\033[41m",
        "bg_green":  "\033[42m",
        "bg_yellow": "\033[43m",
        "bg_blue":   "\033[44m",
        "bg_cyan":   "\033[46m",
        "bg_black":  "\033[40m",
    }

    @classmethod
    def _enabled(cls) -> bool:
        return getattr(Config, "ANSI_ENABLED", True)

    @classmethod
    def wrap(cls, code: str, text: str) -> str:
        if not cls._enabled():
            return text
        return f"{code}{text}{cls.PALETTE['reset']}"

    @classmethod
    def style(cls, text: str, *codes: str) -> str:
        """Apply multiple named styles from PALETTE."""
        if not cls._enabled():
            return text
        prefix = "".join(cls.PALETTE.get(c, "") for c in codes)
        return f"{prefix}{text}{cls.PALETTE['reset']}"

    @classmethod
    def strip(cls, text: str) -> str:
        """Remove all ANSI escape sequences from *text*."""
        import re
        return re.sub(r"\033\[[0-9;]*m", "", text)

    # ── Convenience shorthands ─────────────────────────────────────────────────

    @classmethod
    def bold(cls, t: str)    -> str: return cls.style(t, "bold")
    @classmethod
    def dim(cls, t: str)     -> str: return cls.style(t, "dim")
    @classmethod
    def red(cls, t: str)     -> str: return cls.style(t, "red")
    @classmethod
    def green(cls, t: str)   -> str: return cls.style(t, "green")
    @classmethod
    def yellow(cls, t: str)  -> str: return cls.style(t, "yellow")
    @classmethod
    def cyan(cls, t: str)    -> str: return cls.style(t, "cyan")
    @classmethod
    def blue(cls, t: str)    -> str: return cls.style(t, "blue")
    @classmethod
    def magenta(cls, t: str) -> str: return cls.style(t, "magenta")
    @classmethod
    def grey(cls, t: str)    -> str: return cls.style(t, "grey")

    # ── String constants for modules that use Ansi.COLOUR directly ────────────
    RESET         = "\033[0m"
    BOLD          = "\033[1m"
    DIM           = "\033[2m"
    ITALIC        = "\033[3m"
    UNDERLINE     = "\033[4m"
    BLACK         = "\033[30m"
    RED           = "\033[91m"
    GREEN         = "\033[92m"
    YELLOW        = "\033[93m"
    BLUE          = "\033[94m"
    MAGENTA       = "\033[95m"
    CYAN          = "\033[96m"
    WHITE         = "\033[97m"
    GREY          = "\033[90m"
    BRIGHT_RED    = "\033[91m"
    BRIGHT_GREEN  = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE   = "\033[94m"
    BRIGHT_CYAN   = "\033[96m"
    BRIGHT_WHITE  = "\033[97m"
    BG_BLACK      = "\033[40m"
    BG_RED        = "\033[41m"
    BG_GREEN      = "\033[42m"
    BG_YELLOW     = "\033[43m"
    BG_BLUE       = "\033[44m"
    BG_CYAN       = "\033[46m"

    @classmethod
    def pct_colour(cls, pct: float, text: str | None = None) -> str:
        """Colour a percentage string green/yellow/red by value."""
        colour = "green" if pct < 60 else "yellow" if pct < 85 else "red"
        label  = text if text is not None else f"{pct:.1f}%"
        return cls.style(label, colour)

    @classmethod
    def pct_bar(cls, pct: float, width: int = 24) -> str:
        """Render a coloured block progress bar."""
        filled = int(pct / 100 * width)
        colour = "green" if pct < 60 else "yellow" if pct < 85 else "red"
        bar    = "█" * filled + "░" * (width - filled)
        return cls.style(bar, colour)


# ═══════════════════════════════════════════════════════════════════════════════
#  Terminal geometry
# ═══════════════════════════════════════════════════════════════════════════════

def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return getattr(Config, "TERMINAL_WIDTH_FALLBACK", 120)

def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def _pause() -> None:
    msg = getattr(Config, "UI_PAUSE_MSG", "Press Enter to continue…")
    ind = getattr(Config, "UI_INDENT", "  ")
    input(Ansi.dim(f"\n{ind}{msg}"))


# ═══════════════════════════════════════════════════════════════════════════════
#  Core UI class  —  the single import for every module
# ═══════════════════════════════════════════════════════════════════════════════

class UI:
    """
    Stateless collection of display primitives.
    Every method is a @staticmethod — no instantiation needed.

    All output respects:
      • Config.ANSI_ENABLED     — strip colours when False
      • Config.UI_INDENT        — consistent left-margin
      • Config.TERMINAL_WIDTH_FALLBACK — fallback when tty not available
    """

    _IND = property(lambda self: getattr(Config, "UI_INDENT", "  "))

    # ══════════════════════════════════════════════════════════════════════════
    #  Section headers
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def header(title: str) -> None:
        """Full-width double-line header with centred title."""
        ind  = getattr(Config, "UI_INDENT", "  ")
        sep  = getattr(Config, "UI_SEPARATOR_CHAR", "═")
        w    = _term_width() - len(ind)
        line = sep * w
        print(f"\n{ind}{Ansi.bold(line)}")
        print(f"{ind}{Ansi.style(f'  {title}', 'bold', 'cyan')}")
        print(f"{ind}{Ansi.bold(line)}\n")

    @staticmethod
    def subheader(title: str) -> None:
        """Lighter section break — single line, dimmed."""
        ind = getattr(Config, "UI_INDENT", "  ")
        w   = _term_width() - len(ind)
        print(f"\n{ind}{Ansi.bold(title)}")
        print(f"{ind}{Ansi.dim('─' * min(len(title) + 4, w))}")

    @staticmethod
    def section(title: str) -> None:
        """Inline section marker — box-drawing left bracket."""
        ind = getattr(Config, "UI_INDENT", "  ")
        w   = _term_width() - len(ind) - len(title) - 8
        print(f"\n{ind}{Ansi.bold(f'╔══ {title} ' + '═' * max(0, w) + '╗')}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Status messages
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def success(msg: str) -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.green('✔')}  {msg}")

    @staticmethod
    def error(msg: str) -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.red('✘')}  {Ansi.red(msg)}", file=sys.stderr)

    @staticmethod
    def warn(msg: str) -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.yellow('⚠')}  {Ansi.yellow(msg)}")

    @staticmethod
    def info(msg: str) -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.cyan('ℹ')}  {msg}")

    @staticmethod
    def dim(msg: str) -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.dim(msg)}")

    @staticmethod
    def blank() -> None:
        print()

    # ══════════════════════════════════════════════════════════════════════════
    #  Input
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def prompt(label: str, *, default: str = "") -> str:
        """
        Read a line from stdin.  Shows *default* in brackets if provided.
        Always returns a stripped string (never None).
        """
        ind    = getattr(Config, "UI_INDENT", "  ")
        glyph  = getattr(Config, "UI_PROMPT_GLYPH", "›")
        suffix = f" [{Ansi.dim(default)}]" if default else ""
        try:
            result = input(f"{ind}{Ansi.cyan(glyph)} {label}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        return result if result else default

    @staticmethod
    def confirm(label: str, *, default: bool = False) -> bool:
        """Yes/No prompt. Returns bool."""
        ind   = getattr(Config, "UI_INDENT", "  ")
        glyph = getattr(Config, "UI_PROMPT_GLYPH", "›")
        opts  = Ansi.dim("[Y/n]") if default else Ansi.dim("[y/N]")
        try:
            raw = input(f"{ind}{Ansi.cyan(glyph)} {label} {opts}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        return raw in ("y", "yes")

    @staticmethod
    def prompt_int(
        label: str,
        *,
        min_val: int | None = None,
        max_val: int | None = None,
        default: int | None = None,
    ) -> int | None:
        """Prompt for an integer with optional range validation."""
        while True:
            raw = UI.prompt(label, default=str(default) if default is not None else "")
            if not raw:
                return default
            if not raw.lstrip("-").isdigit():
                UI.warn("Please enter a valid integer.")
                continue
            val = int(raw)
            if min_val is not None and val < min_val:
                UI.warn(f"Value must be ≥ {min_val}.")
                continue
            if max_val is not None and val > max_val:
                UI.warn(f"Value must be ≤ {max_val}.")
                continue
            return val

    @staticmethod
    def choose(
        options: list[str],
        *,
        label: str = "Choose",
        allow_empty: bool = False,
    ) -> int | None:
        """
        Numbered choice menu for a flat list of strings.
        Returns 0-based index of selection, or None if aborted.
        """
        ind = getattr(Config, "UI_INDENT", "  ")
        for i, opt in enumerate(options, 1):
            print(f"{ind}  {Ansi.cyan(f'[{i}]')}  {opt}")
        print()
        raw = UI.prompt(f"{label} (1-{len(options)}, 0=cancel)")
        if not raw.isdigit():
            return None
        idx = int(raw)
        if idx == 0:
            return None
        if not (1 <= idx <= len(options)):
            UI.warn("Out of range.")
            return None
        return idx - 1

    # ══════════════════════════════════════════════════════════════════════════
    #  Table renderer
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def table(
        rows:    list[list[Any]],
        headers: list[str],
        *,
        max_col_width: int = 40,
        zebra:    bool = True,
        caption:  str  = "",
    ) -> None:
        """
        Auto-fit column-width table with optional zebra striping.

        Parameters
        ──────────
        rows          : list of rows; each row is a list of cell values
        headers       : column header strings
        max_col_width : hard cap per column (truncated with …)
        zebra         : dim every other row for readability
        caption       : printed below the table if non-empty
        """
        if not rows:
            UI.dim("(no data)")
            return

        ind  = getattr(Config, "UI_INDENT", "  ")
        tw   = _term_width() - len(ind) * 2

        # Stringify all cells; truncate to max_col_width
        def _cell(v: Any) -> str:
            s = Ansi.strip(str(v))
            return s if len(s) <= max_col_width else s[: max_col_width - 1] + "…"

        str_rows = [[_cell(c) for c in row] for row in rows]
        n_cols   = len(headers)

        # Column widths: max of header vs cell content
        col_w = [
            min(max(len(headers[i]), max(len(r[i]) for r in str_rows)), max_col_width)
            for i in range(n_cols)
        ]

        # Shrink if total width exceeds terminal
        total = sum(col_w) + (n_cols - 1) * 3   # 3 = " │ "
        if total > tw and n_cols > 1:
            excess = total - tw
            # Shrink widest columns first
            for _ in range(excess):
                widest = col_w.index(max(col_w))
                if col_w[widest] > 4:
                    col_w[widest] -= 1

        sep_row = "─┼─".join("─" * w for w in col_w)
        fmt     = " │ ".join(f"{{:<{w}}}" for w in col_w)

        # Header
        header_cells = [h[:col_w[i]].ljust(col_w[i]) for i, h in enumerate(headers)]
        print(f"{ind}{Ansi.bold(fmt.format(*header_cells))}")
        print(f"{ind}{Ansi.dim(sep_row)}")

        # Rows — preserve original ANSI in display but measure stripped width
        for idx, (original_row, str_row) in enumerate(zip(rows, str_rows)):
            cells = []
            for i, (orig, stripped) in enumerate(zip(original_row, str_row)):
                orig_s = str(orig)
                # Pad based on stripped length, but output original (with colour)
                pad    = " " * max(0, col_w[i] - len(stripped))
                cells.append(orig_s + pad)
            line = f" │ ".join(cells)
            if zebra and idx % 2 == 1:
                line = Ansi.dim(line)
            print(f"{ind}{line}")

        if caption:
            print(f"{ind}{Ansi.dim(caption)}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Key-value block
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def kv_block(
        pairs:   list[tuple[str, str]],
        *,
        label_w: int  = 22,
        indent:  str  = "",
    ) -> None:
        """
        Render a list of (label, value) pairs aligned on the colon.

        Example
        ───────
        UI.kv_block([("Hostname", "mypc"), ("OS", "Linux 6.9")])
        →
            Hostname               mypc
            OS                     Linux 6.9
        """
        ind = getattr(Config, "UI_INDENT", "  ") + indent
        for label, value in pairs:
            print(f"{ind}{Ansi.dim(label.ljust(label_w))} {value}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Progress bar  (blocking, inline update)
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def progress(
        current: int,
        total:   int,
        *,
        label: str  = "",
        width: int  = 30,
        done:  bool = False,
    ) -> None:
        """
        Print an in-place updating progress bar.
        Call with done=True on the final step to print a newline.
        """
        ind  = getattr(Config, "UI_INDENT", "  ")
        pct  = (current / total * 100) if total else 0.0
        bar  = Ansi.pct_bar(pct, width)
        pct_s = Ansi.pct_colour(pct)
        line = f"\r{ind}{bar} {pct_s}  {current}/{total}  {label}"
        sys.stdout.write(line)
        sys.stdout.flush()
        if done:
            print()

    # ══════════════════════════════════════════════════════════════════════════
    #  Spinner
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def spinner(
        label:  str,
        target: Callable,
        *args:  Any,
        **kwargs: Any,
    ) -> Any:
        """
        Run *target(*args, **kwargs)* in a background thread while showing
        an animated spinner. Returns the target's return value.

        Usage
        ─────
            result = UI.spinner("Scanning ports…", scan_func, host, timeout=1.0)
        """
        result_box: list[Any]       = [None]
        exc_box:    list[Exception] = []

        def _run() -> None:
            try:
                result_box[0] = target(*args, **kwargs)
            except Exception as e:
                exc_box.append(e)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        ind    = getattr(Config, "UI_INDENT", "  ")
        frames = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        while thread.is_alive():
            frame = next(frames)
            sys.stdout.write(f"\r{ind}{Ansi.cyan(frame)}  {label}")
            sys.stdout.flush()
            time.sleep(0.08)

        sys.stdout.write(f"\r{' ' * (_term_width() - 1)}\r")   # clear line
        sys.stdout.flush()
        thread.join()

        if exc_box:
            raise exc_box[0]
        return result_box[0]

    # ══════════════════════════════════════════════════════════════════════════
    #  Box / panel
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def box(
        lines:   list[str],
        *,
        title:   str  = "",
        width:   int  = 0,
        colour:  str  = "white",
    ) -> None:
        """
        Draw a rounded box around *lines*.

        Parameters
        ──────────
        lines  : content lines (ANSI allowed; stripped for width calculation)
        title  : optional title in the top border
        width  : inner width; 0 = auto from content and terminal
        colour : border colour name (Ansi.PALETTE key)
        """
        ind    = getattr(Config, "UI_INDENT", "  ")
        tw     = _term_width() - len(ind) * 2
        inner  = width or min(tw - 4, max((len(Ansi.strip(l)) for l in lines), default=40))

        def _border(s: str) -> str:
            return Ansi.style(s, colour)

        top_title = f" {title} " if title else ""
        top_fill  = inner - len(top_title)
        top_left  = top_fill // 2
        top_right = top_fill - top_left

        print(f"{ind}{_border('╭' + '─' * top_left + top_title + '─' * top_right + '╮')}")
        for line in lines:
            stripped = Ansi.strip(line)
            pad      = inner - len(stripped)
            print(f"{ind}{_border('│')} {line}{' ' * max(0, pad)} {_border('│')}")
        print(f"{ind}{_border('╰' + '─' * (inner + 2) + '╯')}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Paginator
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def paginate(lines: list[str], *, page_size: int = 0) -> None:
        """
        Display *lines* page by page.
        *page_size* defaults to terminal height - 4.
        """
        try:
            rows = os.get_terminal_size().lines - 4
        except OSError:
            rows = 20
        ps = page_size or rows

        for i in range(0, len(lines), ps):
            chunk = lines[i: i + ps]
            for line in chunk:
                print(line)
            if i + ps < len(lines):
                remaining = len(lines) - i - ps
                ind = getattr(Config, "UI_INDENT", "  ")
                raw = input(
                    Ansi.dim(f"{ind}── {remaining} lines remaining  "
                             f"[Enter=next  q=quit] ── ")
                ).strip().lower()
                if raw == "q":
                    return

    # ══════════════════════════════════════════════════════════════════════════
    #  Main menu renderer
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def main_menu(items: list[tuple[str, str, str]], *, title: str = "") -> None:
        """
        Render the main navigation menu.

        Parameters
        ──────────
        items : list of (key, icon, label)
        title : optional sub-title below the banner
        """
        ind = getattr(Config, "UI_INDENT", "  ")
        if title:
            print(f"{ind}{Ansi.dim(title)}\n")
        for key, icon, label in items:
            key_s   = Ansi.style(f"[{key}]", "bold", "cyan")
            icon_s  = icon
            label_s = label
            print(f"{ind}  {key_s}  {icon_s}  {label_s}")
        print()

    # ══════════════════════════════════════════════════════════════════════════
    #  Startup banner
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def banner() -> None:
        """
        Print the application ASCII art banner.
        Respects ANSI_ENABLED — renders plain text when colours are off.
        """
        name    = getattr(Config, "APP_NAME",    "Local OS")
        version = getattr(Config, "APP_VERSION", "1.0.0")
        ind     = getattr(Config, "UI_INDENT",   "  ")
        tw      = _term_width()

        art = r"""
  ██╗      ██████╗  ██████╗ █████╗ ██╗      ██████╗ ███████╗
  ██║     ██╔═══██╗██╔════╝██╔══██╗██║     ██╔═══██╗██╔════╝
  ██║     ██║   ██║██║     ███████║██║     ██║   ██║███████╗
  ██║     ██║   ██║██║     ██╔══██║██║     ██║   ██║╚════██║
  ███████╗╚██████╔╝╚██████╗██║  ██║███████╗╚██████╔╝███████║
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"""

        _clear()
        print(Ansi.style(art, "cyan", "bold"))
        ver_line = f"  v{version}  —  System Administration Toolkit"
        print(Ansi.dim(ver_line.center(tw)))
        print(Ansi.dim("  " + "─" * (tw - 4)))
        print()

    # ══════════════════════════════════════════════════════════════════════════
    #  Config viewer  (used by terminal.py settings screen)
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def show_config() -> None:
        """Display all Config values in a two-column table."""
        try:
            cfg = Config.dump()
        except AttributeError:
            UI.warn("Config.dump() not available.")
            return
        UI.header("⚙  Current Configuration")
        rows = [[k, str(v)] for k, v in sorted(cfg.items())]
        UI.table(rows, ["KEY", "VALUE"], max_col_width=60, zebra=True)
        _pause()

    # ══════════════════════════════════════════════════════════════════════════
    #  Helpers exposed for other modules
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def pause() -> None:
        _pause()

    @staticmethod
    def clear() -> None:
        _clear()

    @staticmethod
    def warning(msg: str) -> None:
        """Alias for UI.warn() used by git_tools, log_analyzer, docker_manager."""
        ind = getattr(Config, "UI_INDENT", "  ")
        print(f"{ind}{Ansi.yellow('⚠')}  {Ansi.yellow(msg)}")

    @staticmethod
    def separator(*, char: str = "─", colour: str = "dim") -> None:
        ind = getattr(Config, "UI_INDENT", "  ")
        w   = _term_width() - len(ind)
        print(f"{ind}{Ansi.style(char * w, colour)}")

    @staticmethod
    def rule(title: str = "", *, char: str = "─") -> None:
        """Horizontal rule with optional centred title."""
        ind = getattr(Config, "UI_INDENT", "  ")
        w   = _term_width() - len(ind)
        if not title:
            print(f"{ind}{Ansi.dim(char * w)}")
            return
        pad   = (w - len(title) - 2) // 2
        left  = char * pad
        right = char * (w - pad - len(title) - 2)
        print(f"{ind}{Ansi.dim(left)} {Ansi.bold(title)} {Ansi.dim(right)}")