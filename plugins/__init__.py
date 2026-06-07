"""
plugins/__init__.py — Plugin Auto-Discovery & Lifecycle Manager
===============================================================
Auto-discovers and loads plugins from TWO locations:

  1. <repo>/plugins/          ← bundled / community plugins (this package)
  2. ~/.localos/plugins/      ← user plugins (outside repo, never committed)

Plugin contract
---------------
Every plugin module MUST expose:

  PLUGIN_NAME        str   — human-readable name shown in menus
  PLUGIN_VERSION     str   — semver string, e.g. "1.0.0"
  PLUGIN_DESCRIPTION str   — one-line description
  PLUGIN_AUTHOR      str   — author / maintainer
  PLUGIN_TAGS        list  — list of str tags for search/filter

  def main() -> None        — entry-point called by the terminal router
  def health_check() -> bool — True if all deps are satisfied

Optional hooks (called by the runtime if they exist):

  def on_load()  -> None    — called once after import
  def on_unload()-> None    — called before the plugin is removed

Lazy loading
------------
Plugins are imported only when first invoked (lazy). Heavy imports
(torch, PIL, etc.) belong inside `main()` or `on_load()`, not at
module level.

Safety
------
- Plugin exceptions never crash the main process; they are caught,
  logged, and surfaced as a user-facing error message.
- Plugins run in the same process and have full Python access.
  Do NOT load untrusted plugins from unknown sources.

Usage (from core/terminal.py or ModuleRegistry)
------------------------------------------------
  from plugins import PluginRegistry

  registry = PluginRegistry()          # auto-discovers on init
  registry.list()                      # → list[PluginMeta]
  registry.get("my_plugin")            # → PluginMeta | None
  registry.invoke("my_plugin")         # loads + calls main()
  registry.reload("my_plugin")         # hot-reload (dev mode)
  registry.health()                    # → dict[name → bool]
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import pkgutil
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterator, Optional

logger = logging.getLogger("local_os.plugins")

# ── Paths ─────────────────────────────────────────────────────────────────────

_BUILTIN_PLUGIN_DIR = Path(__file__).parent          # <repo>/plugins/
_USER_PLUGIN_DIR    = Path.home() / ".localos" / "plugins"

# ── Required plugin attributes ────────────────────────────────────────────────

_REQUIRED_ATTRS = (
    "PLUGIN_NAME",
    "PLUGIN_VERSION",
    "PLUGIN_DESCRIPTION",
    "PLUGIN_AUTHOR",
)

_OPTIONAL_HOOKS = ("on_load", "on_unload", "health_check")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class PluginMeta:
    """Metadata + lazy reference for one discovered plugin."""

    name:        str
    version:     str
    description: str
    author:      str
    tags:        list[str]
    module_name: str              # fully-qualified import path
    source_path: Path             # .py file on disk
    builtin:     bool             # True = ships with repo, False = user plugin

    _module: Optional[ModuleType] = field(default=None, repr=False)
    _error:  Optional[str]        = field(default=None, repr=False)

    @property
    def loaded(self) -> bool:
        return self._module is not None

    @property
    def load_error(self) -> Optional[str]:
        return self._error

    def get_attr(self, name: str, default: Any = None) -> Any:
        """Safe attribute access on the underlying module."""
        if self._module is None:
            return default
        return getattr(self._module, name, default)

    def __str__(self) -> str:
        status = "✓" if self.loaded else ("✗" if self._error else "○")
        src    = "builtin" if self.builtin else "user"
        return f"[{status}] {self.name} v{self.version} ({src}) — {self.description}"


# ── Registry ──────────────────────────────────────────────────────────────────

class PluginRegistry:
    """
    Discovers, loads, and manages local_os plugins.

    Typical lifecycle
    -----------------
    registry = PluginRegistry()       # scans both directories
    registry.list()                   # show what's available
    registry.invoke("awesome_plugin") # lazy-load + call main()
    """

    def __init__(
        self,
        builtin_dir: Path = _BUILTIN_PLUGIN_DIR,
        user_dir:    Path = _USER_PLUGIN_DIR,
        auto_load:   bool = False,   # if True, eagerly import all plugins
    ) -> None:
        self._builtin_dir = builtin_dir
        self._user_dir    = user_dir
        self._plugins:   dict[str, PluginMeta] = {}   # key = PLUGIN_NAME
        self._discover()
        if auto_load:
            self._eager_load()

    # ── Discovery ─────────────────────────────────────────────────────────────

    def _discover(self) -> None:
        """Scan both plugin directories and register metadata."""
        self._plugins.clear()

        # 1) Built-in plugins (this package)
        for meta in self._scan_directory(self._builtin_dir, builtin=True):
            self._plugins[meta.name] = meta

        # 2) User plugins (~/.localos/plugins/)
        if self._user_dir.exists():
            for meta in self._scan_directory(self._user_dir, builtin=False):
                if meta.name in self._plugins:
                    logger.info(
                        "User plugin '%s' overrides built-in plugin.", meta.name
                    )
                self._plugins[meta.name] = meta
        else:
            self._user_dir.mkdir(parents=True, exist_ok=True)
            logger.debug("Created user plugin directory: %s", self._user_dir)

    def _scan_directory(
        self, directory: Path, builtin: bool
    ) -> Iterator[PluginMeta]:
        """
        Yield PluginMeta for every valid plugin module found in `directory`.
        Skips __init__.py, files starting with '_', and example_plugin.py
        (the template — it is intentionally not auto-loaded).
        """
        if not directory.is_dir():
            return

        # Add directory to sys.path so user plugins can be imported
        dir_str = str(directory)
        if dir_str not in sys.path:
            sys.path.insert(0, dir_str)

        for finder, module_name, _ispkg in pkgutil.iter_modules([str(directory)]):
            # Skip private, init, and the template file
            if module_name.startswith("_") or module_name == "example_plugin":
                continue

            source_path = directory / f"{module_name}.py"
            if not source_path.exists():
                # Could be a sub-package; skip for now
                continue

            meta = self._inspect_module_file(
                module_name=module_name,
                source_path=source_path,
                builtin=builtin,
            )
            if meta is not None:
                yield meta

    @staticmethod
    def _inspect_module_file(
        module_name: str,
        source_path: Path,
        builtin:     bool,
    ) -> Optional[PluginMeta]:
        """
        Read module-level constants without fully importing the file.
        Uses importlib to do a spec-only load so top-level code is NOT run.
        Falls back to source scanning if spec load fails.
        """
        attrs = _read_module_constants(source_path)
        if attrs is None:
            logger.warning("Could not read constants from '%s' — skipped.", source_path)
            return None

        # Validate required fields
        missing = [a for a in _REQUIRED_ATTRS if a not in attrs]
        if missing:
            logger.warning(
                "'%s' missing required plugin attributes: %s — skipped.",
                module_name, missing,
            )
            return None

        return PluginMeta(
            name        = attrs["PLUGIN_NAME"],
            version     = attrs.get("PLUGIN_VERSION", "0.0.0"),
            description = attrs.get("PLUGIN_DESCRIPTION", ""),
            author      = attrs.get("PLUGIN_AUTHOR", "unknown"),
            tags        = attrs.get("PLUGIN_TAGS", []),
            module_name = module_name,
            source_path = source_path,
            builtin     = builtin,
        )

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_plugin(self, meta: PluginMeta) -> bool:
        """
        Fully import the plugin module.
        Returns True on success, False on failure.
        Sets meta._module or meta._error accordingly.
        """
        if meta.loaded:
            return True

        try:
            spec = importlib.util.spec_from_file_location(
                meta.module_name, meta.source_path
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot create spec for {meta.source_path}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[meta.module_name] = module
            spec.loader.exec_module(module)          # type: ignore[union-attr]

            meta._module = module
            meta._error  = None

            # Call on_load() hook if present
            hook = getattr(module, "on_load", None)
            if callable(hook):
                hook()

            logger.info("Plugin loaded: %s v%s", meta.name, meta.version)
            return True

        except Exception:
            tb = traceback.format_exc()
            meta._error = tb
            logger.error("Failed to load plugin '%s':\n%s", meta.name, tb)
            return False

    def _eager_load(self) -> None:
        for meta in self._plugins.values():
            self._load_plugin(meta)

    # ── Public API ────────────────────────────────────────────────────────────

    def list(self, tag: Optional[str] = None) -> list[PluginMeta]:
        """Return all discovered plugins, optionally filtered by tag."""
        plugins = list(self._plugins.values())
        if tag:
            plugins = [p for p in plugins if tag in p.tags]
        return sorted(plugins, key=lambda p: (not p.builtin, p.name.lower()))

    def get(self, name: str) -> Optional[PluginMeta]:
        """Return PluginMeta by PLUGIN_NAME. None if not found."""
        return self._plugins.get(name)

    def invoke(self, name: str, *args: Any, **kwargs: Any) -> Any:
        """
        Lazy-load plugin by name and call its main(*args, **kwargs).
        Raises PluginNotFoundError if not discovered.
        Raises PluginLoadError if import fails.
        Raises PluginInvokeError if main() raises.
        """
        meta = self._plugins.get(name)
        if meta is None:
            raise PluginNotFoundError(f"Plugin '{name}' not found. "
                                       f"Known: {list(self._plugins)}")

        if not meta.loaded:
            ok = self._load_plugin(meta)
            if not ok:
                raise PluginLoadError(
                    f"Plugin '{name}' failed to load:\n{meta.load_error}"
                )

        entry = meta.get_attr("main")
        if not callable(entry):
            raise PluginLoadError(f"Plugin '{name}' has no callable main().")

        try:
            return entry(*args, **kwargs)
        except Exception as exc:
            tb = traceback.format_exc()
            logger.error("Plugin '%s' raised during main():\n%s", name, tb)
            raise PluginInvokeError(
                f"Plugin '{name}' raised {type(exc).__name__}: {exc}"
            ) from exc

    def reload(self, name: str) -> bool:
        """
        Hot-reload a plugin (useful during development).
        Calls on_unload() if present, removes from sys.modules, re-imports.
        """
        meta = self._plugins.get(name)
        if meta is None:
            return False

        # Unload hook
        if meta.loaded:
            hook = meta.get_attr("on_unload")
            if callable(hook):
                try:
                    hook()
                except Exception:
                    logger.warning("on_unload() raised in '%s'", name, exc_info=True)
            sys.modules.pop(meta.module_name, None)
            meta._module = None
            meta._error  = None

        return self._load_plugin(meta)

    def health(self) -> dict[str, bool | str]:
        """
        Run health_check() on every loaded plugin.
        Returns {plugin_name: True | error_string}.
        """
        results: dict[str, bool | str] = {}
        for meta in self._plugins.values():
            if not meta.loaded:
                results[meta.name] = "not loaded"
                continue
            checker = meta.get_attr("health_check")
            if not callable(checker):
                results[meta.name] = True   # no health_check = assume OK
                continue
            try:
                ok = checker()
                results[meta.name] = bool(ok)
            except Exception as exc:
                results[meta.name] = str(exc)
        return results

    def unload(self, name: str) -> bool:
        """Unload a plugin (calls on_unload, removes from sys.modules)."""
        meta = self._plugins.get(name)
        if meta is None or not meta.loaded:
            return False
        hook = meta.get_attr("on_unload")
        if callable(hook):
            try:
                hook()
            except Exception:
                logger.warning("on_unload() raised for '%s'", name, exc_info=True)
        sys.modules.pop(meta.module_name, None)
        meta._module = None
        return True

    def rescan(self) -> tuple[int, int]:
        """Re-scan plugin directories. Returns (added, removed) counts."""
        before = set(self._plugins)
        self._discover()
        after  = set(self._plugins)
        added   = len(after  - before)
        removed = len(before - after)
        logger.info("Plugin rescan: +%d -%d", added, removed)
        return added, removed

    def __len__(self) -> int:
        return len(self._plugins)

    def __contains__(self, name: str) -> bool:
        return name in self._plugins

    def __iter__(self) -> Iterator[PluginMeta]:
        return iter(self._plugins.values())

    def __repr__(self) -> str:
        return (
            f"PluginRegistry("
            f"discovered={len(self._plugins)}, "
            f"loaded={sum(1 for p in self._plugins.values() if p.loaded)}"
            f")"
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_module_constants(path: Path) -> Optional[dict]:
    """
    Extract module-level string/list constants from a .py file
    WITHOUT executing the file.  Uses ast for safety.
    """
    import ast

    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError) as exc:
        logger.debug("ast.parse failed for %s: %s", path, exc)
        return None

    result: dict = {}

    for node in ast.walk(tree):
        # Handle both:  PLUGIN_X = value
        #           and PLUGIN_X: SomeType = value  (AnnAssign)
        if isinstance(node, ast.Assign):
            targets = node.targets
            value_node = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value_node = node.value
        else:
            continue

        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if not name.startswith("PLUGIN_"):
                continue
            try:
                value = ast.literal_eval(value_node)
                result[name] = value
            except (ValueError, TypeError):
                pass  # non-literal constant — skip

    return result if result else None


# ── Custom exceptions ─────────────────────────────────────────────────────────

class PluginError(RuntimeError):
    """Base class for all plugin-related errors."""


class PluginNotFoundError(PluginError):
    """Raised when the requested plugin was never discovered."""


class PluginLoadError(PluginError):
    """Raised when a plugin fails to import."""


class PluginInvokeError(PluginError):
    """Raised when main() raises an unhandled exception."""


# ── Module-level convenience instance ────────────────────────────────────────
# Imported by core/terminal.py:
#   from plugins import registry
#   registry.invoke("awesome_tool")

# ── Module-level convenience instance ────────────────────────────────────────
# Imported by core/terminal.py:
#   from plugins import registry
#   registry.invoke("awesome_tool")

try:
    registry = PluginRegistry()
except Exception as _registry_exc:
    logger.warning("PluginRegistry failed to initialise: %s", _registry_exc)
    registry = PluginRegistry.__new__(PluginRegistry)
    registry._plugins = {}
    registry._builtin_dir = _BUILTIN_PLUGIN_DIR
    registry._user_dir    = _USER_PLUGIN_DIR

__all__ = [
    "PluginRegistry",
    "PluginMeta",
    "PluginError",
    "PluginNotFoundError",
    "PluginLoadError",
    "PluginInvokeError",
    "registry",
]