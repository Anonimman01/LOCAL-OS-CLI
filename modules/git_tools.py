"""
git_tools.py — Git Repository Management Module
═════════════════════════════════════════════════
Part of local_os toolkit. Full-featured Git interface from the terminal:
status, log, diff, branches, stash, cherry-pick, remote ops, blame, bisect.

Architecture:
  GitRepo          — dataclass representing a discovered repository
  GitCommit        — structured commit (hash, author, date, subject, body)
  GitRunner        — thin subprocess wrapper, all git invocations here
  GitAnalyzer      — business logic: log, diff, stash, cherry-pick, etc.
  GitUI            — terminal rendering (uses core.ui primitives)
  register()       — module entry point called by ModuleRegistry

Design rules:
  • GitRunner never knows about UI; GitUI never runs git directly
  • Every git call goes through GitRunner._run() — timeout, encoding, errors
  • No third-party git library required — pure subprocess
  • Graceful standalone: works without core.ui / core.config imports
  • Thread-safe: no shared mutable state outside GitRunner (per-repo lock)

Author  : local_os project
License : MIT
"""

from __future__ import annotations

# ── stdlib ─────────────────────────────────────────────────────────────────
import collections
import contextlib
import fnmatch
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# ── project imports (graceful standalone fallback) ─────────────────────────
try:
    from core.ui import Ansi, UI  # type: ignore
    from core.config import Config  # type: ignore
except ImportError:
    class Ansi:  # type: ignore  # noqa: E302
        RESET = RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = BOLD = DIM = ""
        WHITE = BRIGHT_WHITE = BRIGHT_GREEN = BRIGHT_RED = BRIGHT_CYAN = ""
        BRIGHT_YELLOW = BG_RED = BG_GREEN = BG_BLUE = ""

        @staticmethod
        def color(text: str, *_: str) -> str:
            return text

    class UI:  # type: ignore  # noqa: E302
        @staticmethod
        def header(title: str) -> None:
            print(f"\n{'═' * 62}\n  {title}\n{'═' * 62}")

        @staticmethod
        def success(msg: str) -> None:
            print(f"  ✓  {msg}")

        @staticmethod
        def error(msg: str) -> None:
            print(f"  ✗  {msg}", file=sys.stderr)

        @staticmethod
        def warning(msg: str) -> None:
            print(f"  ⚠  {msg}")

        @staticmethod
        def info(msg: str) -> None:
            print(f"  ·  {msg}")

        @staticmethod
        def prompt(msg: str) -> str:
            return input(f"  ▶  {msg} ")

        @staticmethod
        def confirm(msg: str) -> bool:
            return input(f"  ?  {msg} [y/N] ").strip().lower() == "y"

        @staticmethod
        def pause() -> None:
            input("  ⏎  Press Enter to continue… ")

    class Config:  # type: ignore  # noqa: E302
        GIT_LOG_LIMIT: int = 50
        GIT_DIFF_CONTEXT: int = 3
        GIT_SEARCH_DIRS: List[str] = ["~", "~/projects", "~/src", "~/code",
                                       "~/work", "~/repos", "/opt", "/srv"]
        GIT_SEARCH_DEPTH: int = 4
        GIT_TIMEOUT: int = 30

# ── logger ──────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── git binary ──────────────────────────────────────────────────────────────
_GIT_BIN: str = shutil.which("git") or "git"
_GIT_AVAILABLE: bool = shutil.which("git") is not None

# ── ANSI diff colours ────────────────────────────────────────────────────────
_DIFF_COLOURS: Dict[str, str] = {
    "+": Ansi.BRIGHT_GREEN,
    "-": Ansi.RED,
    "@": Ansi.CYAN,
    "d": Ansi.BOLD,          # diff --git a/…
    "i": Ansi.BRIGHT_YELLOW, # index line
    "\\": Ansi.DIM,
}

# ── file-status letter → description + colour ────────────────────────────────
_STATUS_MAP: Dict[str, Tuple[str, str]] = {
    "M":  ("modified",   Ansi.YELLOW),
    "A":  ("added",      Ansi.BRIGHT_GREEN),
    "D":  ("deleted",    Ansi.RED),
    "R":  ("renamed",    Ansi.CYAN),
    "C":  ("copied",     Ansi.CYAN),
    "U":  ("unmerged",   Ansi.BRIGHT_RED),
    "?":  ("untracked",  Ansi.DIM),
    "!":  ("ignored",    Ansi.DIM),
    " ":  ("clean",      Ansi.GREEN),
}


# ══════════════════════════════════════════════════════════════════════════
# Exceptions
# ══════════════════════════════════════════════════════════════════════════

class GitToolsError(RuntimeError):
    """Base exception."""


class GitNotFoundError(GitToolsError):
    """git binary not on PATH."""


class GitRepoError(GitToolsError):
    """Not a git repository or repo-level failure."""


class GitCommandError(GitToolsError):
    """git command returned non-zero exit code."""


class GitConflictError(GitToolsError):
    """Operation aborted due to conflicts."""


# ══════════════════════════════════════════════════════════════════════════
# Data-transfer objects
# ══════════════════════════════════════════════════════════════════════════

class FileStatus(str, Enum):
    MODIFIED   = "M"
    ADDED      = "A"
    DELETED    = "D"
    RENAMED    = "R"
    COPIED     = "C"
    UNMERGED   = "U"
    UNTRACKED  = "?"
    IGNORED    = "!"
    CLEAN      = " "

    @classmethod
    def from_char(cls, c: str) -> "FileStatus":
        with contextlib.suppress(ValueError):
            return cls(c.upper())
        return cls.CLEAN


@dataclass(slots=True)
class GitRepo:
    path: str               # absolute path to worktree root
    name: str               # basename
    current_branch: str
    is_bare: bool
    has_remote: bool
    remotes: List[str]
    ahead: int = 0          # commits ahead of upstream
    behind: int = 0         # commits behind upstream
    stash_count: int = 0
    is_dirty: bool = False


@dataclass(slots=True)
class GitCommit:
    hash: str               # full 40-char SHA
    short_hash: str         # 8-char
    author_name: str
    author_email: str
    author_date: str        # ISO-8601
    committer_date: str
    subject: str
    body: str
    refs: str               # decorations: HEAD, branch, tag
    parents: List[str]

    @property
    def short_subject(self) -> str:
        return self.subject[:72] + ("…" if len(self.subject) > 72 else "")


@dataclass(slots=True)
class StatusEntry:
    index_status: FileStatus    # staging area
    work_status: FileStatus     # working tree
    path: str
    orig_path: str = ""         # rename/copy source


@dataclass
class RepoStatus:
    branch: str
    upstream: str
    ahead: int
    behind: int
    staged: List[StatusEntry]
    unstaged: List[StatusEntry]
    untracked: List[StatusEntry]
    unmerged: List[StatusEntry]
    is_clean: bool
    stash_count: int
    last_commit: Optional[GitCommit]


@dataclass(slots=True)
class StashEntry:
    index: int
    ref: str        # stash@{N}
    branch: str
    message: str
    date: str


@dataclass
class BlameEntry:
    hash: str
    author: str
    date: str
    line_no: int
    content: str


# ══════════════════════════════════════════════════════════════════════════
# GitRunner — thin subprocess wrapper
# ══════════════════════════════════════════════════════════════════════════

class GitRunner:
    """
    All git invocations go through here.
    Per-repo lock prevents concurrent mutations on the same worktree.
    """

    _locks: Dict[str, threading.Lock] = {}
    _locks_meta = threading.Lock()

    def __init__(self, repo_path: str) -> None:
        if not _GIT_AVAILABLE:
            raise GitNotFoundError(
                "git not found on PATH. Install git first."
            )
        self.repo_path = repo_path
        # lazy per-repo lock
        with self._locks_meta:
            if repo_path not in self._locks:
                self._locks[repo_path] = threading.Lock()
        self._lock = self._locks[repo_path]

    # ── core run ──────────────────────────────────────────────────────────

    def _run(
        self,
        *args: str,
        check: bool = True,
        timeout: Optional[int] = None,
        input_data: Optional[str] = None,
        env_extra: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Execute git *args in self.repo_path.
        Raises GitCommandError on non-zero exit when check=True.
        """
        timeout = timeout or getattr(Config, "GIT_TIMEOUT", 30)
        cmd = [_GIT_BIN, *args]
        env = os.environ.copy()
        # Force English output for reliable parsing
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        env["GIT_TERMINAL_PROMPT"] = "0"  # never block on password prompt
        if env_extra:
            env.update(env_extra)

        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data,
                env=env,
            )
        except FileNotFoundError as exc:
            raise GitNotFoundError("git binary disappeared from PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitCommandError(
                f"git {args[0]} timed out after {timeout}s"
            ) from exc

        if check and result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            raise GitCommandError(
                f"git {' '.join(args[:3])} failed (rc={result.returncode}): {err}"
            )
        return result

    # ── read-only ops (no lock needed) ───────────────────────────────────

    def is_repo(self) -> bool:
        with contextlib.suppress(GitCommandError, GitNotFoundError):
            r = self._run("rev-parse", "--is-inside-work-tree", check=False)
            return r.returncode == 0 and r.stdout.strip() == "true"
        return False

    def rev_parse(self, ref: str) -> str:
        return self._run("rev-parse", "--verify", ref).stdout.strip()

    def current_branch(self) -> str:
        with contextlib.suppress(GitCommandError):
            return self._run("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        return "HEAD"  # detached

    def list_branches(
        self, remote: bool = False, all_: bool = False
    ) -> List[Tuple[str, bool]]:
        """Return [(branch_name, is_current)]."""
        args = ["branch", "--format=%(refname:short)\t%(HEAD)"]
        if all_:
            args.append("-a")
        elif remote:
            args.append("-r")
        r = self._run(*args)
        results = []
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t", 1)
            name = parts[0].strip()
            current = len(parts) > 1 and parts[1].strip() == "*"
            if name:
                results.append((name, current))
        return results

    def log(
        self,
        limit: int = 50,
        ref: str = "HEAD",
        path: Optional[str] = None,
        author: Optional[str] = None,
        grep: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        all_branches: bool = False,
        merges_only: bool = False,
        no_merges: bool = False,
        oneline: bool = False,
    ) -> List[GitCommit]:
        """Return parsed commit list."""
        sep = "\x1f"   # unit separator — safe inside commit messages
        rec_sep = "\x1e"  # record separator

        fmt = sep.join([
            "%H", "%h", "%an", "%ae", "%aI", "%cI",
            "%s", "%b", "%D", "%P",
        ]) + rec_sep

        args = ["log", f"--format={fmt}", f"-{limit}"]
        if all_branches:
            args.append("--all")
        if no_merges:
            args.append("--no-merges")
        if merges_only:
            args.append("--merges")
        if author:
            args.append(f"--author={author}")
        if grep:
            args.append(f"--grep={grep}")
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")
        args.append(ref)
        if path:
            args += ["--", path]

        r = self._run(*args, check=False)
        if r.returncode not in (0, 128):
            return []

        commits = []
        for record in r.stdout.split(rec_sep):
            record = record.strip()
            if not record:
                continue
            parts = record.split(sep)
            if len(parts) < 9:
                continue
            commits.append(
                GitCommit(
                    hash=parts[0],
                    short_hash=parts[1],
                    author_name=parts[2],
                    author_email=parts[3],
                    author_date=parts[4][:19],
                    committer_date=parts[5][:19],
                    subject=parts[6],
                    body=parts[7].strip(),
                    refs=parts[8],
                    parents=parts[9].split() if len(parts) > 9 else [],
                )
            )
        return commits

    def status(self) -> RepoStatus:
        """Parse `git status --porcelain=v2 --branch` output."""
        r = self._run("status", "--porcelain=v2", "--branch", check=False)
        lines = r.stdout.splitlines()

        branch = ""
        upstream = ""
        ahead = behind = 0
        staged: List[StatusEntry] = []
        unstaged: List[StatusEntry] = []
        untracked: List[StatusEntry] = []
        unmerged: List[StatusEntry] = []

        for line in lines:
            if line.startswith("# branch.head "):
                branch = line[len("# branch.head "):]
            elif line.startswith("# branch.upstream "):
                upstream = line[len("# branch.upstream "):]
            elif line.startswith("# branch.ab "):
                m = re.match(r"# branch\.ab \+(\d+) -(\d+)", line)
                if m:
                    ahead, behind = int(m.group(1)), int(m.group(2))
            elif line.startswith("1 "):
                # ordinary changed entry
                parts = line.split(" ", 8)
                if len(parts) >= 9:
                    xy = parts[1]
                    path = parts[8]
                    ix = FileStatus.from_char(xy[0])
                    wt = FileStatus.from_char(xy[1])
                    e = StatusEntry(ix, wt, path)
                    if xy[0] != " " and xy[0] != "?":
                        staged.append(e)
                    if xy[1] not in (" ", "?"):
                        unstaged.append(e)
            elif line.startswith("2 "):
                # renamed / copied
                parts = line.split(" ", 9)
                if len(parts) >= 10:
                    xy = parts[1]
                    paths = parts[9].split("\t", 1)
                    new_path = paths[0]
                    orig = paths[1] if len(paths) > 1 else ""
                    ix = FileStatus.from_char(xy[0])
                    wt = FileStatus.from_char(xy[1])
                    e = StatusEntry(ix, wt, new_path, orig)
                    staged.append(e)
            elif line.startswith("u "):
                # unmerged
                parts = line.split(" ", 10)
                if len(parts) >= 11:
                    unmerged.append(
                        StatusEntry(FileStatus.UNMERGED, FileStatus.UNMERGED, parts[10])
                    )
            elif line.startswith("? "):
                untracked.append(
                    StatusEntry(FileStatus.UNTRACKED, FileStatus.UNTRACKED, line[2:])
                )

        # stash count
        stash_r = self._run("stash", "list", check=False)
        stash_count = len([l for l in stash_r.stdout.splitlines() if l.strip()])

        # last commit
        commits = self.log(limit=1)
        last_commit = commits[0] if commits else None

        is_clean = not staged and not unstaged and not untracked and not unmerged

        return RepoStatus(
            branch=branch,
            upstream=upstream,
            ahead=ahead,
            behind=behind,
            staged=staged,
            unstaged=unstaged,
            untracked=untracked,
            unmerged=unmerged,
            is_clean=is_clean,
            stash_count=stash_count,
            last_commit=last_commit,
        )

    def diff(
        self,
        cached: bool = False,
        ref1: Optional[str] = None,
        ref2: Optional[str] = None,
        path: Optional[str] = None,
        stat_only: bool = False,
        context: int = 3,
        word_diff: bool = False,
    ) -> str:
        args = ["diff", f"--unified={context}"]
        if stat_only:
            args = ["diff", "--stat"]
        if word_diff:
            args.append("--word-diff=color")
        if cached:
            args.append("--cached")
        if ref1 and ref2:
            args += [f"{ref1}..{ref2}"]
        elif ref1:
            args.append(ref1)
        if path:
            args += ["--", path]
        r = self._run(*args, check=False)
        return r.stdout

    def show(self, ref: str, stat_only: bool = False) -> str:
        args = ["show", "--color=never"]
        if stat_only:
            args.append("--stat")
        args.append(ref)
        r = self._run(*args, check=False)
        return r.stdout

    def blame(self, path: str, start: int = 1, end: Optional[int] = None) -> List[BlameEntry]:
        range_arg = f"-L {start},{end or ''}" if end else f"-L {start},"
        # split into separate args to avoid shell interpretation
        args = ["blame", "--porcelain"]
        if end:
            args += ["-L", f"{start},{end}"]
        else:
            args += ["-L", f"{start},"]
        args.append(path)
        r = self._run(*args, check=False)
        entries: List[BlameEntry] = []
        current: Dict[str, str] = {}
        line_no = start
        for line in r.stdout.splitlines():
            if re.match(r"^[0-9a-f]{40} ", line):
                current = {"hash": line[:40]}
            elif line.startswith("author "):
                current["author"] = line[7:]
            elif line.startswith("author-time "):
                ts = int(line[12:])
                current["date"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            elif line.startswith("\t"):
                entries.append(BlameEntry(
                    hash=current.get("hash", "")[:8],
                    author=current.get("author", ""),
                    date=current.get("date", ""),
                    line_no=line_no,
                    content=line[1:],
                ))
                line_no += 1
        return entries

    def remotes(self) -> List[Tuple[str, str, str]]:
        """Return [(name, url, type)] where type is 'fetch'|'push'."""
        r = self._run("remote", "-v", check=False)
        results = []
        seen: Set[str] = set()
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                key = f"{parts[0]}-{parts[2]}"
                if key not in seen:
                    seen.add(key)
                    results.append((parts[0], parts[1], parts[2].strip("()")))
        return results

    def stash_list(self) -> List[StashEntry]:
        fmt = "%gd\t%s\t%ci"
        r = self._run("stash", "list", f"--format={fmt}", check=False)
        entries = []
        for i, line in enumerate(r.stdout.strip().splitlines()):
            parts = line.split("\t", 2)
            ref = parts[0] if parts else f"stash@{{{i}}}"
            msg = parts[1] if len(parts) > 1 else ""
            date = parts[2][:19] if len(parts) > 2 else ""
            # extract branch from "WIP on branch: …" or "On branch: …"
            branch_m = re.search(r"(?:WIP on|On) ([^:]+)", msg)
            branch = branch_m.group(1) if branch_m else ""
            entries.append(StashEntry(index=i, ref=ref, branch=branch, message=msg, date=date))
        return entries

    def tags(self, pattern: Optional[str] = None) -> List[Tuple[str, str]]:
        """Return [(tag_name, annotated_message_or_hash)]."""
        args = ["tag", "-l", "--sort=-version:refname"]
        if pattern:
            args.append(pattern)
        r = self._run(*args, check=False)
        results = []
        for tag in r.stdout.strip().splitlines():
            if not tag:
                continue
            msg_r = self._run(
                "tag", "-n1", tag, check=False
            )
            msg = msg_r.stdout.strip()[len(tag):].strip() if msg_r.returncode == 0 else ""
            results.append((tag, msg))
        return results

    def graph(self, limit: int = 20, all_: bool = True) -> str:
        args = [
            "log",
            f"--graph",
            "--oneline",
            "--decorate",
            "--color=never",
            f"-{limit}",
        ]
        if all_:
            args.append("--all")
        r = self._run(*args, check=False)
        return r.stdout

    # ── mutating ops (acquire lock) ───────────────────────────────────────

    def checkout(self, branch: str, create: bool = False) -> str:
        with self._lock:
            args = ["checkout"]
            if create:
                args.append("-b")
            args.append(branch)
            r = self._run(*args)
            return r.stdout + r.stderr

    def create_branch(self, name: str, start: str = "HEAD") -> None:
        with self._lock:
            self._run("branch", name, start)

    def delete_branch(self, name: str, force: bool = False) -> None:
        with self._lock:
            flag = "-D" if force else "-d"
            self._run("branch", flag, name)

    def merge(self, branch: str, no_ff: bool = False, squash: bool = False) -> str:
        with self._lock:
            args = ["merge"]
            if no_ff:
                args.append("--no-ff")
            if squash:
                args.append("--squash")
            args.append(branch)
            r = self._run(*args, check=False)
            if r.returncode != 0:
                if "CONFLICT" in r.stdout or "CONFLICT" in r.stderr:
                    raise GitConflictError(r.stdout + r.stderr)
                raise GitCommandError(r.stderr.strip() or r.stdout.strip())
            return r.stdout

    def cherry_pick(
        self, commit: str,
        no_commit: bool = False,
        edit: bool = False,
    ) -> str:
        with self._lock:
            args = ["cherry-pick"]
            if no_commit:
                args.append("-n")
            if edit:
                args.append("-e")
            args.append(commit)
            r = self._run(*args, check=False)
            if r.returncode != 0:
                if "CONFLICT" in r.stdout or "CONFLICT" in r.stderr:
                    raise GitConflictError(r.stdout + r.stderr)
                raise GitCommandError(r.stderr.strip() or r.stdout.strip())
            return r.stdout + r.stderr

    def cherry_pick_abort(self) -> None:
        with self._lock:
            self._run("cherry-pick", "--abort", check=False)

    def cherry_pick_continue(self) -> str:
        with self._lock:
            r = self._run(
                "cherry-pick", "--continue",
                env_extra={"GIT_EDITOR": "true"},   # skip editor
                check=False,
            )
            return r.stdout + r.stderr

    def stash_push(
        self, message: Optional[str] = None, include_untracked: bool = False
    ) -> str:
        with self._lock:
            args = ["stash", "push"]
            if include_untracked:
                args.append("-u")
            if message:
                args += ["-m", message]
            r = self._run(*args)
            return r.stdout.strip()

    def stash_pop(self, index: int = 0) -> str:
        with self._lock:
            r = self._run("stash", "pop", f"stash@{{{index}}}")
            return r.stdout.strip()

    def stash_apply(self, index: int = 0) -> str:
        with self._lock:
            r = self._run("stash", "apply", f"stash@{{{index}}}")
            return r.stdout.strip()

    def stash_drop(self, index: int) -> None:
        with self._lock:
            self._run("stash", "drop", f"stash@{{{index}}}")

    def stash_show(self, index: int = 0, stat_only: bool = False) -> str:
        args = ["stash", "show"]
        if not stat_only:
            args.append("-p")
        args.append(f"stash@{{{index}}}")
        r = self._run(*args, check=False)
        return r.stdout

    def add(self, paths: List[str]) -> None:
        with self._lock:
            self._run("add", "--", *paths)

    def reset(self, paths: List[str], hard: bool = False) -> None:
        with self._lock:
            if hard:
                self._run("reset", "--hard", "HEAD")
            else:
                self._run("reset", "HEAD", "--", *paths)

    def commit(self, message: str, amend: bool = False) -> str:
        with self._lock:
            args = ["commit", "-m", message]
            if amend:
                args.append("--amend")
            r = self._run(*args)
            return r.stdout.strip()

    def fetch(self, remote: str = "origin", prune: bool = True) -> str:
        with self._lock:
            args = ["fetch", remote]
            if prune:
                args.append("--prune")
            r = self._run(*args, timeout=60)
            return r.stdout + r.stderr

    def pull(self, remote: str = "origin", branch: str = "", rebase: bool = False) -> str:
        with self._lock:
            args = ["pull"]
            if rebase:
                args.append("--rebase")
            args.append(remote)
            if branch:
                args.append(branch)
            r = self._run(*args, timeout=60, check=False)
            if r.returncode != 0:
                if "CONFLICT" in r.stdout:
                    raise GitConflictError(r.stdout)
                raise GitCommandError(r.stderr.strip() or r.stdout.strip())
            return r.stdout + r.stderr

    def push(
        self, remote: str = "origin", branch: str = "",
        force: bool = False, tags: bool = False,
        set_upstream: bool = False,
    ) -> str:
        with self._lock:
            args = ["push"]
            if force:
                args.append("--force-with-lease")  # safer than --force
            if tags:
                args.append("--tags")
            if set_upstream:
                args += ["--set-upstream"]
            args.append(remote)
            if branch:
                args.append(branch)
            r = self._run(*args, timeout=60, check=False)
            if r.returncode != 0:
                raise GitCommandError(r.stderr.strip() or r.stdout.strip())
            return r.stdout + r.stderr

    def rebase(
        self, onto: str, interactive: bool = False
    ) -> str:
        with self._lock:
            args = ["rebase"]
            if interactive:
                # non-interactive rebase only in TUI; spawn editor would block
                raise GitCommandError(
                    "Interactive rebase requires a TTY editor. "
                    "Run: git rebase -i " + onto
                )
            args.append(onto)
            r = self._run(*args, check=False)
            if r.returncode != 0:
                if "CONFLICT" in r.stdout or "CONFLICT" in r.stderr:
                    raise GitConflictError(r.stdout + r.stderr)
                raise GitCommandError(r.stderr.strip() or r.stdout.strip())
            return r.stdout + r.stderr

    def rebase_abort(self) -> None:
        with self._lock:
            self._run("rebase", "--abort", check=False)

    def tag_create(
        self, name: str, message: Optional[str] = None, ref: str = "HEAD"
    ) -> None:
        with self._lock:
            if message:
                self._run("tag", "-a", name, ref, "-m", message)
            else:
                self._run("tag", name, ref)

    def tag_delete(self, name: str) -> None:
        with self._lock:
            self._run("tag", "-d", name)

    def config_get(self, key: str) -> str:
        r = self._run("config", "--get", key, check=False)
        return r.stdout.strip()

    def config_list(self, local_only: bool = True) -> Dict[str, str]:
        args = ["config", "--list"]
        if local_only:
            args.append("--local")
        r = self._run(*args, check=False)
        result: Dict[str, str] = {}
        for line in r.stdout.strip().splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip()
        return result

    def repo_info(self) -> GitRepo:
        """Gather all repo metadata in one shot."""
        branch = self.current_branch()
        is_bare_r = self._run("rev-parse", "--is-bare-repository", check=False)
        is_bare = is_bare_r.stdout.strip() == "true"

        remote_list = [r[0] for r in self.remotes()]
        has_remote = bool(remote_list)

        # ahead/behind
        ahead = behind = 0
        upstream_r = self._run(
            "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False
        )
        if upstream_r.returncode == 0:
            upstream = upstream_r.stdout.strip()
            ab_r = self._run(
                "rev-list", "--left-right", "--count", f"{upstream}...HEAD", check=False
            )
            if ab_r.returncode == 0:
                parts = ab_r.stdout.strip().split()
                if len(parts) == 2:
                    behind, ahead = int(parts[0]), int(parts[1])

        # stash count
        stash_r = self._run("stash", "list", check=False)
        stash_count = len([l for l in stash_r.stdout.splitlines() if l])

        # dirty?
        dirty_r = self._run("status", "--porcelain", check=False)
        is_dirty = bool(dirty_r.stdout.strip())

        return GitRepo(
            path=self.repo_path,
            name=Path(self.repo_path).name,
            current_branch=branch,
            is_bare=is_bare,
            has_remote=has_remote,
            remotes=list(dict.fromkeys(remote_list)),  # deduplicate, keep order
            ahead=ahead,
            behind=behind,
            stash_count=stash_count,
            is_dirty=is_dirty,
        )


# ══════════════════════════════════════════════════════════════════════════
# Repository discovery
# ══════════════════════════════════════════════════════════════════════════

def discover_repos(
    search_dirs: Optional[List[str]] = None,
    max_depth: int = 4,
) -> List[GitRepo]:
    """
    Walk search_dirs up to max_depth, find .git directories.
    Returns list of GitRepo (sorted by name).
    """
    if not _GIT_AVAILABLE:
        return []

    dirs = search_dirs or getattr(Config, "GIT_SEARCH_DIRS", ["~"])
    found: List[GitRepo] = []
    seen: Set[str] = set()

    def _walk(base: Path, depth: int) -> None:
        if depth < 0 or not base.is_dir():
            return
        git_dir = base / ".git"
        if git_dir.exists():
            abs_path = str(base.resolve())
            if abs_path not in seen:
                seen.add(abs_path)
                with contextlib.suppress(Exception):
                    runner = GitRunner(abs_path)
                    if runner.is_repo():
                        found.append(runner.repo_info())
            return  # don't recurse into git repos
        # recurse
        try:
            for child in sorted(base.iterdir()):
                if child.is_dir() and not child.name.startswith("."):
                    _walk(child, depth - 1)
        except PermissionError:
            pass

    for d in dirs:
        _walk(Path(d).expanduser().resolve(), max_depth)

    # also add CWD if it's a repo
    cwd = Path.cwd().resolve()
    if str(cwd) not in seen:
        with contextlib.suppress(Exception):
            runner = GitRunner(str(cwd))
            if runner.is_repo():
                found.append(runner.repo_info())

    return sorted(found, key=lambda r: r.name.lower())


# ══════════════════════════════════════════════════════════════════════════
# GitUI — terminal rendering layer
# ══════════════════════════════════════════════════════════════════════════

class GitUI:
    """All terminal I/O for git_tools."""

    def __init__(self) -> None:
        self._runner: Optional[GitRunner] = None
        self._repo: Optional[GitRepo] = None

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _term_width() -> int:
        try:
            return os.get_terminal_size().columns
        except OSError:
            return 100

    @classmethod
    def _divider(cls, char: str = "─") -> None:
        print(f"{Ansi.DIM}{char * cls._term_width()}{Ansi.RESET}")

    @staticmethod
    def _colour_diff_line(line: str) -> str:
        if line.startswith("+++") or line.startswith("---"):
            return f"{Ansi.BOLD}{line}{Ansi.RESET}"
        if line.startswith("+"):
            return f"{Ansi.BRIGHT_GREEN}{line}{Ansi.RESET}"
        if line.startswith("-"):
            return f"{Ansi.RED}{line}{Ansi.RESET}"
        if line.startswith("@@"):
            return f"{Ansi.CYAN}{line}{Ansi.RESET}"
        if line.startswith("diff ") or line.startswith("index "):
            return f"{Ansi.BOLD}{line}{Ansi.RESET}"
        return f"{Ansi.DIM}{line}{Ansi.RESET}"

    @staticmethod
    def _render_commit_oneline(c: GitCommit, width: int = 100) -> str:
        refs_part = ""
        if c.refs:
            refs_col = Ansi.YELLOW if "HEAD" in c.refs else Ansi.CYAN
            refs_part = f" {refs_col}({c.refs}){Ansi.RESET}"

        date = c.author_date[:10]
        auth = c.author_name[:14]
        subj_width = max(20, width - 50)
        subj = c.short_subject[:subj_width]

        return (
            f"  {Ansi.YELLOW}{c.short_hash}{Ansi.RESET}"
            f"{refs_part}"
            f" {Ansi.DIM}{date}{Ansi.RESET}"
            f" {Ansi.CYAN}{auth:<14}{Ansi.RESET}"
            f" {subj}"
        )

    @staticmethod
    def _status_icon(s: FileStatus) -> str:
        icons = {
            FileStatus.MODIFIED:  f"{Ansi.YELLOW}M{Ansi.RESET}",
            FileStatus.ADDED:     f"{Ansi.BRIGHT_GREEN}A{Ansi.RESET}",
            FileStatus.DELETED:   f"{Ansi.RED}D{Ansi.RESET}",
            FileStatus.RENAMED:   f"{Ansi.CYAN}R{Ansi.RESET}",
            FileStatus.COPIED:    f"{Ansi.CYAN}C{Ansi.RESET}",
            FileStatus.UNMERGED:  f"{Ansi.BRIGHT_RED}U{Ansi.RESET}",
            FileStatus.UNTRACKED: f"{Ansi.DIM}?{Ansi.RESET}",
        }
        return icons.get(s, " ")

    def _require_runner(self) -> GitRunner:
        if self._runner is None:
            raise GitRepoError("No repository selected. Use 'Open Repo' first.")
        return self._runner

    def _repo_header(self) -> str:
        if self._repo is None:
            return "Git Tools"
        dirty = f" {Ansi.YELLOW}[dirty]{Ansi.RESET}" if self._repo.is_dirty else ""
        ahead = (
            f" {Ansi.BRIGHT_GREEN}↑{self._repo.ahead}{Ansi.RESET}"
            if self._repo.ahead else ""
        )
        behind = (
            f" {Ansi.RED}↓{self._repo.behind}{Ansi.RESET}"
            if self._repo.behind else ""
        )
        stash = (
            f" {Ansi.CYAN}≡{self._repo.stash_count}{Ansi.RESET}"
            if self._repo.stash_count else ""
        )
        return (
            f"🌿  {Ansi.BOLD}{self._repo.name}{Ansi.RESET}  "
            f"{Ansi.CYAN}{self._repo.current_branch}{Ansi.RESET}"
            f"{dirty}{ahead}{behind}{stash}"
        )

    # ── repo picker ───────────────────────────────────────────────────────

    def _open_repo(self) -> bool:
        """Discover repos and let user pick one, or type a path."""
        UI.info("Searching for repositories…")
        repos = discover_repos()

        if repos:
            UI.header(f"Found {len(repos)} repository/ies")
            for i, r in enumerate(repos, 1):
                dirty = f"{Ansi.YELLOW}*{Ansi.RESET}" if r.is_dirty else " "
                ab = ""
                if r.ahead:
                    ab += f" {Ansi.BRIGHT_GREEN}↑{r.ahead}{Ansi.RESET}"
                if r.behind:
                    ab += f" {Ansi.RED}↓{r.behind}{Ansi.RESET}"
                print(
                    f"  {Ansi.DIM}{i:>3}.{Ansi.RESET}  "
                    f"{dirty} {Ansi.BOLD}{r.name:<28}{Ansi.RESET}"
                    f"  {Ansi.CYAN}{r.current_branch:<22}{Ansi.RESET}"
                    f"{ab}"
                    f"  {Ansi.DIM}{r.path}{Ansi.RESET}"
                )
            self._divider()

        raw = UI.prompt("Repo # or path (blank=cancel):").strip()
        if not raw:
            return False

        chosen_path: Optional[str] = None
        if raw.isdigit() and repos:
            idx = int(raw) - 1
            if 0 <= idx < len(repos):
                chosen_path = repos[idx].path
            else:
                UI.error("Index out of range")
                return False
        else:
            p = Path(raw).expanduser().resolve()
            if p.is_dir():
                chosen_path = str(p)
            else:
                UI.error(f"Directory not found: {raw}")
                return False

        runner = GitRunner(chosen_path)
        if not runner.is_repo():
            UI.error(f"Not a git repository: {chosen_path}")
            return False

        self._runner = runner
        self._repo = runner.repo_info()
        UI.success(
            f"Opened {self._repo.name!r} on branch {self._repo.current_branch!r}"
        )
        return True

    # ── branch picker ─────────────────────────────────────────────────────

    def _pick_branch(
        self, include_remote: bool = False, prompt: str = "Branch"
    ) -> Optional[str]:
        runner = self._require_runner()
        branches = runner.list_branches(all_=include_remote)
        if not branches:
            UI.warning("No branches found.")
            return None
        for i, (name, current) in enumerate(branches, 1):
            cur_mark = f"{Ansi.BRIGHT_GREEN}*{Ansi.RESET}" if current else " "
            print(f"  {Ansi.DIM}{i:>3}.{Ansi.RESET} {cur_mark} {name}")
        raw = UI.prompt(f"{prompt} # or name (blank=cancel):").strip()
        if not raw:
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(branches):
                return branches[idx][0]
        return raw or None

    # ── commit picker ─────────────────────────────────────────────────────

    def _pick_commit(self, commits: List[GitCommit]) -> Optional[GitCommit]:
        w = self._term_width()
        for i, c in enumerate(commits, 1):
            print(f"  {Ansi.DIM}{i:>3}.{Ansi.RESET}{self._render_commit_oneline(c, w)}")
        raw = UI.prompt("Commit # or hash (blank=cancel):").strip()
        if not raw:
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(commits):
                return commits[idx]
        for c in commits:
            if c.hash.startswith(raw) or c.short_hash == raw:
                return c
        UI.error(f"No match: {raw!r}")
        return None

    # ══════════════════════════════════════════════════════════════════════
    # MAIN MENU
    # ══════════════════════════════════════════════════════════════════════

    def run(self) -> None:
        while True:
            UI.header(self._repo_header() if self._repo else "🌿  Git Tools")
            menu_items = [
                ("O", "Open Repository"),
                ("─", "─── Repository ──────────────────"),
                ("1", "Status"),
                ("2", "Log / History"),
                ("3", "Diff"),
                ("4", "Branches"),
                ("5", "Stash"),
                ("6", "Cherry-pick"),
                ("7", "Remotes  (fetch / pull / push)"),
                ("8", "Tags"),
                ("9", "Blame"),
                ("G", "Graph  (commit tree)"),
                ("C", "Config"),
                ("0", "Back"),
            ]
            for key, label in menu_items:
                if key == "─":
                    print(f"  {Ansi.DIM}{label}{Ansi.RESET}")
                else:
                    print(f"  {Ansi.CYAN}{key}{Ansi.RESET}  {label}")
            self._divider()
            choice = UI.prompt("Choose:").strip().upper()

            if choice == "0":
                break
            elif choice == "O":
                self._open_repo()
                continue

            if self._runner is None:
                UI.warning("No repo open. Press O to open one first.")
                continue

            dispatch: Dict[str, Callable[[], None]] = {
                "1": self._menu_status,
                "2": self._menu_log,
                "3": self._menu_diff,
                "4": self._menu_branches,
                "5": self._menu_stash,
                "6": self._menu_cherry_pick,
                "7": self._menu_remotes,
                "8": self._menu_tags,
                "9": self._menu_blame,
                "G": self._menu_graph,
                "C": self._menu_config,
            }
            handler = dispatch.get(choice)
            if handler:
                try:
                    handler()
                    # refresh repo info after mutating operations
                    if self._runner:
                        self._repo = self._runner.repo_info()
                except GitConflictError as exc:
                    UI.error(f"Conflicts: {exc}")
                    UI.pause()
                except GitCommandError as exc:
                    UI.error(str(exc))
                    UI.pause()
                except GitRepoError as exc:
                    UI.error(str(exc))
                    UI.pause()
                except KeyboardInterrupt:
                    print()
                    UI.info("Interrupted.")
            else:
                UI.warning("Unknown option")

    # ══════════════════════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════════════════════

    def _menu_status(self) -> None:
        runner = self._require_runner()
        s = runner.status()
        UI.header(f"Status: {s.branch}")

        # branch / tracking info
        if s.upstream:
            ab = ""
            if s.ahead:
                ab += f"  {Ansi.BRIGHT_GREEN}↑ {s.ahead} ahead{Ansi.RESET}"
            if s.behind:
                ab += f"  {Ansi.RED}↓ {s.behind} behind{Ansi.RESET}"
            print(f"  Tracking  {Ansi.CYAN}{s.upstream}{Ansi.RESET}{ab}")
        if s.stash_count:
            print(f"  Stashed   {Ansi.CYAN}{s.stash_count}{Ansi.RESET} entries")

        if s.is_clean:
            UI.success("Working tree is clean.")
        else:
            def _section(title: str, entries: List[StatusEntry], icon_side: str = "index") -> None:
                if not entries:
                    return
                print(f"\n  {Ansi.BOLD}{title}{Ansi.RESET}  ({len(entries)})")
                for e in entries:
                    st = e.index_status if icon_side == "index" else e.work_status
                    icon = self._status_icon(st)
                    orig = f"  ← {Ansi.DIM}{e.orig_path}{Ansi.RESET}" if e.orig_path else ""
                    print(f"    {icon}  {e.path}{orig}")

            _section("Staged", s.staged)
            _section("Unstaged", s.unstaged, "work")
            _section("Untracked", s.untracked)
            _section("Unmerged (CONFLICTS)", s.unmerged)

        if s.last_commit:
            print(f"\n  {Ansi.BOLD}Last commit{Ansi.RESET}")
            print(self._render_commit_oneline(s.last_commit, self._term_width()))

        self._divider()
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # LOG
    # ══════════════════════════════════════════════════════════════════════

    def _menu_log(self) -> None:
        runner = self._require_runner()
        limit_raw = UI.prompt(
            f"Commits to show [{getattr(Config, 'GIT_LOG_LIMIT', 50)}]:"
        ).strip()
        limit = int(limit_raw) if limit_raw.isdigit() else getattr(Config, "GIT_LOG_LIMIT", 50)

        author = UI.prompt("Filter by author (blank=all):").strip() or None
        grep = UI.prompt("Filter by message (blank=all):").strip() or None
        branch_raw = UI.prompt("Branch/ref [HEAD]:").strip() or "HEAD"
        no_merges = UI.confirm("Exclude merge commits?")

        commits = runner.log(
            limit=limit, ref=branch_raw, author=author,
            grep=grep, no_merges=no_merges,
        )
        UI.header(f"Log: {branch_raw}  ({len(commits)} commits)")
        self._divider()
        w = self._term_width()
        for c in commits:
            print(self._render_commit_oneline(c, w))

        self._divider()
        if commits and UI.confirm("Show full details of a commit?"):
            chosen = self._pick_commit(commits)
            if chosen:
                self._show_commit_detail(runner, chosen)
        UI.pause()

    def _show_commit_detail(self, runner: GitRunner, c: GitCommit) -> None:
        UI.header(f"Commit {c.short_hash}")
        pairs = [
            ("Hash",    c.hash),
            ("Author",  f"{c.author_name} <{c.author_email}>"),
            ("Date",    c.author_date),
            ("Subject", c.subject),
        ]
        for k, v in pairs:
            print(f"  {Ansi.CYAN}{k:<10}{Ansi.RESET} {v}")
        if c.body:
            print(f"\n  {c.body}")
        self._divider()
        diff_text = runner.show(c.hash)
        for line in diff_text.splitlines():
            print(self._colour_diff_line(line))

    # ══════════════════════════════════════════════════════════════════════
    # DIFF
    # ══════════════════════════════════════════════════════════════════════

    def _menu_diff(self) -> None:
        runner = self._require_runner()
        print(
            f"\n  {Ansi.CYAN}1{Ansi.RESET} Working tree vs index\n"
            f"  {Ansi.CYAN}2{Ansi.RESET} Staged (index vs HEAD)\n"
            f"  {Ansi.CYAN}3{Ansi.RESET} Two commits / branches\n"
            f"  {Ansi.CYAN}4{Ansi.RESET} Diff stat only\n"
        )
        self._divider()
        choice = UI.prompt("Choice:").strip()

        stat_only = (choice == "4")
        ctx_raw = UI.prompt(
            f"Context lines [{getattr(Config, 'GIT_DIFF_CONTEXT', 3)}]:"
        ).strip()
        ctx = int(ctx_raw) if ctx_raw.isdigit() else getattr(Config, "GIT_DIFF_CONTEXT", 3)
        path_filter = UI.prompt("Limit to file/path (blank=all):").strip() or None

        if choice == "1":
            diff_text = runner.diff(context=ctx, path=path_filter, stat_only=stat_only)
        elif choice == "2":
            diff_text = runner.diff(cached=True, context=ctx, path=path_filter, stat_only=stat_only)
        elif choice in ("3", "4"):
            r1 = UI.prompt("Ref1 (e.g. HEAD~3, branch, hash):").strip() or "HEAD~1"
            r2 = UI.prompt("Ref2 (blank=HEAD):").strip() or "HEAD"
            diff_text = runner.diff(
                ref1=r1, ref2=r2, context=ctx,
                path=path_filter, stat_only=(choice == "4")
            )
        else:
            diff_text = runner.diff(context=ctx)

        UI.header("Diff")
        self._divider()
        if not diff_text.strip():
            UI.info("No differences.")
        else:
            for line in diff_text.splitlines():
                print(self._colour_diff_line(line))
        self._divider()
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # BRANCHES
    # ══════════════════════════════════════════════════════════════════════

    def _menu_branches(self) -> None:
        runner = self._require_runner()
        while True:
            branches = runner.list_branches(all_=True)
            UI.header(f"Branches  ({len(branches)} total)")
            for i, (name, cur) in enumerate(branches, 1):
                mark = f"{Ansi.BRIGHT_GREEN}●{Ansi.RESET}" if cur else f"{Ansi.DIM}○{Ansi.RESET}"
                is_remote = name.startswith("remotes/") or name.startswith("origin/")
                col = Ansi.DIM if is_remote else Ansi.RESET
                print(f"  {Ansi.DIM}{i:>3}.{Ansi.RESET} {mark} {col}{name}{Ansi.RESET}")
            self._divider()
            print(
                f"  {Ansi.CYAN}C{Ansi.RESET}heckout  "
                f"{Ansi.CYAN}N{Ansi.RESET}ew  "
                f"{Ansi.CYAN}D{Ansi.RESET}elete  "
                f"{Ansi.CYAN}M{Ansi.RESET}erge  "
                f"{Ansi.CYAN}R{Ansi.RESET}ebase  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            self._divider()
            cmd = UI.prompt("Action:").strip().upper()

            if cmd == "0":
                break
            elif cmd == "C":
                branch = self._pick_branch()
                if branch:
                    out = runner.checkout(branch)
                    UI.success(f"Checked out {branch!r}")
                    if out.strip():
                        print(f"  {Ansi.DIM}{out.strip()}{Ansi.RESET}")
                    self._repo = runner.repo_info()
            elif cmd == "N":
                name = UI.prompt("New branch name:").strip()
                if not name:
                    continue
                start = UI.prompt("Start point [HEAD]:").strip() or "HEAD"
                checkout_now = UI.confirm(f"Checkout {name!r} immediately?")
                if checkout_now:
                    runner.checkout(name, create=True)
                else:
                    runner.create_branch(name, start)
                UI.success(f"Branch {name!r} created")
                self._repo = runner.repo_info()
            elif cmd == "D":
                branch = self._pick_branch(prompt="Delete branch")
                if branch:
                    force = UI.confirm(f"Force delete {branch!r}?")
                    runner.delete_branch(branch, force=force)
                    UI.success(f"Deleted branch {branch!r}")
            elif cmd == "M":
                branch = self._pick_branch(include_remote=True, prompt="Merge branch into HEAD")
                if branch:
                    no_ff = UI.confirm("No fast-forward (--no-ff)?")
                    out = runner.merge(branch, no_ff=no_ff)
                    UI.success(f"Merged {branch!r}")
                    print(f"  {Ansi.DIM}{out.strip()[:200]}{Ansi.RESET}")
            elif cmd == "R":
                onto = UI.prompt("Rebase onto (branch/ref):").strip()
                if onto:
                    out = runner.rebase(onto)
                    UI.success(f"Rebased onto {onto!r}")
                    print(f"  {Ansi.DIM}{out.strip()[:200]}{Ansi.RESET}")

    # ══════════════════════════════════════════════════════════════════════
    # STASH
    # ══════════════════════════════════════════════════════════════════════

    def _menu_stash(self) -> None:
        runner = self._require_runner()
        while True:
            entries = runner.stash_list()
            UI.header(f"Stash  ({len(entries)} entries)")
            if entries:
                for e in entries:
                    print(
                        f"  {Ansi.CYAN}{e.ref:<14}{Ansi.RESET} "
                        f"{Ansi.DIM}{e.date:<20}{Ansi.RESET} "
                        f"{Ansi.BOLD}{e.branch:<20}{Ansi.RESET} "
                        f"{e.message[:50]}"
                    )
            else:
                UI.info("Stash is empty.")
            self._divider()
            print(
                f"  {Ansi.CYAN}P{Ansi.RESET}ush  "
                f"{Ansi.CYAN}O{Ansi.RESET}pp  "
                f"{Ansi.CYAN}A{Ansi.RESET}pply  "
                f"{Ansi.CYAN}S{Ansi.RESET}how  "
                f"{Ansi.CYAN}D{Ansi.RESET}rop  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            self._divider()
            cmd = UI.prompt("Action:").strip().upper()

            if cmd == "0":
                break
            elif cmd == "P":
                msg = UI.prompt("Stash message (blank=auto):").strip() or None
                untracked = UI.confirm("Include untracked files?")
                out = runner.stash_push(message=msg, include_untracked=untracked)
                UI.success(out or "Stashed.")
            elif cmd in ("O", "A"):
                if not entries:
                    UI.warning("Nothing in stash.")
                    continue
                raw = UI.prompt("Stash index [0]:").strip()
                idx = int(raw) if raw.isdigit() else 0
                if cmd == "O":
                    out = runner.stash_pop(idx)
                    UI.success(f"Popped stash@{{{idx}}}")
                else:
                    out = runner.stash_apply(idx)
                    UI.success(f"Applied stash@{{{idx}}}")
                if out:
                    print(f"  {Ansi.DIM}{out[:200]}{Ansi.RESET}")
            elif cmd == "S":
                if not entries:
                    UI.warning("Nothing in stash.")
                    continue
                raw = UI.prompt("Stash index [0]:").strip()
                idx = int(raw) if raw.isdigit() else 0
                stat_only = UI.confirm("Stat only (no full diff)?")
                diff_text = runner.stash_show(idx, stat_only=stat_only)
                self._divider()
                for line in diff_text.splitlines():
                    print(self._colour_diff_line(line))
                self._divider()
                UI.pause()
            elif cmd == "D":
                if not entries:
                    UI.warning("Nothing to drop.")
                    continue
                raw = UI.prompt("Stash index to drop:").strip()
                idx = int(raw) if raw.isdigit() else 0
                if UI.confirm(f"Drop stash@{{{idx}}}?"):
                    runner.stash_drop(idx)
                    UI.success(f"Dropped stash@{{{idx}}}")

    # ══════════════════════════════════════════════════════════════════════
    # CHERRY-PICK
    # ══════════════════════════════════════════════════════════════════════

    def _menu_cherry_pick(self) -> None:
        runner = self._require_runner()
        UI.header("Cherry-pick")

        limit = getattr(Config, "GIT_LOG_LIMIT", 50)
        all_branches = UI.confirm("Show commits from all branches?")
        commits = runner.log(limit=limit, all_branches=all_branches, no_merges=True)

        if not commits:
            UI.info("No commits to cherry-pick.")
            UI.pause()
            return

        chosen = self._pick_commit(commits)
        if chosen is None:
            return

        UI.info(f"Cherry-picking: {chosen.short_hash} — {chosen.short_subject}")
        no_commit = UI.confirm("Stage only, don't commit (--no-commit)?")

        try:
            out = runner.cherry_pick(chosen.hash, no_commit=no_commit)
            if out.strip():
                print(f"  {Ansi.DIM}{out.strip()[:300]}{Ansi.RESET}")
            UI.success(f"Cherry-picked {chosen.short_hash}")
        except GitConflictError as exc:
            UI.error("Cherry-pick produced conflicts!")
            print(f"  {Ansi.DIM}{str(exc)[:400]}{Ansi.RESET}")
            action = UI.prompt("[A]bort / [C]ontinue after fixing conflicts:").strip().upper()
            if action == "A":
                runner.cherry_pick_abort()
                UI.info("Cherry-pick aborted.")
            elif action == "C":
                out = runner.cherry_pick_continue()
                UI.success("Cherry-pick continued.")
                print(f"  {Ansi.DIM}{out.strip()[:200]}{Ansi.RESET}")
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # REMOTES
    # ══════════════════════════════════════════════════════════════════════

    def _menu_remotes(self) -> None:
        runner = self._require_runner()
        while True:
            remotes = runner.remotes()
            UI.header(f"Remotes  ({len(set(r[0] for r in remotes))} total)")
            for name, url, rtype in remotes:
                print(
                    f"  {Ansi.CYAN}{name:<12}{Ansi.RESET} "
                    f"{Ansi.DIM}{rtype:<6}{Ansi.RESET} "
                    f"{url}"
                )
            self._divider()
            print(
                f"  {Ansi.CYAN}F{Ansi.RESET}etch  "
                f"{Ansi.CYAN}P{Ansi.RESET}ull  "
                f"{Ansi.CYAN}U{Ansi.RESET}pload (push)  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            self._divider()
            cmd = UI.prompt("Action:").strip().upper()

            if cmd == "0":
                break
            remote_names = list(dict.fromkeys(r[0] for r in remotes)) or ["origin"]
            remote_str = "/".join(remote_names[:3])

            if cmd == "F":
                remote = UI.prompt(f"Remote [{remote_names[0]}]:").strip() or remote_names[0]
                prune = UI.confirm("Prune deleted remote branches?")
                UI.info(f"Fetching from {remote!r}…")
                out = runner.fetch(remote, prune=prune)
                UI.success(f"Fetched {remote!r}")
                if out.strip():
                    print(f"  {Ansi.DIM}{out.strip()[:300]}{Ansi.RESET}")
            elif cmd == "P":
                remote = UI.prompt(f"Remote [{remote_names[0]}]:").strip() or remote_names[0]
                rebase = UI.confirm("Rebase instead of merge?")
                UI.info(f"Pulling from {remote!r}…")
                out = runner.pull(remote, rebase=rebase)
                UI.success("Pull complete")
                if out.strip():
                    print(f"  {Ansi.DIM}{out.strip()[:300]}{Ansi.RESET}")
            elif cmd == "U":
                remote = UI.prompt(f"Remote [{remote_names[0]}]:").strip() or remote_names[0]
                branch = self._repo.current_branch if self._repo else ""
                force = UI.confirm("Force push? (--force-with-lease)")
                push_tags = UI.confirm("Include tags?")
                set_up = UI.confirm("Set upstream (--set-upstream)?")
                UI.info(f"Pushing to {remote!r}…")
                out = runner.push(
                    remote, branch=branch,
                    force=force, tags=push_tags, set_upstream=set_up,
                )
                UI.success("Push complete")
                if out.strip():
                    print(f"  {Ansi.DIM}{out.strip()[:300]}{Ansi.RESET}")

    # ══════════════════════════════════════════════════════════════════════
    # TAGS
    # ══════════════════════════════════════════════════════════════════════

    def _menu_tags(self) -> None:
        runner = self._require_runner()
        while True:
            pattern = UI.prompt("Filter pattern (blank=all):").strip() or None
            tags = runner.tags(pattern=pattern)
            UI.header(f"Tags  ({len(tags)} found)")
            if tags:
                for name, msg in tags[:50]:
                    print(
                        f"  {Ansi.YELLOW}{name:<30}{Ansi.RESET} "
                        f"{Ansi.DIM}{msg[:50]}{Ansi.RESET}"
                    )
                if len(tags) > 50:
                    UI.info(f"… {len(tags) - 50} more")
            else:
                UI.info("No tags found.")
            self._divider()
            print(
                f"  {Ansi.CYAN}C{Ansi.RESET}reate  "
                f"{Ansi.CYAN}D{Ansi.RESET}elete  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            cmd = UI.prompt("Action:").strip().upper()
            if cmd == "0":
                break
            elif cmd == "C":
                name = UI.prompt("Tag name:").strip()
                if not name:
                    continue
                msg = UI.prompt("Annotation message (blank=lightweight):").strip() or None
                ref = UI.prompt("Ref [HEAD]:").strip() or "HEAD"
                runner.tag_create(name, message=msg, ref=ref)
                UI.success(f"Tag {name!r} created")
            elif cmd == "D":
                name = UI.prompt("Tag to delete:").strip()
                if name and UI.confirm(f"Delete tag {name!r}?"):
                    runner.tag_delete(name)
                    UI.success(f"Deleted tag {name!r}")

    # ══════════════════════════════════════════════════════════════════════
    # BLAME
    # ══════════════════════════════════════════════════════════════════════

    def _menu_blame(self) -> None:
        runner = self._require_runner()
        UI.header("Blame")
        path = UI.prompt("File path (relative to repo root):").strip()
        if not path:
            return
        start_raw = UI.prompt("Start line [1]:").strip()
        end_raw = UI.prompt("End line (blank=+50):").strip()
        start = int(start_raw) if start_raw.isdigit() else 1
        end = int(end_raw) if end_raw.isdigit() else start + 50

        entries = runner.blame(path, start=start, end=end)
        UI.header(f"Blame: {path}  L{start}–{end}")
        self._divider()
        if not entries:
            UI.info("No blame data (file may not be committed).")
        else:
            for e in entries:
                print(
                    f"  {Ansi.YELLOW}{e.hash:<9}{Ansi.RESET}"
                    f"  {Ansi.DIM}{e.date:<11}{Ansi.RESET}"
                    f"  {Ansi.CYAN}{e.author[:16]:<16}{Ansi.RESET}"
                    f"  {Ansi.DIM}{e.line_no:>4}{Ansi.RESET}"
                    f"  {e.content}"
                )
        self._divider()
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # GRAPH
    # ══════════════════════════════════════════════════════════════════════

    def _menu_graph(self) -> None:
        runner = self._require_runner()
        limit_raw = UI.prompt("Commits to graph [30]:").strip()
        limit = int(limit_raw) if limit_raw.isdigit() else 30
        all_ = UI.confirm("Show all branches?")

        graph_text = runner.graph(limit=limit, all_=all_)
        UI.header(f"Commit Graph  (last {limit})")
        self._divider()
        for line in graph_text.splitlines():
            # inject basic colour hints for branches/HEAD
            line = re.sub(r"\(([^)]+)\)", lambda m: f"{Ansi.YELLOW}({m.group(1)}){Ansi.RESET}", line)
            line = re.sub(r"\b([0-9a-f]{7,8})\b",
                          lambda m: f"{Ansi.CYAN}{m.group(1)}{Ansi.RESET}", line)
            print(f"  {line}")
        self._divider()
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════
    # CONFIG
    # ══════════════════════════════════════════════════════════════════════

    def _menu_config(self) -> None:
        runner = self._require_runner()
        cfg = runner.config_list(local_only=False)
        UI.header(f"Git Config  ({len(cfg)} entries)")
        self._divider()
        categories: Dict[str, List[Tuple[str, str]]] = collections.defaultdict(list)
        for k, v in sorted(cfg.items()):
            section = k.split(".")[0]
            categories[section].append((k, v))
        for section, pairs in sorted(categories.items()):
            print(f"\n  {Ansi.BOLD}[{section}]{Ansi.RESET}")
            for k, v in pairs:
                print(f"    {Ansi.CYAN}{k:<35}{Ansi.RESET} {v}")
        self._divider()
        UI.pause()


# ══════════════════════════════════════════════════════════════════════════
# Module registry entry point
# ══════════════════════════════════════════════════════════════════════════

def register(registry: Any) -> None:
    """Called by modules/__init__.py ModuleRegistry."""
    registry.register(
        key="git_tools",
        label="Git Tools",
        description=(
            "Full Git management: status, log, diff, branches, stash, "
            "cherry-pick, remotes, tags, blame, graph."
        ),
        entry=run,
        health=health_check,
        tags=["git", "vcs", "devops"],
    )


def run() -> None:
    """Module entry point called by terminal router."""
    try:
        GitUI().run()
    except GitNotFoundError as exc:
        UI.error(str(exc))
        UI.info("Install git: https://git-scm.com/downloads")
        UI.pause()
    except KeyboardInterrupt:
        print()
        UI.info("Git Tools closed.")


def health_check() -> Dict[str, Any]:
    """Called by ModuleRegistry."""
    result: Dict[str, Any] = {
        "status": "ok",
        "git_version": "",
        "repos_found": 0,
        "error": None,
    }
    if not _GIT_AVAILABLE:
        result["status"] = "unavailable"
        result["error"] = "git not found on PATH"
        return result
    try:
        r = subprocess.run(
            [_GIT_BIN, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        result["git_version"] = r.stdout.strip()
        repos = discover_repos()
        result["repos_found"] = len(repos)
    except Exception as exc:
        result["status"] = "degraded"
        result["error"] = str(exc)
    return result


# ══════════════════════════════════════════════════════════════════════════
# Standalone execution
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    print("Git Tools — standalone mode")
    hc = health_check()
    print(f"Health: {hc}")
    if hc["status"] in ("ok", "degraded"):
        run()
    else:
        print(f"git unavailable: {hc['error']}")
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════
# Plugin registry metadata (required by plugins/__init__.py PluginRegistry)
# ══════════════════════════════════════════════════════════════════════════

PLUGIN_NAME        = "Git Tools"
PLUGIN_VERSION     = "1.0.0"
PLUGIN_DESCRIPTION = "Git repository management: log, diff, branches, stash, blame, bisect"
PLUGIN_AUTHOR      = "local_os project"
PLUGIN_TAGS: list  = ["git", "vcs", "developer"]


def main() -> None:
    """Entry-point called by PluginRegistry.invoke()."""
    run()