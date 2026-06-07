"""
docker_manager.py — Docker Container & Image Management Module
═══════════════════════════════════════════════════════════════
Part of local_os toolkit. Provides full lifecycle management of Docker
containers, images, volumes, networks, and real-time stats streaming.

Architecture:
  DockerClient      — thin wrapper around docker SDK / docker CLI fallback
  DockerManager     — business logic, error handling, audit logging
  DockerUI          — terminal rendering (uses core.ui primitives)
  register(registry) — module entry point called by ModuleRegistry

Requires:
  pip install docker>=7.0.0          # python docker SDK
  Docker daemon running (unix socket or TCP)

Fallback:
  If docker SDK unavailable, falls back to subprocess docker CLI.
  All public methods work in both modes transparently.

Author  : local_os project
License : MIT
"""

from __future__ import annotations

# ── stdlib ────────────────────────────────────────────────────────────────────
import contextlib
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    pass

# ── optional docker SDK ───────────────────────────────────────────────────────
try:
    import docker  # type: ignore
    import docker.errors  # type: ignore
    from docker.models.containers import Container  # type: ignore
    from docker.models.images import Image  # type: ignore

    _SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SDK_AVAILABLE = False
    docker = None  # type: ignore

# ── project imports (graceful if running standalone) ─────────────────────────
try:
    from core.ui import Ansi, UI  # type: ignore
    from core.config import Config  # type: ignore
except ImportError:
    # ── minimal stubs for standalone testing ──────────────────────────────────
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
            print(f"\n{'═' * 60}")
            print(f"  {title}")
            print("═" * 60)

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
            input("  ⏎  Press Enter to continue…")

    class Config:  # type: ignore  # noqa: E302
        DOCKER_TIMEOUT: int = 30
        DOCKER_LOG_LINES: int = 100
        DOCKER_STATS_INTERVAL: float = 2.0
        AUDIT_ENABLED: bool = True

# ── logger ────────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── constants ─────────────────────────────────────────────────────────────────
_DOCKER_BIN: str = shutil.which("docker") or "docker"
_COMPOSE_BIN: str = shutil.which("docker-compose") or "docker-compose"
_COMPOSE_V2: str = "docker compose"  # docker compose v2 (plugin)

_BYTE_UNITS: Tuple[str, ...] = ("B", "KB", "MB", "GB", "TB")
_NANO_CPU: float = 1e9  # docker reports CPU in nanoseconds / nano-CPUs

# container state colours
_STATE_COLOUR: Dict[str, str] = {
    "running": Ansi.BRIGHT_GREEN,
    "exited": Ansi.RED,
    "paused": Ansi.YELLOW,
    "restarting": Ansi.CYAN,
    "dead": Ansi.RED,
    "created": Ansi.DIM,
    "removing": Ansi.MAGENTA,
}


# ══════════════════════════════════════════════════════════════════════════════
# Data-transfer objects
# ══════════════════════════════════════════════════════════════════════════════

class ContainerState(str, Enum):
    RUNNING = "running"
    EXITED = "exited"
    PAUSED = "paused"
    RESTARTING = "restarting"
    DEAD = "dead"
    CREATED = "created"
    REMOVING = "removing"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ContainerInfo:
    id: str
    short_id: str
    name: str
    image: str
    state: ContainerState
    status: str
    created: str
    ports: Dict[str, Any]
    labels: Dict[str, str]
    network_mode: str
    restart_policy: str
    cpu_percent: float = 0.0
    mem_usage_mb: float = 0.0
    mem_limit_mb: float = 0.0
    net_in_mb: float = 0.0
    net_out_mb: float = 0.0
    block_read_mb: float = 0.0
    block_write_mb: float = 0.0


@dataclass(slots=True)
class ImageInfo:
    id: str
    short_id: str
    tags: List[str]
    size_mb: float
    created: str
    architecture: str
    os: str
    author: str
    comment: str
    layers: int


@dataclass(slots=True)
class VolumeInfo:
    name: str
    driver: str
    mountpoint: str
    created: str
    labels: Dict[str, str]
    scope: str


@dataclass(slots=True)
class NetworkInfo:
    id: str
    name: str
    driver: str
    scope: str
    ipam_subnet: str
    containers: List[str]
    internal: bool
    attachable: bool


@dataclass
class DockerStats:
    """Live resource usage snapshot for a single container."""
    container_id: str
    container_name: str
    cpu_percent: float
    mem_usage_mb: float
    mem_limit_mb: float
    mem_percent: float
    net_in_mb: float
    net_out_mb: float
    block_read_mb: float
    block_write_mb: float
    pids: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ══════════════════════════════════════════════════════════════════════════════
# Exceptions
# ══════════════════════════════════════════════════════════════════════════════

class DockerManagerError(RuntimeError):
    """Base exception for all docker_manager errors."""


class DockerDaemonError(DockerManagerError):
    """Docker daemon not reachable."""


class DockerNotFoundError(DockerManagerError):
    """Requested resource not found."""


class DockerOperationError(DockerManagerError):
    """Operation failed on the daemon side."""


# ══════════════════════════════════════════════════════════════════════════════
# Helper utilities
# ══════════════════════════════════════════════════════════════════════════════

def _bytes_to_human(num_bytes: int, precision: int = 2) -> str:
    """Convert raw byte count to human-readable string."""
    val = float(num_bytes)
    for unit in _BYTE_UNITS:
        if abs(val) < 1024.0:
            return f"{val:.{precision}f} {unit}"
        val /= 1024.0
    return f"{val:.{precision}f} PB"


def _bytes_to_mb(num_bytes: int) -> float:
    return round(num_bytes / (1024 ** 2), 2)


def _parse_docker_ts(ts: str) -> str:
    """Normalize Docker ISO-8601 timestamp to local display string."""
    if not ts:
        return "—"
    # Docker sometimes adds nanoseconds; truncate to microseconds
    ts = re.sub(r"(\.\d{6})\d*", r"\1", ts.rstrip("Z")) + "+00:00"
    with contextlib.suppress(ValueError):
        dt = datetime.fromisoformat(ts).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return ts[:19]


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 100


def _run_cli(
    *args: str,
    input_data: Optional[str] = None,
    timeout: int = 60,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run docker CLI and return CompletedProcess.
    Raises DockerOperationError on non-zero exit when check=True.
    """
    cmd = [_DOCKER_BIN, *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
    except FileNotFoundError as exc:
        raise DockerDaemonError(
            "docker binary not found. Install Docker first."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerOperationError(
            f"docker command timed out after {timeout}s: {' '.join(args)}"
        ) from exc

    if check and result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise DockerOperationError(
            f"docker {args[0]} failed (rc={result.returncode}): {stderr}"
        )
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Docker client abstraction (SDK ↔ CLI)
# ══════════════════════════════════════════════════════════════════════════════

class _SDKClient:
    """Adapter around the official docker-py SDK."""

    def __init__(self) -> None:
        if not _SDK_AVAILABLE:
            raise ImportError("docker SDK not installed")
        timeout = getattr(Config, "DOCKER_TIMEOUT", 30)
        try:
            self._cli = docker.from_env(timeout=timeout)
            self._cli.ping()
        except docker.errors.DockerException as exc:
            raise DockerDaemonError(
                f"Cannot connect to Docker daemon: {exc}"
            ) from exc

    # ── container ops ─────────────────────────────────────────────────────────

    def containers(self, all: bool = True) -> List[ContainerInfo]:
        raw = self._cli.containers.list(all=all)
        return [self._map_container(c) for c in raw]

    def get_container(self, id_or_name: str) -> ContainerInfo:
        try:
            c = self._cli.containers.get(id_or_name)
            return self._map_container(c)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(f"Container not found: {id_or_name}") from exc

    def start(self, id_or_name: str) -> None:
        try:
            self._cli.containers.get(id_or_name).start()
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def stop(self, id_or_name: str, timeout: int = 10) -> None:
        try:
            self._cli.containers.get(id_or_name).stop(timeout=timeout)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def restart(self, id_or_name: str, timeout: int = 10) -> None:
        try:
            self._cli.containers.get(id_or_name).restart(timeout=timeout)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def remove_container(
        self, id_or_name: str, force: bool = False, volumes: bool = False
    ) -> None:
        try:
            self._cli.containers.get(id_or_name).remove(force=force, v=volumes)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def pause(self, id_or_name: str) -> None:
        try:
            self._cli.containers.get(id_or_name).pause()
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    def unpause(self, id_or_name: str) -> None:
        try:
            self._cli.containers.get(id_or_name).unpause()
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    def logs(
        self,
        id_or_name: str,
        tail: int = 100,
        follow: bool = False,
        timestamps: bool = True,
    ) -> Union[str, Iterator[str]]:
        try:
            c = self._cli.containers.get(id_or_name)
            raw = c.logs(
                tail=tail,
                follow=follow,
                timestamps=timestamps,
                stream=follow,
            )
            if follow:
                return (line.decode("utf-8", errors="replace").rstrip() for line in raw)
            return raw.decode("utf-8", errors="replace")
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    def exec_run(
        self, id_or_name: str, command: str
    ) -> Tuple[int, str]:
        try:
            c = self._cli.containers.get(id_or_name)
            result = c.exec_run(command, demux=False)
            output = (result.output or b"").decode("utf-8", errors="replace")
            return result.exit_code, output
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    def stats_once(self, id_or_name: str) -> DockerStats:
        try:
            c = self._cli.containers.get(id_or_name)
            raw = c.stats(stream=False)
            return self._parse_stats(raw, c.name)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    def stats_stream(
        self, id_or_name: str
    ) -> Generator[DockerStats, None, None]:
        try:
            c = self._cli.containers.get(id_or_name)
            for raw in c.stats(stream=True, decode=True):
                yield self._parse_stats(raw, c.name)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    # ── image ops ─────────────────────────────────────────────────────────────

    def images(self) -> List[ImageInfo]:
        raw = self._cli.images.list(all=False)
        return [self._map_image(i) for i in raw]

    def pull_image(
        self,
        name: str,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> ImageInfo:
        try:
            for line in self._cli.api.pull(name, stream=True, decode=True):
                if progress_cb and "status" in line:
                    detail = line.get("progressDetail", {})
                    total = detail.get("total")
                    current = detail.get("current")
                    pct = f" {current}/{total}" if total and current else ""
                    progress_cb(f"{line['status']}{pct}")
            img = self._cli.images.get(name)
            return self._map_image(img)
        except docker.errors.ImageNotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def remove_image(
        self, id_or_name: str, force: bool = False
    ) -> None:
        try:
            self._cli.images.remove(id_or_name, force=force)
        except docker.errors.ImageNotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc
        except docker.errors.APIError as exc:
            raise DockerOperationError(str(exc)) from exc

    def prune_images(self) -> Dict[str, Any]:
        return self._cli.images.prune()

    def prune_containers(self) -> Dict[str, Any]:
        return self._cli.containers.prune()

    def prune_volumes(self) -> Dict[str, Any]:
        return self._cli.volumes.prune()

    def inspect_image(self, id_or_name: str) -> Dict[str, Any]:
        try:
            img = self._cli.images.get(id_or_name)
            return img.attrs
        except docker.errors.ImageNotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    # ── volume ops ────────────────────────────────────────────────────────────

    def volumes(self) -> List[VolumeInfo]:
        raw = self._cli.volumes.list()
        return [self._map_volume(v) for v in raw]

    def remove_volume(self, name: str, force: bool = False) -> None:
        try:
            v = self._cli.volumes.get(name)
            v.remove(force=force)
        except docker.errors.NotFound as exc:
            raise DockerNotFoundError(str(exc)) from exc

    # ── network ops ───────────────────────────────────────────────────────────

    def networks(self) -> List[NetworkInfo]:
        raw = self._cli.networks.list()
        return [self._map_network(n) for n in raw]

    # ── mappers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _map_container(c: "Container") -> ContainerInfo:
        attrs = c.attrs or {}
        host_config = attrs.get("HostConfig", {})
        restart = host_config.get("RestartPolicy", {}).get("Name", "no")
        network_mode = host_config.get("NetworkMode", "")
        state_str = (attrs.get("State", {}).get("Status") or "unknown").lower()
        try:
            state = ContainerState(state_str)
        except ValueError:
            state = ContainerState.UNKNOWN

        return ContainerInfo(
            id=attrs.get("Id", c.id or "")[:64],
            short_id=(c.short_id or c.id or "")[:12],
            name=c.name or "—",
            image=(
                c.image.tags[0]
                if c.image and c.image.tags
                else attrs.get("Config", {}).get("Image", "—")
            ),
            state=state,
            status=attrs.get("State", {}).get("Status", "—"),
            created=_parse_docker_ts(attrs.get("Created", "")),
            ports=attrs.get("NetworkSettings", {}).get("Ports", {}),
            labels=attrs.get("Config", {}).get("Labels", {}) or {},
            network_mode=network_mode,
            restart_policy=restart,
        )

    @staticmethod
    def _map_image(i: "Image") -> ImageInfo:
        attrs = i.attrs or {}
        size_bytes = attrs.get("Size", 0)
        config = attrs.get("Config") or {}
        return ImageInfo(
            id=i.id or "",
            short_id=(i.short_id or i.id or "")[:12],
            tags=i.tags or [],
            size_mb=_bytes_to_mb(size_bytes),
            created=_parse_docker_ts(attrs.get("Created", "")),
            architecture=attrs.get("Architecture", "—"),
            os=attrs.get("Os", "—"),
            author=attrs.get("Author", "—"),
            comment=attrs.get("Comment", ""),
            layers=len(attrs.get("RootFS", {}).get("Layers", [])),
        )

    @staticmethod
    def _map_volume(v: Any) -> VolumeInfo:
        attrs = v.attrs or {}
        return VolumeInfo(
            name=attrs.get("Name", v.name or "—"),
            driver=attrs.get("Driver", "local"),
            mountpoint=attrs.get("Mountpoint", "—"),
            created=_parse_docker_ts(attrs.get("CreatedAt", "")),
            labels=attrs.get("Labels", {}) or {},
            scope=attrs.get("Scope", "local"),
        )

    @staticmethod
    def _map_network(n: Any) -> NetworkInfo:
        attrs = n.attrs or {}
        ipam = attrs.get("IPAM", {}) or {}
        configs = ipam.get("Config") or []
        subnet = configs[0].get("Subnet", "—") if configs else "—"
        containers_raw = attrs.get("Containers", {}) or {}
        container_names = [
            v.get("Name", k) for k, v in containers_raw.items()
        ]
        return NetworkInfo(
            id=n.id or "",
            name=n.name or "—",
            driver=attrs.get("Driver", "bridge"),
            scope=attrs.get("Scope", "local"),
            ipam_subnet=subnet,
            containers=container_names,
            internal=attrs.get("Internal", False),
            attachable=attrs.get("Attachable", False),
        )

    @staticmethod
    def _parse_stats(raw: Dict[str, Any], name: str) -> DockerStats:
        # CPU
        cpu_delta = (
            raw.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
            - raw.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        )
        sys_delta = raw.get("cpu_stats", {}).get("system_cpu_usage", 0) - raw.get(
            "precpu_stats", {}
        ).get("system_cpu_usage", 0)
        num_cpus = len(
            raw.get("cpu_stats", {}).get("cpu_usage", {}).get("percpu_usage") or [1]
        )
        cpu_pct = (
            (cpu_delta / sys_delta) * num_cpus * 100.0
            if sys_delta > 0 and cpu_delta > 0
            else 0.0
        )

        # Memory
        mem_stats = raw.get("memory_stats", {})
        mem_usage = mem_stats.get("usage", 0) - mem_stats.get(
            "stats", {}
        ).get("cache", 0)
        mem_limit = mem_stats.get("limit", 1)
        mem_pct = (mem_usage / mem_limit * 100.0) if mem_limit > 0 else 0.0

        # Network
        nets = raw.get("networks", {})
        net_in = sum(v.get("rx_bytes", 0) for v in nets.values())
        net_out = sum(v.get("tx_bytes", 0) for v in nets.values())

        # Block I/O
        bio = raw.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
        block_read = sum(e.get("value", 0) for e in bio if e.get("op") == "Read")
        block_write = sum(e.get("value", 0) for e in bio if e.get("op") == "Write")

        return DockerStats(
            container_id=raw.get("id", "")[:12],
            container_name=name.lstrip("/"),
            cpu_percent=round(cpu_pct, 2),
            mem_usage_mb=round(_bytes_to_mb(mem_usage), 2),
            mem_limit_mb=round(_bytes_to_mb(mem_limit), 2),
            mem_percent=round(mem_pct, 2),
            net_in_mb=round(_bytes_to_mb(net_in), 3),
            net_out_mb=round(_bytes_to_mb(net_out), 3),
            block_read_mb=round(_bytes_to_mb(block_read), 3),
            block_write_mb=round(_bytes_to_mb(block_write), 3),
            pids=raw.get("pids_stats", {}).get("current", 0),
        )


class _CLIClient:
    """
    Fallback adapter that shells out to the docker CLI.
    Supports the same interface as _SDKClient for the subset of operations
    that can be reliably parsed from CLI output.
    """

    def _json(self, *args: str) -> Any:
        r = _run_cli(*args)
        return json.loads(r.stdout.strip() or "[]")

    # ── container ops ─────────────────────────────────────────────────────────

    def containers(self, all: bool = True) -> List[ContainerInfo]:
        fmt = (
            '{"id":"{{.ID}}","name":"{{.Names}}","image":"{{.Image}}",'
            '"state":"{{.State}}","status":"{{.Status}}","created":"{{.CreatedAt}}",'
            '"ports":"{{.Ports}}"}'
        )
        args = ["ps", "--format", fmt]
        if all:
            args.append("-a")
        raw = _run_cli(*args)
        results: List[ContainerInfo] = []
        for line in raw.stdout.strip().splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                d = json.loads(line)
                state_str = d.get("state", "unknown").lower()
                try:
                    state = ContainerState(state_str)
                except ValueError:
                    state = ContainerState.UNKNOWN
                results.append(
                    ContainerInfo(
                        id=d.get("id", ""),
                        short_id=d.get("id", "")[:12],
                        name=d.get("name", "").lstrip("/"),
                        image=d.get("image", "—"),
                        state=state,
                        status=d.get("status", ""),
                        created=d.get("created", ""),
                        ports={},
                        labels={},
                        network_mode="",
                        restart_policy="",
                    )
                )
        return results

    def get_container(self, id_or_name: str) -> ContainerInfo:
        for c in self.containers(all=True):
            if c.short_id == id_or_name[:12] or c.name == id_or_name:
                return c
        raise DockerNotFoundError(f"Container not found: {id_or_name}")

    def start(self, id_or_name: str) -> None:
        _run_cli("start", id_or_name)

    def stop(self, id_or_name: str, timeout: int = 10) -> None:
        _run_cli("stop", "--time", str(timeout), id_or_name)

    def restart(self, id_or_name: str, timeout: int = 10) -> None:
        _run_cli("restart", "--time", str(timeout), id_or_name)

    def remove_container(
        self, id_or_name: str, force: bool = False, volumes: bool = False
    ) -> None:
        args = ["rm"]
        if force:
            args.append("-f")
        if volumes:
            args.append("-v")
        args.append(id_or_name)
        _run_cli(*args)

    def pause(self, id_or_name: str) -> None:
        _run_cli("pause", id_or_name)

    def unpause(self, id_or_name: str) -> None:
        _run_cli("unpause", id_or_name)

    def logs(
        self,
        id_or_name: str,
        tail: int = 100,
        follow: bool = False,
        timestamps: bool = True,
    ) -> Union[str, Iterator[str]]:
        args = ["logs", f"--tail={tail}"]
        if timestamps:
            args.append("--timestamps")
        if follow:
            args.append("-f")
        args.append(id_or_name)

        if not follow:
            r = _run_cli(*args, check=False)
            return (r.stdout or "") + (r.stderr or "")

        def _stream() -> Iterator[str]:
            proc = subprocess.Popen(
                [_DOCKER_BIN] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    yield line.rstrip()
            finally:
                proc.terminate()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=5)

        return _stream()

    def exec_run(self, id_or_name: str, command: str) -> Tuple[int, str]:
        result = _run_cli("exec", id_or_name, "sh", "-c", command, check=False)
        return result.returncode, result.stdout + result.stderr

    def stats_once(self, id_or_name: str) -> DockerStats:
        fmt = (
            '{"id":"{{.ID}}","name":"{{.Name}}",'
            '"cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}",'
            '"net":"{{.NetIO}}","block":"{{.BlockIO}}","pids":"{{.PIDs}}"}'
        )
        r = _run_cli("stats", "--no-stream", "--format", fmt, id_or_name)
        try:
            d = json.loads(r.stdout.strip())
        except json.JSONDecodeError as exc:
            raise DockerOperationError("Failed to parse stats output") from exc
        return self._parse_cli_stats(d)

    def stats_stream(self, id_or_name: str) -> Generator[DockerStats, None, None]:
        fmt = (
            '{"id":"{{.ID}}","name":"{{.Name}}",'
            '"cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}",'
            '"net":"{{.NetIO}}","block":"{{.BlockIO}}","pids":"{{.PIDs}}"}'
        )
        proc = subprocess.Popen(
            [_DOCKER_BIN, "stats", "--format", fmt, id_or_name],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    yield self._parse_cli_stats(json.loads(line))
        finally:
            proc.terminate()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)

    # ── image ops ─────────────────────────────────────────────────────────────

    def images(self) -> List[ImageInfo]:
        fmt = (
            '{"id":"{{.ID}}","tag":"{{.Tag}}","repo":"{{.Repository}}",'
            '"size":"{{.Size}}","created":"{{.CreatedAt}}"}'
        )
        r = _run_cli("images", "--format", fmt)
        results: List[ImageInfo] = []
        for line in r.stdout.strip().splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                d = json.loads(line)
                tag = d.get("tag", "")
                repo = d.get("repo", "")
                full_tag = f"{repo}:{tag}" if repo and tag else repo or tag or "—"
                results.append(
                    ImageInfo(
                        id=d.get("id", ""),
                        short_id=d.get("id", "")[:12],
                        tags=[full_tag] if full_tag and full_tag != ":<none>" else [],
                        size_mb=self._parse_size_mb(d.get("size", "0")),
                        created=d.get("created", ""),
                        architecture="—",
                        os="—",
                        author="—",
                        comment="",
                        layers=0,
                    )
                )
        return results

    def pull_image(
        self,
        name: str,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> ImageInfo:
        proc = subprocess.Popen(
            [_DOCKER_BIN, "pull", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            if progress_cb:
                progress_cb(line.rstrip())
        proc.wait()
        if proc.returncode != 0:
            raise DockerOperationError(f"Failed to pull image: {name}")
        imgs = self.images()
        for img in imgs:
            if any(name in t for t in img.tags):
                return img
        raise DockerNotFoundError(f"Image not found after pull: {name}")

    def remove_image(self, id_or_name: str, force: bool = False) -> None:
        args = ["rmi"]
        if force:
            args.append("-f")
        args.append(id_or_name)
        _run_cli(*args)

    def prune_images(self) -> Dict[str, Any]:
        r = _run_cli("image", "prune", "-f")
        return {"output": r.stdout}

    def prune_containers(self) -> Dict[str, Any]:
        r = _run_cli("container", "prune", "-f")
        return {"output": r.stdout}

    def prune_volumes(self) -> Dict[str, Any]:
        r = _run_cli("volume", "prune", "-f")
        return {"output": r.stdout}

    def inspect_image(self, id_or_name: str) -> Dict[str, Any]:
        r = _run_cli("image", "inspect", id_or_name)
        data = json.loads(r.stdout)
        return data[0] if data else {}

    # ── volume ops ────────────────────────────────────────────────────────────

    def volumes(self) -> List[VolumeInfo]:
        r = _run_cli(
            "volume",
            "ls",
            "--format",
            '{"name":"{{.Name}}","driver":"{{.Driver}}","scope":"{{.Scope}}"}',
        )
        results: List[VolumeInfo] = []
        for line in r.stdout.strip().splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                d = json.loads(line)
                results.append(
                    VolumeInfo(
                        name=d.get("name", ""),
                        driver=d.get("driver", "local"),
                        mountpoint="—",
                        created="—",
                        labels={},
                        scope=d.get("scope", "local"),
                    )
                )
        return results

    def remove_volume(self, name: str, force: bool = False) -> None:
        args = ["volume", "rm"]
        if force:
            args.append("-f")
        args.append(name)
        _run_cli(*args)

    # ── network ops ───────────────────────────────────────────────────────────

    def networks(self) -> List[NetworkInfo]:
        r = _run_cli(
            "network",
            "ls",
            "--format",
            '{"id":"{{.ID}}","name":"{{.Name}}","driver":"{{.Driver}}","scope":"{{.Scope}}"}',
        )
        results: List[NetworkInfo] = []
        for line in r.stdout.strip().splitlines():
            with contextlib.suppress(json.JSONDecodeError):
                d = json.loads(line)
                results.append(
                    NetworkInfo(
                        id=d.get("id", ""),
                        name=d.get("name", ""),
                        driver=d.get("driver", "bridge"),
                        scope=d.get("scope", "local"),
                        ipam_subnet="—",
                        containers=[],
                        internal=False,
                        attachable=False,
                    )
                )
        return results

    # ── private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_size_mb(s: str) -> float:
        """Parse docker size strings like '45.6MB', '1.2GB', '512kB'."""
        s = s.strip()
        m = re.match(r"([\d.]+)\s*([KkMmGgTt]?)[Bb]?", s)
        if not m:
            return 0.0
        val = float(m.group(1))
        unit = m.group(2).upper()
        mult = {"K": 1 / 1024, "": 1 / (1024 ** 2), "M": 1.0, "G": 1024.0, "T": 1024 ** 2}
        return round(val * mult.get(unit, 1.0), 2)

    @staticmethod
    def _parse_cli_stats(d: Dict[str, Any]) -> DockerStats:
        """Parse docker stats CLI output dict into DockerStats."""

        def _parse_pct(s: str) -> float:
            return float(s.replace("%", "").strip() or "0")

        def _parse_mb_pair(s: str) -> Tuple[float, float]:
            """Parse '1.2MB / 4GB' → (usage_mb, limit_mb)."""
            parts = re.split(r"\s*/\s*", s.strip())
            if len(parts) == 2:
                return (
                    _CLIClient._parse_size_mb(parts[0]),
                    _CLIClient._parse_size_mb(parts[1]),
                )
            return 0.0, 0.0

        cpu = _parse_pct(d.get("cpu", "0%"))
        mem_usage, mem_limit = _parse_mb_pair(d.get("mem", "0B / 0B"))
        mem_pct = (mem_usage / mem_limit * 100.0) if mem_limit > 0 else 0.0
        net_in, net_out = _parse_mb_pair(d.get("net", "0B / 0B"))
        blk_r, blk_w = _parse_mb_pair(d.get("block", "0B / 0B"))

        return DockerStats(
            container_id=d.get("id", "")[:12],
            container_name=d.get("name", "").lstrip("/"),
            cpu_percent=round(cpu, 2),
            mem_usage_mb=round(mem_usage, 2),
            mem_limit_mb=round(mem_limit, 2),
            mem_percent=round(mem_pct, 2),
            net_in_mb=round(net_in, 3),
            net_out_mb=round(net_out, 3),
            block_read_mb=round(blk_r, 3),
            block_write_mb=round(blk_w, 3),
            pids=int(d.get("pids", 0) or 0),
        )


def _make_client() -> Union[_SDKClient, _CLIClient]:
    """Factory: prefer SDK, fall back to CLI, raise if neither works."""
    if _SDK_AVAILABLE:
        with contextlib.suppress(DockerDaemonError):
            return _SDKClient()
    # SDK not available or daemon not reachable via SDK — try CLI
    if shutil.which("docker"):
        return _CLIClient()
    raise DockerDaemonError(
        "Docker not available: install docker SDK (`pip install docker`) "
        "or ensure the docker binary is on PATH."
    )


# ══════════════════════════════════════════════════════════════════════════════
# Business-logic layer
# ══════════════════════════════════════════════════════════════════════════════

class DockerManager:
    """
    High-level Docker operations with audit logging, retry, and rich error
    handling.  All public methods are safe to call from any thread.
    """

    def __init__(self) -> None:
        self._client: Optional[Union[_SDKClient, _CLIClient]] = None
        self._lock = threading.Lock()

    # ── lazy client ───────────────────────────────────────────────────────────

    @property
    def client(self) -> Union[_SDKClient, _CLIClient]:
        with self._lock:
            if self._client is None:
                self._client = _make_client()
            return self._client

    def _reset_client(self) -> None:
        with self._lock:
            self._client = None

    # ── audit ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _audit(action: str, target: str = "", detail: str = "") -> None:
        """Write action to audit log if available."""
        try:
            from data import audit  # type: ignore

            audit.log("docker_manager", action, target, detail)
        except Exception:
            logger.debug("audit.log unavailable: %s %s %s", action, target, detail)

    # ── containers ────────────────────────────────────────────────────────────

    def list_containers(self, all: bool = True) -> List[ContainerInfo]:
        return self.client.containers(all=all)

    def start_container(self, id_or_name: str) -> None:
        self.client.start(id_or_name)
        self._audit("start", id_or_name)

    def stop_container(self, id_or_name: str, timeout: int = 10) -> None:
        self.client.stop(id_or_name, timeout=timeout)
        self._audit("stop", id_or_name)

    def restart_container(self, id_or_name: str, timeout: int = 10) -> None:
        self.client.restart(id_or_name, timeout=timeout)
        self._audit("restart", id_or_name)

    def remove_container(
        self, id_or_name: str, force: bool = False, volumes: bool = False
    ) -> None:
        self.client.remove_container(id_or_name, force=force, volumes=volumes)
        self._audit("remove_container", id_or_name, f"force={force} volumes={volumes}")

    def pause_container(self, id_or_name: str) -> None:
        self.client.pause(id_or_name)
        self._audit("pause", id_or_name)

    def unpause_container(self, id_or_name: str) -> None:
        self.client.unpause(id_or_name)
        self._audit("unpause", id_or_name)

    def get_logs(
        self,
        id_or_name: str,
        tail: int = 100,
        follow: bool = False,
        timestamps: bool = True,
    ) -> Union[str, Iterator[str]]:
        self._audit("logs", id_or_name, f"tail={tail} follow={follow}")
        return self.client.logs(
            id_or_name, tail=tail, follow=follow, timestamps=timestamps
        )

    def exec_in_container(self, id_or_name: str, command: str) -> Tuple[int, str]:
        self._audit("exec", id_or_name, command)
        return self.client.exec_run(id_or_name, command)

    def get_stats(self, id_or_name: str) -> DockerStats:
        return self.client.stats_once(id_or_name)

    def stream_stats(self, id_or_name: str) -> Generator[DockerStats, None, None]:
        return self.client.stats_stream(id_or_name)

    # ── images ────────────────────────────────────────────────────────────────

    def list_images(self) -> List[ImageInfo]:
        return self.client.images()

    def pull_image(
        self,
        name: str,
        progress_cb: Optional[Callable[[str], None]] = None,
    ) -> ImageInfo:
        self._audit("pull_image", name)
        return self.client.pull_image(name, progress_cb=progress_cb)

    def remove_image(self, id_or_name: str, force: bool = False) -> None:
        self.client.remove_image(id_or_name, force=force)
        self._audit("remove_image", id_or_name, f"force={force}")

    def inspect_image(self, id_or_name: str) -> Dict[str, Any]:
        return self.client.inspect_image(id_or_name)

    def prune_all(self) -> Dict[str, Any]:
        """Prune stopped containers, dangling images, and unused volumes."""
        self._audit("prune_all", "", "")
        results: Dict[str, Any] = {}
        results["containers"] = self.client.prune_containers()
        results["images"] = self.client.prune_images()
        results["volumes"] = self.client.prune_volumes()
        return results

    # ── volumes ───────────────────────────────────────────────────────────────

    def list_volumes(self) -> List[VolumeInfo]:
        return self.client.volumes()

    def remove_volume(self, name: str, force: bool = False) -> None:
        self.client.remove_volume(name, force=force)
        self._audit("remove_volume", name)

    # ── networks ──────────────────────────────────────────────────────────────

    def list_networks(self) -> List[NetworkInfo]:
        return self.client.networks()


# ══════════════════════════════════════════════════════════════════════════════
# Terminal UI layer
# ══════════════════════════════════════════════════════════════════════════════

class DockerUI:
    """
    All terminal rendering for the docker manager.
    Keeps business logic in DockerManager and rendering here.
    """

    # spacing constants
    _COL_ID = 12
    _COL_NAME = 24
    _COL_IMAGE = 28
    _COL_STATE = 12
    _COL_STATUS = 22

    def __init__(self, manager: Optional[DockerManager] = None) -> None:
        self._m = manager or DockerManager()

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _state_colour(state: ContainerState) -> str:
        return _STATE_COLOUR.get(state.value, Ansi.RESET)

    @staticmethod
    def _bar(pct: float, width: int = 20) -> str:
        pct = max(0.0, min(100.0, pct))
        filled = int(width * pct / 100)
        colour = (
            Ansi.BRIGHT_GREEN if pct < 60
            else Ansi.YELLOW if pct < 85
            else Ansi.BRIGHT_RED
        )
        bar = "█" * filled + "░" * (width - filled)
        return f"{colour}{bar}{Ansi.RESET} {pct:5.1f}%"

    @staticmethod
    def _divider(char: str = "─") -> None:
        print(f"{Ansi.DIM}{char * _term_width()}{Ansi.RESET}")

    @staticmethod
    def _pick_container(
        containers: List[ContainerInfo], prompt_text: str = "Container"
    ) -> Optional[ContainerInfo]:
        for i, c in enumerate(containers, 1):
            col = _STATE_COLOUR.get(c.state.value, Ansi.RESET)
            print(
                f"  {Ansi.DIM}{i:>2}.{Ansi.RESET} "
                f"{Ansi.BOLD}{c.name:<24}{Ansi.RESET} "
                f"{col}{c.state.value:<12}{Ansi.RESET} "
                f"{Ansi.DIM}{c.short_id}{Ansi.RESET}"
            )
        raw = UI.prompt(f"{prompt_text} # (or name/ID, blank=cancel):")
        if not raw.strip():
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(containers):
                return containers[idx]
            UI.error("Index out of range")
            return None
        for c in containers:
            if c.name == raw.strip() or c.short_id.startswith(raw.strip()[:8]):
                return c
        UI.error(f"No match: {raw!r}")
        return None

    # ══════════════════════════════════════════════════════════════════════════
    # MAIN MENU
    # ══════════════════════════════════════════════════════════════════════════

    def run(self) -> None:
        while True:
            UI.header("🐋  Docker Manager")
            menu_items = [
                ("1", "Container List & Manage"),
                ("2", "Live Stats  (real-time)"),
                ("3", "Container Logs"),
                ("4", "Exec in Container"),
                ("5", "Image Management"),
                ("6", "Volume Management"),
                ("7", "Network Overview"),
                ("8", "Pull Image"),
                ("9", "System Prune"),
                ("0", "Back"),
            ]
            for key, label in menu_items:
                print(f"  {Ansi.CYAN}{key}{Ansi.RESET}  {label}")
            self._divider()
            choice = UI.prompt("Choose:").strip()
            dispatch = {
                "1": self._menu_containers,
                "2": self._menu_live_stats,
                "3": self._menu_logs,
                "4": self._menu_exec,
                "5": self._menu_images,
                "6": self._menu_volumes,
                "7": self._menu_networks,
                "8": self._menu_pull,
                "9": self._menu_prune,
                "0": None,
            }
            if choice == "0":
                break
            handler = dispatch.get(choice)
            if handler:
                try:
                    handler()
                except DockerDaemonError as exc:
                    UI.error(f"Docker daemon error: {exc}")
                    UI.pause()
                except DockerNotFoundError as exc:
                    UI.error(f"Not found: {exc}")
                    UI.pause()
                except DockerOperationError as exc:
                    UI.error(f"Operation failed: {exc}")
                    UI.pause()
                except KeyboardInterrupt:
                    print()
                    UI.info("Interrupted.")
            else:
                UI.warning("Invalid choice")

    # ══════════════════════════════════════════════════════════════════════════
    # CONTAINERS
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_containers(self) -> None:
        while True:
            containers = self._m.list_containers(all=True)
            self._render_container_table(containers)
            print()
            print(
                f"  {Ansi.CYAN}S{Ansi.RESET}tart  "
                f"{Ansi.CYAN}X{Ansi.RESET}  Stop  "
                f"{Ansi.CYAN}R{Ansi.RESET}estart  "
                f"{Ansi.CYAN}P{Ansi.RESET}ause  "
                f"{Ansi.CYAN}U{Ansi.RESET}npause  "
                f"{Ansi.CYAN}D{Ansi.RESET}elete  "
                f"{Ansi.CYAN}I{Ansi.RESET}nspect  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            self._divider()
            cmd = UI.prompt("Action:").strip().upper()

            if cmd == "0":
                break
            elif cmd in ("S", "X", "R", "P", "U", "D", "I"):
                c = self._pick_container(containers)
                if c is None:
                    continue
                try:
                    if cmd == "S":
                        self._m.start_container(c.id)
                        UI.success(f"Started {c.name}")
                    elif cmd == "X":
                        self._m.stop_container(c.id)
                        UI.success(f"Stopped {c.name}")
                    elif cmd == "R":
                        self._m.restart_container(c.id)
                        UI.success(f"Restarted {c.name}")
                    elif cmd == "P":
                        self._m.pause_container(c.id)
                        UI.success(f"Paused {c.name}")
                    elif cmd == "U":
                        self._m.unpause_container(c.id)
                        UI.success(f"Unpaused {c.name}")
                    elif cmd == "D":
                        force = UI.confirm(f"Force remove {c.name!r}?")
                        self._m.remove_container(c.id, force=force, volumes=False)
                        UI.success(f"Removed {c.name}")
                    elif cmd == "I":
                        self._render_container_inspect(c)
                        UI.pause()
                except (DockerNotFoundError, DockerOperationError) as exc:
                    UI.error(str(exc))
            else:
                UI.warning("Unknown action")

    def _render_container_table(self, containers: List[ContainerInfo]) -> None:
        UI.header(f"Containers ({len(containers)} total)")
        if not containers:
            UI.info("No containers found.")
            return

        header = (
            f"  {'ID':<{self._COL_ID}} "
            f"{'NAME':<{self._COL_NAME}} "
            f"{'IMAGE':<{self._COL_IMAGE}} "
            f"{'STATE':<{self._COL_STATE}} "
            f"STATUS"
        )
        print(f"{Ansi.BOLD}{header}{Ansi.RESET}")
        self._divider()

        running = [c for c in containers if c.state == ContainerState.RUNNING]
        stopped = [c for c in containers if c.state != ContainerState.RUNNING]

        for c in running + stopped:
            col = _STATE_COLOUR.get(c.state.value, Ansi.RESET)
            print(
                f"  {Ansi.DIM}{c.short_id:<{self._COL_ID}}{Ansi.RESET} "
                f"{Ansi.BOLD}{_truncate(c.name, self._COL_NAME):<{self._COL_NAME}}{Ansi.RESET} "
                f"{Ansi.DIM}{_truncate(c.image, self._COL_IMAGE):<{self._COL_IMAGE}}{Ansi.RESET} "
                f"{col}{c.state.value:<{self._COL_STATE}}{Ansi.RESET} "
                f"{c.status}"
            )
        self._divider()
        print(
            f"  Running: {Ansi.BRIGHT_GREEN}{len(running)}{Ansi.RESET}  "
            f"Stopped: {Ansi.RED}{len(stopped)}{Ansi.RESET}"
        )

    def _render_container_inspect(self, c: ContainerInfo) -> None:
        UI.header(f"Inspect: {c.name}")
        fields: List[Tuple[str, str]] = [
            ("ID", c.id),
            ("Short ID", c.short_id),
            ("Name", c.name),
            ("Image", c.image),
            ("State", c.state.value),
            ("Status", c.status),
            ("Created", c.created),
            ("Network Mode", c.network_mode),
            ("Restart Policy", c.restart_policy),
        ]
        for label, value in fields:
            print(f"  {Ansi.CYAN}{label:<20}{Ansi.RESET} {value}")

        if c.ports:
            print(f"\n  {Ansi.CYAN}{'Ports':<20}{Ansi.RESET}")
            for container_port, host_bindings in c.ports.items():
                if host_bindings:
                    for hb in host_bindings:
                        host = f"{hb.get('HostIp', '')}:{hb.get('HostPort', '')}"
                        print(f"    {host:<20} → {container_port}")
                else:
                    print(f"    {'(not exposed)':<20}   {container_port}")

        if c.labels:
            print(f"\n  {Ansi.CYAN}Labels:{Ansi.RESET}")
            for k, v in list(c.labels.items())[:10]:
                print(f"    {Ansi.DIM}{k}{Ansi.RESET} = {v}")
            if len(c.labels) > 10:
                print(f"    … {len(c.labels) - 10} more")

    # ══════════════════════════════════════════════════════════════════════════
    # LIVE STATS
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_live_stats(self) -> None:
        containers = self._m.list_containers(all=False)
        if not containers:
            UI.info("No running containers.")
            UI.pause()
            return

        c = self._pick_container(containers, "Stream stats for container")
        if c is None:
            return

        UI.info(f"Streaming stats for {c.name!r} — Ctrl-C to stop")
        self._divider()
        try:
            for stats in self._m.stream_stats(c.id):
                self._render_stats_row(stats)
                time.sleep(getattr(Config, "DOCKER_STATS_INTERVAL", 2.0))
        except KeyboardInterrupt:
            print()
            UI.info("Stats stream stopped.")

    def _render_stats_row(self, s: DockerStats) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        cpu_bar = self._bar(s.cpu_percent, 16)
        mem_bar = self._bar(s.mem_percent, 16)
        print(
            f"  {Ansi.DIM}{ts}{Ansi.RESET} "
            f"{Ansi.BOLD}{s.container_name:<20}{Ansi.RESET}  "
            f"CPU {cpu_bar}  "
            f"MEM {mem_bar}  "
            f"{Ansi.DIM}{s.mem_usage_mb:.0f}/{s.mem_limit_mb:.0f} MB{Ansi.RESET}  "
            f"NET ↓{s.net_in_mb:.2f} ↑{s.net_out_mb:.2f} MB  "
            f"BLK r{s.block_read_mb:.2f} w{s.block_write_mb:.2f} MB  "
            f"PIDs {s.pids}"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # LOGS
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_logs(self) -> None:
        containers = self._m.list_containers(all=True)
        c = self._pick_container(containers, "View logs for container")
        if c is None:
            return

        tail_raw = UI.prompt("Tail N lines [100]:").strip()
        tail = int(tail_raw) if tail_raw.isdigit() else 100
        follow = UI.confirm("Follow (live stream)?")
        timestamps = UI.confirm("Show timestamps?")

        UI.header(f"Logs: {c.name} (tail={tail})")
        self._divider()

        try:
            output = self._m.get_logs(
                c.id, tail=tail, follow=follow, timestamps=timestamps
            )
            if follow:
                for line in output:  # type: ignore[union-attr]
                    print(line)
            else:
                print(output)
        except KeyboardInterrupt:
            print()
            UI.info("Log stream stopped.")
        finally:
            self._divider()
            if not follow:
                UI.pause()

    # ══════════════════════════════════════════════════════════════════════════
    # EXEC
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_exec(self) -> None:
        containers = [
            c for c in self._m.list_containers(all=False)
            if c.state == ContainerState.RUNNING
        ]
        if not containers:
            UI.info("No running containers to exec into.")
            UI.pause()
            return

        c = self._pick_container(containers, "Exec in container")
        if c is None:
            return

        cmd = UI.prompt("Command to run [sh]:").strip() or "sh"
        exit_code, output = self._m.exec_in_container(c.id, cmd)
        UI.header(f"Exec: {c.name}  →  {cmd}")
        print(output)
        colour = Ansi.BRIGHT_GREEN if exit_code == 0 else Ansi.RED
        print(f"\n  Exit code: {colour}{exit_code}{Ansi.RESET}")
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════════
    # IMAGES
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_images(self) -> None:
        while True:
            images = self._m.list_images()
            self._render_image_table(images)
            print()
            print(
                f"  {Ansi.CYAN}D{Ansi.RESET}elete  "
                f"{Ansi.CYAN}I{Ansi.RESET}nspect  "
                f"{Ansi.CYAN}0{Ansi.RESET} Back"
            )
            self._divider()
            cmd = UI.prompt("Action:").strip().upper()

            if cmd == "0":
                break
            elif cmd in ("D", "I"):
                if not images:
                    UI.warning("No images.")
                    continue
                for i, img in enumerate(images, 1):
                    tag = img.tags[0] if img.tags else img.short_id
                    print(
                        f"  {Ansi.DIM}{i:>2}.{Ansi.RESET} "
                        f"{Ansi.BOLD}{_truncate(tag, 40):<42}{Ansi.RESET} "
                        f"{img.size_mb:>8.1f} MB  "
                        f"{Ansi.DIM}{img.created}{Ansi.RESET}"
                    )
                raw = UI.prompt("Image # or tag (blank=cancel):")
                img_choice = self._pick_image(images, raw)
                if img_choice is None:
                    continue
                try:
                    if cmd == "D":
                        force = UI.confirm(f"Force remove {img_choice.short_id!r}?")
                        ref = img_choice.tags[0] if img_choice.tags else img_choice.id
                        self._m.remove_image(ref, force=force)
                        UI.success(f"Removed image {ref}")
                    elif cmd == "I":
                        data = self._m.inspect_image(
                            img_choice.tags[0] if img_choice.tags else img_choice.id
                        )
                        self._render_image_inspect(img_choice, data)
                        UI.pause()
                except (DockerNotFoundError, DockerOperationError) as exc:
                    UI.error(str(exc))

    def _render_image_table(self, images: List[ImageInfo]) -> None:
        UI.header(f"Images ({len(images)} total)")
        if not images:
            UI.info("No images found.")
            return
        header = (
            f"  {'ID':<13} {'TAGS':<40} {'SIZE MB':>9} {'CREATED':<20} {'LAYERS':>6}"
        )
        print(f"{Ansi.BOLD}{header}{Ansi.RESET}")
        self._divider()
        total_mb = 0.0
        for img in images:
            tag_str = ", ".join(img.tags) if img.tags else "—"
            total_mb += img.size_mb
            print(
                f"  {Ansi.DIM}{img.short_id:<13}{Ansi.RESET} "
                f"{_truncate(tag_str, 40):<40} "
                f"{img.size_mb:>9.1f} "
                f"{Ansi.DIM}{img.created:<20}{Ansi.RESET} "
                f"{img.layers:>6}"
            )
        self._divider()
        print(f"  Total: {total_mb:.1f} MB  ({total_mb / 1024:.2f} GB)")

    def _render_image_inspect(self, img: ImageInfo, data: Dict[str, Any]) -> None:
        UI.header(f"Image Inspect: {img.tags[0] if img.tags else img.short_id}")
        pairs: List[Tuple[str, str]] = [
            ("ID", img.id[:32] + "…"),
            ("Tags", ", ".join(img.tags) or "—"),
            ("Size", f"{img.size_mb:.1f} MB"),
            ("Created", img.created),
            ("Architecture", img.architecture),
            ("OS", img.os),
            ("Author", img.author or "—"),
            ("Layers", str(img.layers)),
        ]
        for label, value in pairs:
            print(f"  {Ansi.CYAN}{label:<20}{Ansi.RESET} {value}")

        if data:
            env = (data.get("Config") or {}).get("Env") or []
            if env:
                print(f"\n  {Ansi.CYAN}ENV:{Ansi.RESET}")
                for e in env[:10]:
                    print(f"    {Ansi.DIM}{e}{Ansi.RESET}")
                if len(env) > 10:
                    print(f"    … {len(env) - 10} more")

            exposed = (data.get("Config") or {}).get("ExposedPorts") or {}
            if exposed:
                print(f"\n  {Ansi.CYAN}Exposed Ports:{Ansi.RESET}")
                for p in exposed:
                    print(f"    {p}")

    @staticmethod
    def _pick_image(
        images: List[ImageInfo], raw: str
    ) -> Optional[ImageInfo]:
        if not raw.strip():
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(images):
                return images[idx]
        for img in images:
            if raw in img.tags or img.short_id.startswith(raw[:8]):
                return img
        UI.error(f"No image match: {raw!r}")
        return None

    # ══════════════════════════════════════════════════════════════════════════
    # VOLUMES
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_volumes(self) -> None:
        volumes = self._m.list_volumes()
        UI.header(f"Volumes ({len(volumes)} total)")
        if not volumes:
            UI.info("No volumes found.")
            UI.pause()
            return

        header = f"  {'NAME':<36} {'DRIVER':<12} {'SCOPE':<8} MOUNTPOINT"
        print(f"{Ansi.BOLD}{header}{Ansi.RESET}")
        self._divider()
        for v in volumes:
            print(
                f"  {Ansi.BOLD}{_truncate(v.name, 35):<36}{Ansi.RESET} "
                f"{v.driver:<12} "
                f"{v.scope:<8} "
                f"{Ansi.DIM}{_truncate(v.mountpoint, 40)}{Ansi.RESET}"
            )
        self._divider()

        if UI.confirm("Delete a volume?"):
            name = UI.prompt("Volume name:").strip()
            if not name:
                return
            force = UI.confirm("Force?")
            try:
                self._m.remove_volume(name, force=force)
                UI.success(f"Volume {name!r} removed")
            except (DockerNotFoundError, DockerOperationError) as exc:
                UI.error(str(exc))
        else:
            UI.pause()

    # ══════════════════════════════════════════════════════════════════════════
    # NETWORKS
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_networks(self) -> None:
        networks = self._m.list_networks()
        UI.header(f"Networks ({len(networks)} total)")
        if not networks:
            UI.info("No networks found.")
            UI.pause()
            return

        header = f"  {'ID':<13} {'NAME':<24} {'DRIVER':<10} {'SCOPE':<8} SUBNET"
        print(f"{Ansi.BOLD}{header}{Ansi.RESET}")
        self._divider()
        for n in networks:
            print(
                f"  {Ansi.DIM}{n.id[:12]:<13}{Ansi.RESET} "
                f"{Ansi.BOLD}{_truncate(n.name, 23):<24}{Ansi.RESET} "
                f"{n.driver:<10} "
                f"{n.scope:<8} "
                f"{n.ipam_subnet}"
            )
            if n.containers:
                attached = ", ".join(n.containers[:4])
                if len(n.containers) > 4:
                    attached += f" +{len(n.containers) - 4} more"
                print(f"    {Ansi.DIM}containers: {attached}{Ansi.RESET}")
        self._divider()
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════════
    # PULL
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_pull(self) -> None:
        name = UI.prompt("Image to pull (e.g. nginx:latest):").strip()
        if not name:
            return

        UI.header(f"Pulling {name}")
        last_status: Dict[str, str] = {}

        def progress(msg: str) -> None:
            # Throttle duplicate lines
            if last_status.get("msg") != msg:
                print(f"  {Ansi.DIM}{_truncate(msg, 70)}{Ansi.RESET}")
                last_status["msg"] = msg

        try:
            img = self._m.pull_image(name, progress_cb=progress)
            self._divider()
            UI.success(
                f"Pulled {img.tags[0] if img.tags else name}  "
                f"({img.size_mb:.1f} MB)"
            )
        except (DockerNotFoundError, DockerOperationError) as exc:
            UI.error(str(exc))
        UI.pause()

    # ══════════════════════════════════════════════════════════════════════════
    # PRUNE
    # ══════════════════════════════════════════════════════════════════════════

    def _menu_prune(self) -> None:
        UI.header("System Prune")
        UI.warning(
            "This will remove ALL stopped containers, dangling images, "
            "and unused volumes."
        )
        if not UI.confirm("Proceed?"):
            return
        try:
            results = self._m.prune_all()
            self._divider()
            for resource, data in results.items():
                output = ""
                if isinstance(data, dict):
                    output = data.get("output", "") or ""
                    if "SpaceReclaimed" in data:
                        freed = _bytes_to_human(data["SpaceReclaimed"])
                        output = f"Reclaimed {freed}"
                UI.success(f"{resource.capitalize()}: {output or 'done'}")
        except DockerOperationError as exc:
            UI.error(str(exc))
        UI.pause()


# ══════════════════════════════════════════════════════════════════════════════
# Module registry entry point
# ══════════════════════════════════════════════════════════════════════════════

def register(registry: Any) -> None:
    """
    Called by modules/__init__.py ModuleRegistry.
    Registers this module under the 'docker' key.
    """
    registry.register(
        key="docker",
        label="Docker Manager",
        description=(
            "Manage containers, images, volumes and networks. "
            "Live stats, log streaming, exec, pull, prune."
        ),
        entry=run,
        health=health_check,
        tags=["docker", "containers", "devops"],
    )


def run() -> None:
    """Module entry point called by terminal router."""
    try:
        ui = DockerUI()
        ui.run()
    except DockerDaemonError as exc:
        UI.error(str(exc))
        UI.info("Make sure Docker is running: `systemctl start docker`")
        UI.pause()
    except KeyboardInterrupt:
        print()
        UI.info("Docker Manager closed.")


def health_check() -> Dict[str, Any]:
    """
    Called by ModuleRegistry.health_check().
    Returns a dict with status, backend, and container_count.
    """
    result: Dict[str, Any] = {
        "status": "ok",
        "backend": "none",
        "containers": 0,
        "error": None,
    }
    try:
        if _SDK_AVAILABLE:
            client = _SDKClient()
            result["backend"] = "sdk"
        elif shutil.which("docker"):
            client = _CLIClient()  # type: ignore[assignment]
            result["backend"] = "cli"
        else:
            result["status"] = "unavailable"
            result["error"] = "Docker not found"
            return result

        containers = client.containers(all=False)
        result["containers"] = len(containers)
    except DockerDaemonError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    except Exception as exc:  # pragma: no cover
        result["status"] = "error"
        result["error"] = str(exc)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Standalone execution (dev / debug)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    print("Docker Manager — standalone mode")
    hc = health_check()
    print(f"Health: {hc}")
    if hc["status"] == "ok":
        run()
    else:
        print(f"Docker unavailable: {hc['error']}")
        sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════
# Plugin registry metadata (required by plugins/__init__.py PluginRegistry)
# ══════════════════════════════════════════════════════════════════════════

PLUGIN_NAME        = "Docker Manager"
PLUGIN_VERSION     = "1.0.0"
PLUGIN_DESCRIPTION = "Docker container and image management: start, stop, logs, inspect"
PLUGIN_AUTHOR      = "local_os project"
PLUGIN_TAGS: list  = ["docker", "containers", "devops"]


def main() -> None:
    """Entry-point called by PluginRegistry.invoke()."""
    run()