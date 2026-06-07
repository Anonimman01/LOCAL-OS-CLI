"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              LOCAL OS — System Information Module                            ║
║              modules/system_info.py                                          ║
║                                                                              ║
║  Responsibilities:                                                           ║
║    • OS / kernel / hostname / uptime                                         ║
║    • CPU — model, cores, freq, per-core usage, load average                 ║
║    • Memory — RAM + swap, usage bars, pressure levels                       ║
║    • Disk — all partitions, usage, I/O counters                              ║
║    • GPU — via GPUtil (optional, graceful fallback)                          ║
║    • Network interfaces — IPs, MACs, speed, sent/recv                       ║
║    • Battery — charge, plugged state, ETA                                   ║
║    • Temperatures — CPU, GPU, NVMe, fans                                    ║
║    • Boot time, users, system users                                          ║
║    • Full system report — export to .txt                                     ║
║    • Live resource dashboard (continuous refresh)                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import time
import platform
import datetime
import socket
import textwrap
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
except ImportError:
    class _MissingPsutil:
        def __getattr__(self, name):
            raise ImportError("Missing dependency 'psutil'. Install with: pip install psutil")
    psutil = _MissingPsutil()

# ── Optional GPU support ───────────────────────────────────────────────────────
try:
    import GPUtil  # type: ignore
    _GPU_AVAILABLE = True
except ImportError:
    _GPU_AVAILABLE = False

# ── Local imports ──────────────────────────────────────────────────────────────
try:
    from core.ui import UI
    from core.config import Config
except ImportError:
    class UI:  # type: ignore
        @staticmethod
        def header(t: str) -> None: print(f"\n{'═'*60}\n  {t}\n{'═'*60}")
        @staticmethod
        def success(m: str) -> None: print(f"  ✔  {m}")
        @staticmethod
        def error(m: str) -> None:   print(f"  ✘  {m}", file=sys.stderr)
        @staticmethod
        def warn(m: str) -> None:    print(f"  ⚠  {m}")
        @staticmethod
        def info(m: str) -> None:    print(f"  ℹ  {m}")
        @staticmethod
        def prompt(p: str) -> str:   return input(f"  › {p}: ").strip()
        @staticmethod
        def confirm(p: str) -> bool: return input(f"  › {p} [y/N]: ").strip().lower() == "y"
        @staticmethod
        def table(rows: list, headers: list[str]) -> None:
            col_w = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
            sep   = "─┼─".join("─" * w for w in col_w)
            fmt   = " │ ".join(f"{{:<{w}}}" for w in col_w)
            print("  " + fmt.format(*headers))
            print("  " + sep)
            for row in rows:
                print("  " + fmt.format(*[str(v) for v in row]))

    class Config:  # type: ignore
        SYSINFO_REFRESH_INTERVAL: float = 2.0
        SYSINFO_REPORT_PATH: str        = "system_report.txt"
        TEMP_WARN_C: float              = 75.0
        TEMP_CRIT_C: float              = 90.0


# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI helpers  (kept local so module stays self-contained)
# ═══════════════════════════════════════════════════════════════════════════════

_C = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "cyan":    "\033[96m",
    "blue":    "\033[94m",
    "magenta": "\033[95m",
    "white":   "\033[97m",
}

def _c(colour: str, text: str) -> str:
    return f"{_C.get(colour, '')}{text}{_C['reset']}"

def _bold(text: str) -> str:
    return f"{_C['bold']}{text}{_C['reset']}"

def _dim(text: str) -> str:
    return f"{_C['dim']}{text}{_C['reset']}"


# ═══════════════════════════════════════════════════════════════════════════════
#  Utility functions
# ═══════════════════════════════════════════════════════════════════════════════

def _bytes_human(n: int, *, suffix: str = "B") -> str:
    """Convert byte count to human-readable string."""
    for unit in ("", "K", "M", "G", "T", "P"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}{suffix}"
        n //= 1024
    return f"{n:.1f} E{suffix}"

def _pct_bar(pct: float, width: int = 24) -> str:
    """Render a coloured ASCII progress bar."""
    filled = int(pct / 100 * width)
    colour = "green" if pct < 60 else "yellow" if pct < 85 else "red"
    bar    = "█" * filled + "░" * (width - filled)
    return _c(colour, bar)

def _pct_colour(pct: float, fmt: str = "{:.1f}%") -> str:
    colour = "green" if pct < 60 else "yellow" if pct < 85 else "red"
    return _c(colour, fmt.format(pct))

def _temp_colour(celsius: float) -> str:
    warn = getattr(Config, "TEMP_WARN_C", 75.0)
    crit = getattr(Config, "TEMP_CRIT_C", 90.0)
    colour = "green" if celsius < warn else "yellow" if celsius < crit else "red"
    return _c(colour, f"{celsius:.1f} °C")

def _uptime_str(boot_ts: float) -> str:
    delta = datetime.timedelta(seconds=int(time.time() - boot_ts))
    days  = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    mins,  sec = divmod(rem, 60)
    parts = []
    if days:  parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if mins:  parts.append(f"{mins}m")
    parts.append(f"{sec}s")
    return " ".join(parts)

def _terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 120

def _section(title: str) -> str:
    width = _terminal_width()
    pad   = width - len(title) - 6
    return _bold(f"\n  ╔══ {title} {'═' * max(0, pad)}╗")

def _kv(label: str, value: str, *, label_w: int = 22) -> str:
    return f"  {_dim(label.ljust(label_w))} {value}"


# ═══════════════════════════════════════════════════════════════════════════════
#  Data collectors — each returns a plain-Python structure, no I/O
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class OsInfo:
    system:       str
    node:         str
    release:      str
    version:      str
    machine:      str
    processor:    str
    python:       str
    boot_time:    float
    logged_users: list[str]

@dataclass
class CpuInfo:
    brand:          str
    physical_cores: int
    logical_cores:  int
    max_freq_mhz:   float
    min_freq_mhz:   float
    cur_freq_mhz:   float
    total_pct:      float
    per_core_pct:   list[float]
    load_avg:       tuple[float, float, float]   # 1, 5, 15 min
    ctx_switches:   int
    interrupts:     int

@dataclass
class MemInfo:
    ram_total:  int
    ram_used:   int
    ram_free:   int
    ram_pct:    float
    ram_cached: int
    swap_total: int
    swap_used:  int
    swap_free:  int
    swap_pct:   float

@dataclass
class DiskPartition:
    device:     str
    mountpoint: str
    fstype:     str
    total:      int
    used:       int
    free:       int
    pct:        float
    read_bytes: int
    write_bytes: int

@dataclass
class NetworkInterface:
    name:       str
    ipv4:       list[str]
    ipv6:       list[str]
    mac:        str
    speed_mbps: int        # 0 if unknown
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errin:      int
    errout:     int

@dataclass
class GpuInfo:
    id:       int
    name:     str
    load_pct: float
    mem_used: int
    mem_total: int
    mem_pct:  float
    temp_c:   float
    driver:   str

@dataclass
class BatteryInfo:
    percent:    float
    plugged:    bool
    secs_left:  int        # -1 = unknown / charging
    status:     str        # "Charging" | "Discharging" | "Full"

@dataclass
class TempEntry:
    label:   str
    current: float
    high:    float
    critical: float


# ─── Collector class ───────────────────────────────────────────────────────────

class HardwareCollector:
    """
    Gathers all hardware/OS metrics via psutil (and optionally GPUtil).
    No display logic lives here — pure data extraction.
    """

    # ── OS ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def os_info() -> OsInfo:
        uname = platform.uname()
        users = []
        try:
            users = [f"{u.name}@{u.host}" for u in psutil.users()]
        except Exception:
            pass
        return OsInfo(
            system       = uname.system,
            node         = uname.node,
            release      = uname.release,
            version      = uname.version,
            machine      = uname.machine,
            processor    = uname.processor or platform.processor() or "n/a",
            python       = platform.python_version(),
            boot_time    = psutil.boot_time(),
            logged_users = users,
        )

    # ── CPU ────────────────────────────────────────────────────────────────────

    @staticmethod
    def cpu_info() -> CpuInfo:
        freq = psutil.cpu_freq()
        stat = psutil.cpu_stats()

        # Load average — Windows doesn't support os.getloadavg
        try:
            load = os.getloadavg()  # type: ignore[attr-defined]
        except AttributeError:
            load = (0.0, 0.0, 0.0)

        # CPU brand via cpuinfo when available, else platform fallback
        brand = "n/a"
        try:
            import cpuinfo  # type: ignore
            brand = cpuinfo.get_cpu_info().get("brand_raw", "n/a")
        except ImportError:
            brand = platform.processor() or "n/a"

        return CpuInfo(
            brand          = brand,
            physical_cores = psutil.cpu_count(logical=False) or 0,
            logical_cores  = psutil.cpu_count(logical=True)  or 0,
            max_freq_mhz   = freq.max  if freq else 0.0,
            min_freq_mhz   = freq.min  if freq else 0.0,
            cur_freq_mhz   = freq.current if freq else 0.0,
            total_pct      = psutil.cpu_percent(interval=0.3),
            per_core_pct   = psutil.cpu_percent(interval=0.3, percpu=True),  # type: ignore
            load_avg       = load,
            ctx_switches   = stat.ctx_switches,
            interrupts     = stat.interrupts,
        )

    # ── Memory ─────────────────────────────────────────────────────────────────

    @staticmethod
    def mem_info() -> MemInfo:
        r = psutil.virtual_memory()
        s = psutil.swap_memory()
        return MemInfo(
            ram_total  = r.total,
            ram_used   = r.used,
            ram_free   = r.available,
            ram_pct    = r.percent,
            ram_cached = getattr(r, "cached", 0) or getattr(r, "buffers", 0),
            swap_total = s.total,
            swap_used  = s.used,
            swap_free  = s.free,
            swap_pct   = s.percent,
        )

    # ── Disk ───────────────────────────────────────────────────────────────────

    @staticmethod
    def disk_info() -> list[DiskPartition]:
        io_map: dict[str, psutil._common.sdiskio] = {}  # type: ignore
        try:
            io_map = psutil.disk_io_counters(perdisk=True) or {}  # type: ignore
        except Exception:
            pass

        partitions: list[DiskPartition] = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except PermissionError:
                continue

            # Match I/O counters to device (strip /dev/ prefix on Linux)
            dev_key = os.path.basename(part.device)
            io      = io_map.get(dev_key) or io_map.get(part.device)

            partitions.append(DiskPartition(
                device      = part.device,
                mountpoint  = part.mountpoint,
                fstype      = part.fstype,
                total       = usage.total,
                used        = usage.used,
                free        = usage.free,
                pct         = usage.percent,
                read_bytes  = io.read_bytes  if io else 0,
                write_bytes = io.write_bytes if io else 0,
            ))
        return partitions

    # ── Network ────────────────────────────────────────────────────────────────

    @staticmethod
    def network_info() -> list[NetworkInterface]:
        addrs   = psutil.net_if_addrs()
        stats   = psutil.net_if_stats()
        io_all  = psutil.net_io_counters(pernic=True) or {}

        interfaces: list[NetworkInterface] = []
        for name, addr_list in addrs.items():
            ipv4, ipv6, mac = [], [], "n/a"
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ipv4.append(addr.address)
                elif addr.family == socket.AF_INET6:
                    ipv6.append(addr.address.split("%")[0])
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address

            st  = stats.get(name)
            io  = io_all.get(name)
            interfaces.append(NetworkInterface(
                name         = name,
                ipv4         = ipv4,
                ipv6         = ipv6,
                mac          = mac,
                speed_mbps   = st.speed if st else 0,
                bytes_sent   = io.bytes_sent   if io else 0,
                bytes_recv   = io.bytes_recv   if io else 0,
                packets_sent = io.packets_sent if io else 0,
                packets_recv = io.packets_recv if io else 0,
                errin        = io.errin        if io else 0,
                errout       = io.errout       if io else 0,
            ))
        return interfaces

    # ── GPU ────────────────────────────────────────────────────────────────────

    @staticmethod
    def gpu_info() -> list[GpuInfo]:
        if not _GPU_AVAILABLE:
            return []
        try:
            gpus = GPUtil.getGPUs()
            return [
                GpuInfo(
                    id        = g.id,
                    name      = g.name,
                    load_pct  = g.load * 100,
                    mem_used  = int(g.memoryUsed * 1024 * 1024),
                    mem_total = int(g.memoryTotal * 1024 * 1024),
                    mem_pct   = (g.memoryUsed / g.memoryTotal * 100) if g.memoryTotal else 0,
                    temp_c    = g.temperature or 0.0,
                    driver    = g.driver,
                )
                for g in gpus
            ]
        except Exception:
            return []

    # ── Battery ────────────────────────────────────────────────────────────────

    @staticmethod
    def battery_info() -> Optional[BatteryInfo]:
        bat = psutil.sensors_battery()
        if bat is None:
            return None
        if bat.power_plugged:
            status = "Full" if bat.percent >= 99.9 else "Charging"
        else:
            status = "Discharging"
        return BatteryInfo(
            percent   = bat.percent,
            plugged   = bat.power_plugged,
            secs_left = bat.secsleft if bat.secsleft not in (-1, -2) else -1,
            status    = status,
        )

    # ── Temperatures ───────────────────────────────────────────────────────────

    @staticmethod
    def temperatures() -> list[TempEntry]:
        entries: list[TempEntry] = []
        try:
            sensors = psutil.sensors_temperatures()
        except AttributeError:
            return []   # Windows — not supported
        for source, readings in (sensors or {}).items():
            for r in readings:
                label = f"{source} / {r.label}" if r.label else source
                entries.append(TempEntry(
                    label    = label,
                    current  = r.current,
                    high     = r.high    or 0.0,
                    critical = r.critical or 0.0,
                ))
        return entries


# ═══════════════════════════════════════════════════════════════════════════════
#  Renderer  —  converts collected data into terminal output
# ═══════════════════════════════════════════════════════════════════════════════

class SysInfoRenderer:
    """
    All display logic. Receives data objects from HardwareCollector,
    produces ANSI-coloured terminal strings. Zero side effects other than print.
    """

    # ── OS ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def render_os(info: OsInfo) -> None:
        print(_section("Operating System"))
        boot_dt = datetime.datetime.fromtimestamp(info.boot_time)
        print(_kv("Hostname",    _c("cyan",  info.node)))
        print(_kv("OS",          _bold(f"{info.system} {info.release}")))
        print(_kv("Version",     info.version[:60]))
        print(_kv("Architecture", info.machine))
        print(_kv("Processor",   info.processor[:60]))
        print(_kv("Python",      info.python))
        print(_kv("Boot time",   boot_dt.strftime("%Y-%m-%d %H:%M:%S")))
        print(_kv("Uptime",      _c("green", _uptime_str(info.boot_time))))
        users = ", ".join(info.logged_users) or "none"
        print(_kv("Logged users", users))

    # ── CPU ────────────────────────────────────────────────────────────────────

    @staticmethod
    def render_cpu(info: CpuInfo) -> None:
        print(_section("CPU"))
        print(_kv("Model",           info.brand[:60]))
        print(_kv("Physical cores",  str(info.physical_cores)))
        print(_kv("Logical cores",   str(info.logical_cores)))
        freq_s = (f"{info.cur_freq_mhz:.0f} MHz  "
                  f"(min {info.min_freq_mhz:.0f}  max {info.max_freq_mhz:.0f})")
        print(_kv("Frequency",       freq_s))

        # Overall usage bar
        bar = _pct_bar(info.total_pct)
        pct = _pct_colour(info.total_pct)
        print(_kv("Usage",           f"{bar} {pct}"))

        # Per-core bars (up to 16, then summarise)
        cores = info.per_core_pct
        print(f"\n  {_dim('Per-core usage:')}")
        cols = 4
        for i in range(0, min(len(cores), 16), cols):
            row_parts = []
            for j in range(cols):
                if i + j >= len(cores):
                    break
                c_pct = cores[i + j]
                bar_s = _pct_bar(c_pct, 10)
                num_s = _pct_colour(c_pct, "{:5.1f}%")
                row_parts.append(f"  C{i+j:02d} {bar_s} {num_s}")
            print("".join(row_parts))
        if len(cores) > 16:
            print(f"  {_dim(f'… and {len(cores)-16} more cores')}")

        # Load average
        la = info.load_avg
        la_s = f"{la[0]:.2f}  {la[1]:.2f}  {la[2]:.2f}  (1m / 5m / 15m)"
        print(_kv("\nLoad average", la_s))
        print(_kv("Context switches", f"{info.ctx_switches:,}"))
        print(_kv("Interrupts",       f"{info.interrupts:,}"))

    # ── Memory ─────────────────────────────────────────────────────────────────

    @staticmethod
    def render_mem(info: MemInfo) -> None:
        print(_section("Memory"))

        # RAM
        ram_bar = _pct_bar(info.ram_pct)
        ram_pct = _pct_colour(info.ram_pct)
        print(_kv("RAM",
                  f"{ram_bar} {ram_pct}  "
                  f"{_bytes_human(info.ram_used)} / {_bytes_human(info.ram_total)}"))
        print(_kv("  Available", _bytes_human(info.ram_free)))
        if info.ram_cached:
            print(_kv("  Cached / Buf", _bytes_human(info.ram_cached)))

        # Swap
        if info.swap_total:
            swp_bar = _pct_bar(info.swap_pct)
            swp_pct = _pct_colour(info.swap_pct)
            print(_kv("Swap",
                      f"{swp_bar} {swp_pct}  "
                      f"{_bytes_human(info.swap_used)} / {_bytes_human(info.swap_total)}"))
        else:
            print(_kv("Swap", _dim("not configured")))

    # ── Disk ───────────────────────────────────────────────────────────────────

    @staticmethod
    def render_disk(partitions: list[DiskPartition]) -> None:
        print(_section("Disk Partitions"))
        if not partitions:
            print("  " + _dim("No partitions found."))
            return
        for p in partitions:
            bar = _pct_bar(p.pct)
            pct = _pct_colour(p.pct)
            print(f"\n  {_bold(p.mountpoint)}  "
                  f"{_dim(p.device)}  {_dim('['+p.fstype+']')}")
            print(f"    {bar} {pct}  "
                  f"{_bytes_human(p.used)} / {_bytes_human(p.total)}  "
                  f"({_bytes_human(p.free)} free)")
            if p.read_bytes or p.write_bytes:
                print(f"    {_dim('I/O total')}  "
                      f"↑ {_bytes_human(p.write_bytes)}  "
                      f"↓ {_bytes_human(p.read_bytes)}")

    # ── Network ────────────────────────────────────────────────────────────────

    @staticmethod
    def render_network(interfaces: list[NetworkInterface]) -> None:
        print(_section("Network Interfaces"))
        if not interfaces:
            print("  " + _dim("No interfaces found."))
            return
        for iface in interfaces:
            # Skip loopback by default — show if it has traffic
            if iface.name == "lo" and not iface.bytes_sent:
                continue
            print(f"\n  {_bold(iface.name)}  {_dim(iface.mac)}")
            if iface.ipv4:
                print(f"    {_dim('IPv4')}  {', '.join(iface.ipv4)}")
            if iface.ipv6:
                for ip in iface.ipv6[:2]:
                    print(f"    {_dim('IPv6')}  {ip}")
            if iface.speed_mbps:
                print(f"    {_dim('Speed')}  {iface.speed_mbps} Mbps")
            print(f"    {_dim('Sent')}  {_bytes_human(iface.bytes_sent)}  "
                  f"({iface.packets_sent:,} pkts)  "
                  f"{_dim('Recv')}  {_bytes_human(iface.bytes_recv)}  "
                  f"({iface.packets_recv:,} pkts)")
            if iface.errin or iface.errout:
                print(_c("yellow",
                         f"    ⚠  errors in={iface.errin}  out={iface.errout}"))

    # ── GPU ────────────────────────────────────────────────────────────────────

    @staticmethod
    def render_gpu(gpus: list[GpuInfo]) -> None:
        print(_section("GPU"))
        if not gpus:
            if not _GPU_AVAILABLE:
                print("  " + _dim("GPUtil not installed — run: pip install gputil"))
            else:
                print("  " + _dim("No NVIDIA GPU detected."))
            return
        for g in gpus:
            print(f"\n  {_bold(f'GPU {g.id}:')} {g.name}  {_dim('drv ' + g.driver)}")
            load_bar = _pct_bar(g.load_pct)
            load_pct = _pct_colour(g.load_pct)
            mem_bar  = _pct_bar(g.mem_pct)
            mem_pct  = _pct_colour(g.mem_pct)
            print(f"    {_dim('Load')}  {load_bar} {load_pct}")
            print(f"    {_dim('VRAM')}  {mem_bar} {mem_pct}  "
                  f"{_bytes_human(g.mem_used)} / {_bytes_human(g.mem_total)}")
            print(f"    {_dim('Temp')}  {_temp_colour(g.temp_c)}")

    # ── Battery ────────────────────────────────────────────────────────────────

    @staticmethod
    def render_battery(bat: Optional[BatteryInfo]) -> None:
        print(_section("Battery"))
        if bat is None:
            print("  " + _dim("No battery detected (desktop / VM)."))
            return
        icon   = "🔌" if bat.plugged else "🔋"
        colour = "green" if bat.percent > 40 else "yellow" if bat.percent > 15 else "red"
        bar    = _pct_bar(bat.percent)
        pct    = _c(colour, f"{bat.percent:.1f}%")
        print(f"  {icon}  {bar} {pct}  {_dim('['+bat.status+']')}")
        if bat.secs_left > 0:
            eta = str(datetime.timedelta(seconds=bat.secs_left))
            print(_kv("  Time remaining", eta))

    # ── Temperatures ───────────────────────────────────────────────────────────

    @staticmethod
    def render_temps(entries: list[TempEntry]) -> None:
        print(_section("Temperatures"))
        if not entries:
            print("  " + _dim("Sensor data unavailable (requires Linux / macOS or admin)."))
            return
        for e in entries:
            temp_s = _temp_colour(e.current)
            hi_s   = _dim(f"  high {e.high:.0f}°C") if e.high else ""
            cr_s   = _c("red", f"  crit {e.critical:.0f}°C") if e.critical else ""
            print(f"  {e.label:<40} {temp_s}{hi_s}{cr_s}")

    # ── Combined full report ────────────────────────────────────────────────────

    @classmethod
    def render_full(cls) -> None:
        """Collect and render all sections at once."""
        UI.header("🖥  System Information — Full Report")

        collector = HardwareCollector()
        cls.render_os(collector.os_info())
        cls.render_cpu(collector.cpu_info())
        cls.render_mem(collector.mem_info())
        cls.render_disk(collector.disk_info())
        cls.render_network(collector.network_info())
        cls.render_gpu(collector.gpu_info())
        cls.render_battery(collector.battery_info())
        cls.render_temps(collector.temperatures())
        print()

    # ── Compact dashboard (one screen) ────────────────────────────────────────

    @classmethod
    def render_dashboard(cls) -> None:
        """Single-screen summary — suitable for the live monitor loop."""
        os_i  = HardwareCollector.os_info()
        cpu_i = HardwareCollector.cpu_info()
        mem_i = HardwareCollector.mem_info()
        bat_i = HardwareCollector.battery_info()

        ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        up    = _uptime_str(os_i.boot_time)
        width = _terminal_width()
        print(_bold(f"  {'LOCAL OS — System Dashboard':^{width-4}}"))
        print(_dim(f"  {ts:^{width-4}}  uptime {up}"))
        print(_dim("  " + "─" * (width - 2)))

        # CPU row
        cpu_bar = _pct_bar(cpu_i.total_pct, 30)
        cpu_pct = _pct_colour(cpu_i.total_pct)
        print(f"  {'CPU':<8} {cpu_bar} {cpu_pct}  "
              f"{_dim(str(cpu_i.physical_cores)+'p/'+str(cpu_i.logical_cores)+'l '
              + str(cpu_i.cur_freq_mhz)[:6]+' MHz')}")

        # RAM row
        mem_bar = _pct_bar(mem_i.ram_pct, 30)
        mem_pct = _pct_colour(mem_i.ram_pct)
        print(f"  {'RAM':<8} {mem_bar} {mem_pct}  "
              f"{_bytes_human(mem_i.ram_used)}/{_bytes_human(mem_i.ram_total)}")

        # Swap row
        if mem_i.swap_total:
            swp_bar = _pct_bar(mem_i.swap_pct, 30)
            swp_pct = _pct_colour(mem_i.swap_pct)
            print(f"  {'SWAP':<8} {swp_bar} {swp_pct}  "
                  f"{_bytes_human(mem_i.swap_used)}/{_bytes_human(mem_i.swap_total)}")

        # Per-core mini bars (one line, condensed)
        mini = "  CPU/core  "
        for i, p in enumerate(cpu_i.per_core_pct[:16]):
            filled = int(p / 100 * 5)
            col    = "green" if p < 60 else "yellow" if p < 85 else "red"
            mini  += _c(col, "▇" * filled + "░" * (5 - filled)) + " "
        print(mini)

        # Battery
        if bat_i:
            icon  = "🔌" if bat_i.plugged else "🔋"
            col   = "green" if bat_i.percent > 40 else "yellow" if bat_i.percent > 15 else "red"
            b_bar = _pct_bar(bat_i.percent, 20)
            b_pct = _c(col, f"{bat_i.percent:.0f}%")
            print(f"  {'BATTERY':<8} {icon} {b_bar} {b_pct}  {_dim(bat_i.status)}")

        # Disk quick summary
        disks = HardwareCollector.disk_info()
        for d in disks[:4]:
            d_bar = _pct_bar(d.pct, 15)
            d_pct = _pct_colour(d.pct)
            label = (d.mountpoint or d.device)[:12].ljust(12)
            print(f"  {label} {d_bar} {d_pct}  "
                  f"{_bytes_human(d.used)}/{_bytes_human(d.total)}")

        print(_dim("  " + "─" * (width - 2)))


# ═══════════════════════════════════════════════════════════════════════════════
#  Export  —  plain-text system report
# ═══════════════════════════════════════════════════════════════════════════════

class ReportExporter:
    """Generates a clean, timestamped plain-text system report file."""

    @staticmethod
    def _strip_ansi(text: str) -> str:
        import re
        return re.sub(r"\033\[[0-9;]*m", "", text)

    @classmethod
    def export(cls, path: str | None = None) -> str:
        """Write report to *path* and return the resolved path."""
        dest = path or getattr(Config, "SYSINFO_REPORT_PATH", "system_report.txt")

        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            SysInfoRenderer.render_full()
        content = cls._strip_ansi(buf.getvalue())

        ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header  = (
            "=" * 70 + "\n"
            f"  LOCAL OS — System Report\n"
            f"  Generated: {ts}\n"
            f"  Host:      {socket.gethostname()}\n"
            "=" * 70 + "\n"
        )

        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(header + content)
        return dest


# ═══════════════════════════════════════════════════════════════════════════════
#  Menu Controller  (called by terminal.py)
# ═══════════════════════════════════════════════════════════════════════════════

class SystemInfo:
    """
    High-level orchestrator. terminal.py imports only this class.

    Usage
    ─────
        from modules.system_info import SystemInfo
        si = SystemInfo()
        si.menu()
    """

    def menu(self) -> None:
        while True:
            UI.header("🖥  System Information")
            self._print_menu()
            choice = UI.prompt("Select option").strip()

            dispatch = {
                "1": self._show_full,
                "2": self._show_os,
                "3": self._show_cpu,
                "4": self._show_mem,
                "5": self._show_disk,
                "6": self._show_network,
                "7": self._show_gpu,
                "8": self._show_battery,
                "9": self._show_temps,
                "10": self._live_dashboard,
                "11": self._export_report,
                "0": None,
            }

            if choice == "0":
                break
            handler = dispatch.get(choice)
            if handler is None:
                UI.warn("Invalid option.")
            else:
                try:
                    handler()
                except KeyboardInterrupt:
                    UI.info("Interrupted.")
                except Exception as exc:
                    UI.error(f"Unexpected error: {exc}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Handlers
    # ══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _show_full() -> None:
        SysInfoRenderer.render_full()
        SystemInfo._pause()

    @staticmethod
    def _show_os() -> None:
        UI.header("🖥  Operating System")
        SysInfoRenderer.render_os(HardwareCollector.os_info())
        SystemInfo._pause()

    @staticmethod
    def _show_cpu() -> None:
        UI.header("⚙  CPU")
        SysInfoRenderer.render_cpu(HardwareCollector.cpu_info())
        SystemInfo._pause()

    @staticmethod
    def _show_mem() -> None:
        UI.header("💾  Memory")
        SysInfoRenderer.render_mem(HardwareCollector.mem_info())
        SystemInfo._pause()

    @staticmethod
    def _show_disk() -> None:
        UI.header("💿  Disk")
        SysInfoRenderer.render_disk(HardwareCollector.disk_info())
        SystemInfo._pause()

    @staticmethod
    def _show_network() -> None:
        UI.header("🌐  Network Interfaces")
        SysInfoRenderer.render_network(HardwareCollector.network_info())
        SystemInfo._pause()

    @staticmethod
    def _show_gpu() -> None:
        UI.header("🎮  GPU")
        SysInfoRenderer.render_gpu(HardwareCollector.gpu_info())
        SystemInfo._pause()

    @staticmethod
    def _show_battery() -> None:
        UI.header("🔋  Battery")
        SysInfoRenderer.render_battery(HardwareCollector.battery_info())
        SystemInfo._pause()

    @staticmethod
    def _show_temps() -> None:
        UI.header("🌡  Temperatures")
        SysInfoRenderer.render_temps(HardwareCollector.temperatures())
        SystemInfo._pause()

    @staticmethod
    def _live_dashboard() -> None:
        UI.header("📡  Live System Dashboard")
        interval_raw = UI.prompt("Refresh interval seconds (Enter=2.0)")
        try:
            interval = float(interval_raw) if interval_raw else 2.0
        except ValueError:
            interval = 2.0
        UI.info("Press Ctrl+C to stop.")
        time.sleep(0.5)
        try:
            while True:
                _os_clear()
                SysInfoRenderer.render_dashboard()
                time.sleep(interval)
        except KeyboardInterrupt:
            UI.info("Dashboard stopped.")

    @staticmethod
    def _export_report() -> None:
        UI.header("💾  Export System Report")
        raw  = UI.prompt("Output file path (Enter=system_report.txt)")
        dest = raw.strip() or None
        UI.info("Collecting data…")
        try:
            path = ReportExporter.export(dest)
            UI.success(f"Report saved → {path}")
        except OSError as e:
            UI.error(f"Could not write file: {e}")
        SystemInfo._pause()

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _print_menu() -> None:
        items = [
            ("1",  "Full system report"),
            ("2",  "Operating system"),
            ("3",  "CPU (cores, freq, per-core usage, load)"),
            ("4",  "Memory (RAM + swap)"),
            ("5",  "Disk partitions + I/O"),
            ("6",  "Network interfaces"),
            ("7",  "GPU (requires GPUtil)"),
            ("8",  "Battery"),
            ("9",  "Temperatures / fans"),
            ("10", "Live dashboard (continuous refresh)"),
            ("11", "Export report to file"),
            ("0",  "Back"),
        ]
        print()
        for key, label in items:
            bullet = _c("cyan", f"[{key}]")
            print(f"    {bullet}  {label}")
        print()

    @staticmethod
    def _pause() -> None:
        input(_dim("\n  Press Enter to continue…"))


def _os_clear() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")


# ═══════════════════════════════════════════════════════════════════════════════
#  Standalone smoke-test
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    si = SystemInfo()
    si.menu()