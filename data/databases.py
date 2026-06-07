"""
local_os/data/databases.py

Централизованная база данных для local_os.
Содержит: порты, расширения файлов, HTTP-коды, страны, команды Linux.

Автор: local_os project
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
#  Вспомогательные типы
# ─────────────────────────────────────────────────────────────────────────────

class Protocol(str, Enum):
    TCP  = "TCP"
    UDP  = "UDP"
    BOTH = "TCP/UDP"


class PortRisk(str, Enum):
    SAFE     = "safe"
    MODERATE = "moderate"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class PortInfo:
    number:      int
    protocol:    Protocol
    service:     str
    description: str
    risk:        PortRisk = PortRisk.SAFE
    rfc:         Optional[str] = None

    def __str__(self) -> str:
        return f"{self.number}/{self.protocol.value} — {self.service}: {self.description}"


@dataclass(frozen=True, slots=True)
class FileExtension:
    ext:         str          # без точки, нижний регистр
    category:    str
    description: str
    mime_type:   str
    is_binary:   bool = False
    is_archive:  bool = False
    is_code:     bool = False
    is_media:    bool = False

    def __str__(self) -> str:
        return f".{self.ext} ({self.category}): {self.description}"


@dataclass(frozen=True, slots=True)
class HttpStatus:
    code:        int
    phrase:      str
    description: str
    rfc:         str
    is_error:    bool = False

    @property
    def category(self) -> str:
        match self.code // 100:
            case 1: return "Informational"
            case 2: return "Success"
            case 3: return "Redirection"
            case 4: return "Client Error"
            case 5: return "Server Error"
            case _: return "Unknown"

    def __str__(self) -> str:
        return f"{self.code} {self.phrase}: {self.description}"


@dataclass(frozen=True, slots=True)
class Country:
    iso2:      str           # ISO 3166-1 alpha-2
    iso3:      str           # ISO 3166-1 alpha-3
    name:      str
    capital:   str
    region:    str
    subregion: str
    tld:       str
    phone_code: str

    def __str__(self) -> str:
        return f"{self.iso2} — {self.name} ({self.capital})"


class CommandCategory(str, Enum):
    FILES       = "Файлы и директории"
    PROCESS     = "Процессы"
    NETWORK     = "Сеть"
    SYSTEM      = "Система"
    PERMISSIONS = "Права доступа"
    ARCHIVE     = "Архивация"
    TEXT        = "Работа с текстом"
    PACKAGE     = "Пакеты"
    DISK        = "Диски и разделы"
    HARDWARE    = "Железо"
    USERS       = "Пользователи"
    SECURITY    = "Безопасность"
    SHELL       = "Shell / Скрипты"


class LinuxArg(NamedTuple):
    flag:        str
    description: str


@dataclass(frozen=True, slots=True)
class LinuxCommand:
    name:        str
    category:    CommandCategory
    synopsis:    str
    description: str
    examples:    Tuple[str, ...]          = field(default_factory=tuple)
    args:        Tuple[LinuxArg, ...]     = field(default_factory=tuple)
    see_also:    Tuple[str, ...]          = field(default_factory=tuple)
    man_section: int                      = 1

    def __str__(self) -> str:
        return f"{self.name}(1): {self.synopsis}"


# ─────────────────────────────────────────────────────────────────────────────
#  ПОРТЫ
# ─────────────────────────────────────────────────────────────────────────────

PORTS: Dict[int, PortInfo] = {
    # ── Well-Known Ports (0–1023) ─────────────────────────────────────────
    20: PortInfo(20,  Protocol.TCP,  "FTP-DATA",   "FTP Data Transfer",            PortRisk.MODERATE, "RFC 959"),
    21: PortInfo(21,  Protocol.TCP,  "FTP",        "File Transfer Protocol",       PortRisk.MODERATE, "RFC 959"),
    22: PortInfo(22,  Protocol.TCP,  "SSH",        "Secure Shell",                 PortRisk.SAFE,     "RFC 4253"),
    23: PortInfo(23,  Protocol.TCP,  "TELNET",     "Telnet (plaintext)",           PortRisk.CRITICAL, "RFC 854"),
    25: PortInfo(25,  Protocol.TCP,  "SMTP",       "Simple Mail Transfer",         PortRisk.MODERATE, "RFC 5321"),
    53: PortInfo(53,  Protocol.BOTH, "DNS",        "Domain Name System",           PortRisk.SAFE,     "RFC 1035"),
    67: PortInfo(67,  Protocol.UDP,  "DHCP",       "DHCP Server",                  PortRisk.MODERATE, "RFC 2131"),
    68: PortInfo(68,  Protocol.UDP,  "DHCP",       "DHCP Client",                  PortRisk.MODERATE, "RFC 2131"),
    69: PortInfo(69,  Protocol.UDP,  "TFTP",       "Trivial File Transfer",        PortRisk.HIGH,     "RFC 1350"),
    80: PortInfo(80,  Protocol.TCP,  "HTTP",       "Hypertext Transfer Protocol",  PortRisk.MODERATE, "RFC 9110"),
    110: PortInfo(110, Protocol.TCP, "POP3",       "Post Office Protocol 3",       PortRisk.MODERATE, "RFC 1939"),
    119: PortInfo(119, Protocol.TCP, "NNTP",       "Network News Transfer",        PortRisk.MODERATE, "RFC 3977"),
    123: PortInfo(123, Protocol.UDP, "NTP",        "Network Time Protocol",        PortRisk.SAFE,     "RFC 5905"),
    135: PortInfo(135, Protocol.TCP, "MSRPC",      "Microsoft RPC",                PortRisk.HIGH,     None),
    137: PortInfo(137, Protocol.UDP, "NetBIOS-NS", "NetBIOS Name Service",         PortRisk.HIGH,     "RFC 1001"),
    138: PortInfo(138, Protocol.UDP, "NetBIOS-DGM","NetBIOS Datagram",             PortRisk.HIGH,     "RFC 1001"),
    139: PortInfo(139, Protocol.TCP, "NetBIOS-SSN","NetBIOS Session",              PortRisk.HIGH,     "RFC 1001"),
    143: PortInfo(143, Protocol.TCP, "IMAP",       "Internet Message Access",      PortRisk.MODERATE, "RFC 9051"),
    161: PortInfo(161, Protocol.UDP, "SNMP",       "Simple Network Management",    PortRisk.HIGH,     "RFC 3411"),
    162: PortInfo(162, Protocol.UDP, "SNMPTRAP",   "SNMP Trap",                    PortRisk.HIGH,     "RFC 3411"),
    179: PortInfo(179, Protocol.TCP, "BGP",        "Border Gateway Protocol",      PortRisk.HIGH,     "RFC 4271"),
    194: PortInfo(194, Protocol.TCP, "IRC",        "Internet Relay Chat",          PortRisk.MODERATE, "RFC 1459"),
    389: PortInfo(389, Protocol.BOTH,"LDAP",       "Lightweight Dir Access",       PortRisk.MODERATE, "RFC 4511"),
    443: PortInfo(443, Protocol.TCP, "HTTPS",      "HTTP over TLS/SSL",            PortRisk.SAFE,     "RFC 9110"),
    445: PortInfo(445, Protocol.TCP, "SMB",        "Server Message Block",         PortRisk.CRITICAL, "RFC 7592"),
    465: PortInfo(465, Protocol.TCP, "SMTPS",      "SMTP over TLS",                PortRisk.SAFE,     None),
    514: PortInfo(514, Protocol.UDP, "SYSLOG",     "System Logging",               PortRisk.MODERATE, "RFC 5424"),
    515: PortInfo(515, Protocol.TCP, "LPD",        "Line Printer Daemon",          PortRisk.MODERATE, "RFC 1179"),
    587: PortInfo(587, Protocol.TCP, "SMTP-SUB",   "SMTP Submission",              PortRisk.SAFE,     "RFC 6409"),
    631: PortInfo(631, Protocol.TCP, "IPP",        "Internet Printing Protocol",   PortRisk.MODERATE, "RFC 8011"),
    636: PortInfo(636, Protocol.TCP, "LDAPS",      "LDAP over TLS",                PortRisk.SAFE,     "RFC 4511"),
    873: PortInfo(873, Protocol.TCP, "RSYNC",      "Remote File Sync",             PortRisk.MODERATE, None),
    989: PortInfo(989, Protocol.TCP, "FTPS-DATA",  "FTP over TLS (data)",          PortRisk.SAFE,     "RFC 4217"),
    990: PortInfo(990, Protocol.TCP, "FTPS",       "FTP over TLS (control)",       PortRisk.SAFE,     "RFC 4217"),
    993: PortInfo(993, Protocol.TCP, "IMAPS",      "IMAP over TLS",                PortRisk.SAFE,     "RFC 9051"),
    995: PortInfo(995, Protocol.TCP, "POP3S",      "POP3 over TLS",                PortRisk.SAFE,     "RFC 1939"),

    # ── Registered Ports (1024–49151) ────────────────────────────────────
    1080:  PortInfo(1080,  Protocol.TCP, "SOCKS",      "SOCKS Proxy",                  PortRisk.MODERATE, "RFC 1928"),
    1194:  PortInfo(1194,  Protocol.UDP, "OpenVPN",    "OpenVPN",                      PortRisk.SAFE,     None),
    1433:  PortInfo(1433,  Protocol.TCP, "MSSQL",      "Microsoft SQL Server",         PortRisk.HIGH,     None),
    1521:  PortInfo(1521,  Protocol.TCP, "OracleDB",   "Oracle Database",              PortRisk.HIGH,     None),
    1723:  PortInfo(1723,  Protocol.TCP, "PPTP",       "Point-to-Point Tunneling",     PortRisk.MODERATE, "RFC 2637"),
    1883:  PortInfo(1883,  Protocol.TCP, "MQTT",       "Message Queuing Telemetry",    PortRisk.MODERATE, None),
    2049:  PortInfo(2049,  Protocol.BOTH,"NFS",        "Network File System",          PortRisk.HIGH,     "RFC 7530"),
    2181:  PortInfo(2181,  Protocol.TCP, "Zookeeper",  "Apache ZooKeeper",             PortRisk.MODERATE, None),
    2375:  PortInfo(2375,  Protocol.TCP, "Docker",     "Docker API (insecure)",        PortRisk.CRITICAL, None),
    2376:  PortInfo(2376,  Protocol.TCP, "Docker-TLS", "Docker API (TLS)",             PortRisk.MODERATE, None),
    3000:  PortInfo(3000,  Protocol.TCP, "Dev-HTTP",   "Development HTTP (Node/Ruby)", PortRisk.MODERATE, None),
    3306:  PortInfo(3306,  Protocol.TCP, "MySQL",      "MySQL / MariaDB",              PortRisk.HIGH,     None),
    3389:  PortInfo(3389,  Protocol.TCP, "RDP",        "Remote Desktop Protocol",      PortRisk.CRITICAL, "MS-RDPBCGR"),
    4369:  PortInfo(4369,  Protocol.TCP, "Erlang",     "Erlang Port Mapper (EPMD)",    PortRisk.HIGH,     None),
    4444:  PortInfo(4444,  Protocol.TCP, "Metasploit", "Metasploit default shell",     PortRisk.CRITICAL, None),
    5000:  PortInfo(5000,  Protocol.TCP, "Flask/UPnP", "Flask dev / UPnP",             PortRisk.MODERATE, None),
    5432:  PortInfo(5432,  Protocol.TCP, "PostgreSQL", "PostgreSQL Database",          PortRisk.HIGH,     None),
    5601:  PortInfo(5601,  Protocol.TCP, "Kibana",     "Elastic Kibana UI",            PortRisk.MODERATE, None),
    5672:  PortInfo(5672,  Protocol.TCP, "AMQP",       "RabbitMQ AMQP",                PortRisk.MODERATE, None),
    5900:  PortInfo(5900,  Protocol.TCP, "VNC",        "Virtual Network Computing",    PortRisk.HIGH,     None),
    6379:  PortInfo(6379,  Protocol.TCP, "Redis",      "Redis In-Memory Store",        PortRisk.CRITICAL, None),
    6443:  PortInfo(6443,  Protocol.TCP, "k8s-API",    "Kubernetes API Server",        PortRisk.HIGH,     None),
    7001:  PortInfo(7001,  Protocol.TCP, "WebLogic",   "Oracle WebLogic Server",       PortRisk.HIGH,     None),
    8080:  PortInfo(8080,  Protocol.TCP, "HTTP-Alt",   "Alternate HTTP / Tomcat",      PortRisk.MODERATE, None),
    8443:  PortInfo(8443,  Protocol.TCP, "HTTPS-Alt",  "Alternate HTTPS",              PortRisk.MODERATE, None),
    8888:  PortInfo(8888,  Protocol.TCP, "Jupyter",    "Jupyter Notebook",             PortRisk.MODERATE, None),
    9000:  PortInfo(9000,  Protocol.TCP, "SonarQube",  "SonarQube / PHP-FPM",          PortRisk.MODERATE, None),
    9090:  PortInfo(9090,  Protocol.TCP, "Prometheus", "Prometheus Metrics",           PortRisk.MODERATE, None),
    9092:  PortInfo(9092,  Protocol.TCP, "Kafka",      "Apache Kafka Broker",          PortRisk.MODERATE, None),
    9200:  PortInfo(9200,  Protocol.TCP, "Elastic",    "Elasticsearch HTTP API",       PortRisk.CRITICAL, None),
    9300:  PortInfo(9300,  Protocol.TCP, "Elastic-T",  "Elasticsearch Transport",      PortRisk.HIGH,     None),
    11211: PortInfo(11211, Protocol.BOTH,"Memcached",  "Memcached Cache",              PortRisk.CRITICAL, None),
    15672: PortInfo(15672, Protocol.TCP, "RabbitMQ-UI","RabbitMQ Management UI",       PortRisk.MODERATE, None),
    27017: PortInfo(27017, Protocol.TCP, "MongoDB",    "MongoDB Database",             PortRisk.CRITICAL, None),
    27018: PortInfo(27018, Protocol.TCP, "MongoDB-S",  "MongoDB Shard",                PortRisk.HIGH,     None),
    50000: PortInfo(50000, Protocol.TCP, "SAP",        "SAP Application Server",       PortRisk.HIGH,     None),
}

# Быстрый поиск сервиса по имени
_PORT_BY_SERVICE: Dict[str, List[PortInfo]] = {}
for _p in PORTS.values():
    _PORT_BY_SERVICE.setdefault(_p.service.upper(), []).append(_p)


def get_port(number: int) -> Optional[PortInfo]:
    """Вернуть информацию о порте по его номеру."""
    return PORTS.get(number)


def find_ports_by_service(name: str) -> List[PortInfo]:
    """Вернуть список портов, связанных с сервисом (регистронезависимо)."""
    return _PORT_BY_SERVICE.get(name.upper(), [])


def get_risky_ports(risk: PortRisk = PortRisk.HIGH) -> List[PortInfo]:
    """Вернуть все порты с уровнем риска >= указанного."""
    levels = [PortRisk.SAFE, PortRisk.MODERATE, PortRisk.HIGH, PortRisk.CRITICAL]
    threshold = levels.index(risk)
    return [p for p in PORTS.values() if levels.index(p.risk) >= threshold]


# ─────────────────────────────────────────────────────────────────────────────
#  РАСШИРЕНИЯ ФАЙЛОВ
# ─────────────────────────────────────────────────────────────────────────────

FILE_EXTENSIONS: Dict[str, FileExtension] = {
    ext.ext: ext for ext in [
        # ── Текстовые / Разметка ──────────────────────────────────────────
        FileExtension("txt",   "Text",     "Plain text",                  "text/plain"),
        FileExtension("md",    "Text",     "Markdown",                    "text/markdown"),
        FileExtension("rst",   "Text",     "reStructuredText",            "text/x-rst"),
        FileExtension("rtf",   "Text",     "Rich Text Format",            "application/rtf"),
        FileExtension("csv",   "Data",     "Comma-Separated Values",      "text/csv"),
        FileExtension("tsv",   "Data",     "Tab-Separated Values",        "text/tab-separated-values"),
        FileExtension("log",   "Text",     "Log file",                    "text/plain"),

        # ── Код ───────────────────────────────────────────────────────────
        FileExtension("py",    "Code",  "Python source",        "text/x-python",     is_code=True),
        FileExtension("pyc",   "Code",  "Python bytecode",      "application/x-python-bytecode", is_binary=True, is_code=True),
        FileExtension("pyi",   "Code",  "Python stub",          "text/x-python",     is_code=True),
        FileExtension("js",    "Code",  "JavaScript",           "text/javascript",   is_code=True),
        FileExtension("mjs",   "Code",  "ES Module JS",         "text/javascript",   is_code=True),
        FileExtension("ts",    "Code",  "TypeScript",           "text/typescript",   is_code=True),
        FileExtension("jsx",   "Code",  "React JSX",            "text/jsx",          is_code=True),
        FileExtension("tsx",   "Code",  "React TSX",            "text/tsx",          is_code=True),
        FileExtension("c",     "Code",  "C source",             "text/x-c",          is_code=True),
        FileExtension("cpp",   "Code",  "C++ source",           "text/x-c++",        is_code=True),
        FileExtension("h",     "Code",  "C/C++ header",         "text/x-c",          is_code=True),
        FileExtension("cs",    "Code",  "C# source",            "text/plain",        is_code=True),
        FileExtension("java",  "Code",  "Java source",          "text/x-java",       is_code=True),
        FileExtension("kt",    "Code",  "Kotlin source",        "text/plain",        is_code=True),
        FileExtension("go",    "Code",  "Go source",            "text/x-go",         is_code=True),
        FileExtension("rs",    "Code",  "Rust source",          "text/x-rust",       is_code=True),
        FileExtension("rb",    "Code",  "Ruby source",          "text/x-ruby",       is_code=True),
        FileExtension("php",   "Code",  "PHP source",           "application/x-php", is_code=True),
        FileExtension("swift", "Code",  "Swift source",         "text/x-swift",      is_code=True),
        FileExtension("lua",   "Code",  "Lua script",           "text/x-lua",        is_code=True),
        FileExtension("r",     "Code",  "R script",             "text/x-r",          is_code=True),
        FileExtension("sh",    "Code",  "Shell script",         "application/x-sh",  is_code=True),
        FileExtension("bash",  "Code",  "Bash script",          "application/x-sh",  is_code=True),
        FileExtension("zsh",   "Code",  "Zsh script",           "application/x-sh",  is_code=True),
        FileExtension("ps1",   "Code",  "PowerShell script",    "text/plain",        is_code=True),
        FileExtension("pl",    "Code",  "Perl script",          "text/x-perl",       is_code=True),
        FileExtension("sql",   "Code",  "SQL script",           "application/sql",   is_code=True),
        FileExtension("asm",   "Code",  "Assembly source",      "text/plain",        is_code=True),

        # ── Веб ───────────────────────────────────────────────────────────
        FileExtension("html",  "Web",   "HTML document",        "text/html",         is_code=True),
        FileExtension("htm",   "Web",   "HTML document",        "text/html",         is_code=True),
        FileExtension("css",   "Web",   "CSS stylesheet",       "text/css",          is_code=True),
        FileExtension("scss",  "Web",   "SCSS stylesheet",      "text/x-scss",       is_code=True),
        FileExtension("less",  "Web",   "LESS stylesheet",      "text/x-less",       is_code=True),
        FileExtension("xml",   "Data",  "XML document",         "application/xml"),
        FileExtension("json",  "Data",  "JSON data",            "application/json"),
        FileExtension("yaml",  "Data",  "YAML data",            "application/yaml"),
        FileExtension("yml",   "Data",  "YAML data",            "application/yaml"),
        FileExtension("toml",  "Data",  "TOML config",          "application/toml"),
        FileExtension("ini",   "Config","INI config",           "text/plain"),
        FileExtension("env",   "Config","Environment file",     "text/plain"),
        FileExtension("conf",  "Config","Generic config",       "text/plain"),
        FileExtension("cfg",   "Config","Generic config",       "text/plain"),

        # ── Документы ─────────────────────────────────────────────────────
        FileExtension("pdf",   "Doc",   "PDF document",         "application/pdf",   is_binary=True),
        FileExtension("doc",   "Doc",   "Word 97-2003",         "application/msword",                                      is_binary=True),
        FileExtension("docx",  "Doc",   "Word 2007+",           "application/vnd.openxmlformats-officedocument.wordprocessingml.document", is_binary=True),
        FileExtension("xls",   "Doc",   "Excel 97-2003",        "application/vnd.ms-excel",                                is_binary=True),
        FileExtension("xlsx",  "Doc",   "Excel 2007+",          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",      is_binary=True),
        FileExtension("ppt",   "Doc",   "PowerPoint 97-2003",   "application/vnd.ms-powerpoint",                           is_binary=True),
        FileExtension("pptx",  "Doc",   "PowerPoint 2007+",     "application/vnd.openxmlformats-officedocument.presentationml.presentation", is_binary=True),
        FileExtension("odt",   "Doc",   "OpenDocument Text",    "application/vnd.oasis.opendocument.text",                 is_binary=True),

        # ── Изображения ───────────────────────────────────────────────────
        FileExtension("jpg",   "Image", "JPEG image",           "image/jpeg",        is_binary=True, is_media=True),
        FileExtension("jpeg",  "Image", "JPEG image",           "image/jpeg",        is_binary=True, is_media=True),
        FileExtension("png",   "Image", "PNG image",            "image/png",         is_binary=True, is_media=True),
        FileExtension("gif",   "Image", "GIF image",            "image/gif",         is_binary=True, is_media=True),
        FileExtension("bmp",   "Image", "Bitmap image",         "image/bmp",         is_binary=True, is_media=True),
        FileExtension("svg",   "Image", "SVG vector",           "image/svg+xml"),
        FileExtension("webp",  "Image", "WebP image",           "image/webp",        is_binary=True, is_media=True),
        FileExtension("ico",   "Image", "Icon file",            "image/x-icon",      is_binary=True, is_media=True),
        FileExtension("tiff",  "Image", "TIFF image",           "image/tiff",        is_binary=True, is_media=True),
        FileExtension("raw",   "Image", "RAW camera image",     "image/x-raw",       is_binary=True, is_media=True),
        FileExtension("psd",   "Image", "Photoshop document",   "image/vnd.adobe.photoshop", is_binary=True, is_media=True),

        # ── Аудио / Видео ─────────────────────────────────────────────────
        FileExtension("mp3",   "Audio", "MP3 audio",            "audio/mpeg",        is_binary=True, is_media=True),
        FileExtension("wav",   "Audio", "WAV audio",            "audio/wav",         is_binary=True, is_media=True),
        FileExtension("flac",  "Audio", "FLAC lossless",        "audio/flac",        is_binary=True, is_media=True),
        FileExtension("ogg",   "Audio", "OGG audio",            "audio/ogg",         is_binary=True, is_media=True),
        FileExtension("aac",   "Audio", "AAC audio",            "audio/aac",         is_binary=True, is_media=True),
        FileExtension("mp4",   "Video", "MP4 video",            "video/mp4",         is_binary=True, is_media=True),
        FileExtension("mkv",   "Video", "Matroska video",       "video/x-matroska",  is_binary=True, is_media=True),
        FileExtension("avi",   "Video", "AVI video",            "video/avi",         is_binary=True, is_media=True),
        FileExtension("mov",   "Video", "QuickTime video",      "video/quicktime",   is_binary=True, is_media=True),
        FileExtension("webm",  "Video", "WebM video",           "video/webm",        is_binary=True, is_media=True),

        # ── Архивы ────────────────────────────────────────────────────────
        FileExtension("zip",   "Archive","ZIP archive",         "application/zip",           is_binary=True, is_archive=True),
        FileExtension("tar",   "Archive","TAR archive",         "application/x-tar",         is_binary=True, is_archive=True),
        FileExtension("gz",    "Archive","GZIP compressed",     "application/gzip",          is_binary=True, is_archive=True),
        FileExtension("bz2",   "Archive","BZIP2 compressed",    "application/x-bzip2",       is_binary=True, is_archive=True),
        FileExtension("xz",    "Archive","XZ compressed",       "application/x-xz",          is_binary=True, is_archive=True),
        FileExtension("7z",    "Archive","7-Zip archive",       "application/x-7z-compressed",is_binary=True, is_archive=True),
        FileExtension("rar",   "Archive","RAR archive",         "application/vnd.rar",       is_binary=True, is_archive=True),
        FileExtension("zst",   "Archive","Zstandard compressed","application/zstd",           is_binary=True, is_archive=True),
        FileExtension("lz4",   "Archive","LZ4 compressed",      "application/x-lz4",         is_binary=True, is_archive=True),

        # ── Исполняемые / Бинарные ────────────────────────────────────────
        FileExtension("exe",   "Binary", "Windows executable",  "application/vnd.microsoft.portable-executable", is_binary=True),
        FileExtension("dll",   "Binary", "Windows library",     "application/vnd.microsoft.portable-executable", is_binary=True),
        FileExtension("so",    "Binary", "Shared object (ELF)", "application/x-sharedlib",   is_binary=True),
        FileExtension("elf",   "Binary", "ELF binary",          "application/x-executable",  is_binary=True),
        FileExtension("deb",   "Package","Debian package",      "application/vnd.debian.binary-package", is_binary=True, is_archive=True),
        FileExtension("rpm",   "Package","RPM package",         "application/x-rpm",         is_binary=True, is_archive=True),
        FileExtension("apk",   "Package","Android package",     "application/vnd.android.package-archive", is_binary=True, is_archive=True),
        FileExtension("dmg",   "Package","macOS disk image",    "application/x-apple-diskimage", is_binary=True),

        # ── Базы данных ───────────────────────────────────────────────────
        FileExtension("db",    "Database","Generic database",   "application/octet-stream",  is_binary=True),
        FileExtension("sqlite","Database","SQLite database",    "application/x-sqlite3",      is_binary=True),
        FileExtension("sqlite3","Database","SQLite 3 database", "application/x-sqlite3",      is_binary=True),
        FileExtension("mdb",   "Database","Access database",    "application/msaccess",       is_binary=True),

        # ── Ключи / Сертификаты ───────────────────────────────────────────
        FileExtension("pem",   "Crypto", "PEM certificate/key", "application/x-pem-file"),
        FileExtension("crt",   "Crypto", "Certificate",         "application/x-x509-ca-cert"),
        FileExtension("cer",   "Crypto", "Certificate (DER)",   "application/pkix-cert",     is_binary=True),
        FileExtension("key",   "Crypto", "Private key",         "application/pkcs8"),
        FileExtension("p12",   "Crypto", "PKCS#12 keystore",    "application/x-pkcs12",      is_binary=True),
        FileExtension("pfx",   "Crypto", "PKCS#12 (Windows)",   "application/x-pkcs12",      is_binary=True),
        FileExtension("gpg",   "Crypto", "GPG encrypted data",  "application/pgp-encrypted",  is_binary=True),
        FileExtension("asc",   "Crypto", "GPG ASCII armor",     "application/pgp-signature"),

        # ── Шрифты ────────────────────────────────────────────────────────
        FileExtension("ttf",   "Font",   "TrueType font",       "font/ttf",          is_binary=True),
        FileExtension("otf",   "Font",   "OpenType font",       "font/otf",          is_binary=True),
        FileExtension("woff",  "Font",   "Web Open Font",       "font/woff",         is_binary=True),
        FileExtension("woff2", "Font",   "Web Open Font 2",     "font/woff2",        is_binary=True),
    ]
}


def get_extension(ext: str) -> Optional[FileExtension]:
    """Информация о расширении (без точки, регистронезависимо)."""
    return FILE_EXTENSIONS.get(ext.lstrip(".").lower())


def extensions_by_category(category: str) -> List[FileExtension]:
    """Все расширения из заданной категории."""
    return [e for e in FILE_EXTENSIONS.values() if e.category.lower() == category.lower()]


def is_safe_to_open(ext: str) -> bool:
    """Безопасно ли открывать файл с этим расширением (не исполняемый)."""
    info = get_extension(ext)
    if info is None:
        return False
    return info.category not in ("Binary", "Package") and not info.is_binary or info.is_media


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP КОДЫ
# ─────────────────────────────────────────────────────────────────────────────

HTTP_STATUSES: Dict[int, HttpStatus] = {
    s.code: s for s in [
        # 1xx Informational
        HttpStatus(100, "Continue",                        "Клиент должен продолжить запрос",                "RFC 9110"),
        HttpStatus(101, "Switching Protocols",             "Сервер переключает протоколы",                   "RFC 9110"),
        HttpStatus(102, "Processing",                      "Запрос принят, обрабатывается",                  "RFC 2518"),
        HttpStatus(103, "Early Hints",                     "Предварительные заголовки",                      "RFC 8297"),

        # 2xx Success
        HttpStatus(200, "OK",                              "Запрос выполнен успешно",                        "RFC 9110"),
        HttpStatus(201, "Created",                         "Ресурс создан",                                  "RFC 9110"),
        HttpStatus(202, "Accepted",                        "Запрос принят, обработка не завершена",          "RFC 9110"),
        HttpStatus(203, "Non-Authoritative Information",   "Информация из стороннего источника",             "RFC 9110"),
        HttpStatus(204, "No Content",                      "Успех, тело ответа отсутствует",                 "RFC 9110"),
        HttpStatus(205, "Reset Content",                   "Сброс содержимого",                              "RFC 9110"),
        HttpStatus(206, "Partial Content",                 "Частичный ответ (Range-запрос)",                 "RFC 9110"),
        HttpStatus(207, "Multi-Status",                    "Несколько статусов (WebDAV)",                    "RFC 4918"),
        HttpStatus(208, "Already Reported",                "Уже сообщено (WebDAV)",                          "RFC 5842"),
        HttpStatus(226, "IM Used",                         "Instance Manipulations применены",               "RFC 3229"),

        # 3xx Redirection
        HttpStatus(300, "Multiple Choices",                "Несколько вариантов ответа",                     "RFC 9110"),
        HttpStatus(301, "Moved Permanently",               "Постоянное перенаправление",                     "RFC 9110"),
        HttpStatus(302, "Found",                           "Временное перенаправление",                      "RFC 9110"),
        HttpStatus(303, "See Other",                       "Смотрите другой ресурс (POST→GET)",              "RFC 9110"),
        HttpStatus(304, "Not Modified",                    "Ресурс не изменился (кеш актуален)",             "RFC 9110"),
        HttpStatus(307, "Temporary Redirect",              "Временный редирект (метод сохраняется)",         "RFC 9110"),
        HttpStatus(308, "Permanent Redirect",              "Постоянный редирект (метод сохраняется)",        "RFC 9110"),

        # 4xx Client Error
        HttpStatus(400, "Bad Request",                     "Некорректный запрос",                            "RFC 9110", is_error=True),
        HttpStatus(401, "Unauthorized",                    "Требуется аутентификация",                       "RFC 9110", is_error=True),
        HttpStatus(402, "Payment Required",                "Требуется оплата",                               "RFC 9110", is_error=True),
        HttpStatus(403, "Forbidden",                       "Доступ запрещён",                                "RFC 9110", is_error=True),
        HttpStatus(404, "Not Found",                       "Ресурс не найден",                               "RFC 9110", is_error=True),
        HttpStatus(405, "Method Not Allowed",              "Метод не разрешён",                              "RFC 9110", is_error=True),
        HttpStatus(406, "Not Acceptable",                  "Неприемлемый формат ответа",                     "RFC 9110", is_error=True),
        HttpStatus(407, "Proxy Authentication Required",   "Требуется аутентификация прокси",                "RFC 9110", is_error=True),
        HttpStatus(408, "Request Timeout",                 "Тайм-аут запроса",                               "RFC 9110", is_error=True),
        HttpStatus(409, "Conflict",                        "Конфликт состояния ресурса",                     "RFC 9110", is_error=True),
        HttpStatus(410, "Gone",                            "Ресурс удалён безвозвратно",                     "RFC 9110", is_error=True),
        HttpStatus(411, "Length Required",                 "Требуется Content-Length",                       "RFC 9110", is_error=True),
        HttpStatus(412, "Precondition Failed",             "Предусловие не выполнено",                       "RFC 9110", is_error=True),
        HttpStatus(413, "Content Too Large",               "Тело запроса слишком большое",                   "RFC 9110", is_error=True),
        HttpStatus(414, "URI Too Long",                    "URI слишком длинный",                            "RFC 9110", is_error=True),
        HttpStatus(415, "Unsupported Media Type",          "Неподдерживаемый тип данных",                    "RFC 9110", is_error=True),
        HttpStatus(416, "Range Not Satisfiable",           "Диапазон не может быть удовлетворён",            "RFC 9110", is_error=True),
        HttpStatus(417, "Expectation Failed",              "Ожидание не выполнено",                          "RFC 9110", is_error=True),
        HttpStatus(418, "I'm a teapot",                    "Я — чайник (RFC 2324)",                          "RFC 2324", is_error=True),
        HttpStatus(421, "Misdirected Request",             "Запрос направлен не тому серверу",               "RFC 9110", is_error=True),
        HttpStatus(422, "Unprocessable Content",           "Семантически некорректный запрос",               "RFC 9110", is_error=True),
        HttpStatus(423, "Locked",                          "Ресурс заблокирован (WebDAV)",                   "RFC 4918", is_error=True),
        HttpStatus(424, "Failed Dependency",               "Зависимость не выполнена (WebDAV)",              "RFC 4918", is_error=True),
        HttpStatus(425, "Too Early",                       "Слишком ранний запрос (TLS 0-RTT)",              "RFC 8470", is_error=True),
        HttpStatus(426, "Upgrade Required",                "Требуется обновление протокола",                 "RFC 9110", is_error=True),
        HttpStatus(428, "Precondition Required",           "Требуется предусловие",                          "RFC 6585", is_error=True),
        HttpStatus(429, "Too Many Requests",               "Слишком много запросов (rate limit)",            "RFC 6585", is_error=True),
        HttpStatus(431, "Request Header Fields Too Large", "Заголовки запроса слишком большие",              "RFC 6585", is_error=True),
        HttpStatus(451, "Unavailable For Legal Reasons",   "Недоступно по юридическим причинам",             "RFC 7725", is_error=True),

        # 5xx Server Error
        HttpStatus(500, "Internal Server Error",           "Внутренняя ошибка сервера",                      "RFC 9110", is_error=True),
        HttpStatus(501, "Not Implemented",                 "Метод не реализован",                            "RFC 9110", is_error=True),
        HttpStatus(502, "Bad Gateway",                     "Неверный ответ от вышестоящего сервера",         "RFC 9110", is_error=True),
        HttpStatus(503, "Service Unavailable",             "Сервис недоступен",                              "RFC 9110", is_error=True),
        HttpStatus(504, "Gateway Timeout",                 "Тайм-аут от вышестоящего сервера",               "RFC 9110", is_error=True),
        HttpStatus(505, "HTTP Version Not Supported",      "Версия HTTP не поддерживается",                  "RFC 9110", is_error=True),
        HttpStatus(506, "Variant Also Negotiates",         "Циклические переговоры о варианте",              "RFC 2295", is_error=True),
        HttpStatus(507, "Insufficient Storage",            "Недостаточно места (WebDAV)",                    "RFC 4918", is_error=True),
        HttpStatus(508, "Loop Detected",                   "Обнаружен цикл (WebDAV)",                        "RFC 5842", is_error=True),
        HttpStatus(510, "Not Extended",                    "Требуется расширение запроса",                   "RFC 2774", is_error=True),
        HttpStatus(511, "Network Authentication Required", "Требуется сетевая аутентификация",               "RFC 6585", is_error=True),
    ]
}


def get_http_status(code: int) -> Optional[HttpStatus]:
    return HTTP_STATUSES.get(code)


def http_statuses_by_category(category: str) -> List[HttpStatus]:
    """Коды по категории: 'Success', 'Client Error', 'Server Error', etc."""
    return [s for s in HTTP_STATUSES.values() if s.category.lower() == category.lower()]


# ─────────────────────────────────────────────────────────────────────────────
#  СТРАНЫ
# ─────────────────────────────────────────────────────────────────────────────

COUNTRIES: Dict[str, Country] = {
    c.iso2: c for c in [
        Country("AF","AFG","Афганистан",         "Кабул",          "Asia",    "Southern Asia",        ".af", "+93"),
        Country("AL","ALB","Албания",             "Тирана",         "Europe",  "Southern Europe",      ".al", "+355"),
        Country("DZ","DZA","Алжир",              "Алжир",          "Africa",  "Northern Africa",      ".dz", "+213"),
        Country("AD","AND","Андорра",             "Андорра-ла-Велья","Europe", "Southern Europe",      ".ad", "+376"),
        Country("AO","AGO","Ангола",              "Луанда",         "Africa",  "Middle Africa",        ".ao", "+244"),
        Country("AG","ATG","Антигуа и Барбуда",   "Сент-Джонс",     "Americas","Caribbean",           ".ag", "+1-268"),
        Country("AR","ARG","Аргентина",           "Буэнос-Айрес",   "Americas","South America",       ".ar", "+54"),
        Country("AM","ARM","Армения",             "Ереван",         "Asia",    "Western Asia",         ".am", "+374"),
        Country("AU","AUS","Австралия",           "Канберра",       "Oceania", "Australia and NZ",     ".au", "+61"),
        Country("AT","AUT","Австрия",             "Вена",           "Europe",  "Western Europe",       ".at", "+43"),
        Country("AZ","AZE","Азербайджан",         "Баку",           "Asia",    "Western Asia",         ".az", "+994"),
        Country("BS","BHS","Багамы",              "Нассау",         "Americas","Caribbean",            ".bs", "+1-242"),
        Country("BH","BHR","Бахрейн",             "Манама",         "Asia",    "Western Asia",         ".bh", "+973"),
        Country("BD","BGD","Бангладеш",           "Дакка",          "Asia",    "Southern Asia",        ".bd", "+880"),
        Country("BY","BLR","Беларусь",            "Минск",          "Europe",  "Eastern Europe",       ".by", "+375"),
        Country("BE","BEL","Бельгия",             "Брюссель",       "Europe",  "Western Europe",       ".be", "+32"),
        Country("BZ","BLZ","Белиз",               "Бельмопан",      "Americas","Central America",      ".bz", "+501"),
        Country("BJ","BEN","Бенин",               "Порто-Ново",     "Africa",  "Western Africa",       ".bj", "+229"),
        Country("BT","BTN","Бутан",               "Тхимпху",        "Asia",    "Southern Asia",        ".bt", "+975"),
        Country("BO","BOL","Боливия",             "Сукре",          "Americas","South America",        ".bo", "+591"),
        Country("BA","BIH","Босния и Герцеговина","Сараево",        "Europe",  "Southern Europe",      ".ba", "+387"),
        Country("BW","BWA","Ботсвана",            "Габороне",       "Africa",  "Southern Africa",      ".bw", "+267"),
        Country("BR","BRA","Бразилия",            "Бразилиа",       "Americas","South America",        ".br", "+55"),
        Country("BN","BRN","Бруней",              "Бандар-Сери-Бегаван","Asia","South-Eastern Asia",  ".bn", "+673"),
        Country("BG","BGR","Болгария",            "София",          "Europe",  "Eastern Europe",       ".bg", "+359"),
        Country("BF","BFA","Буркина-Фасо",        "Уагадугу",       "Africa",  "Western Africa",       ".bf", "+226"),
        Country("BI","BDI","Бурунди",             "Гитега",         "Africa",  "Eastern Africa",       ".bi", "+257"),
        Country("CV","CPV","Кабо-Верде",          "Прая",           "Africa",  "Western Africa",       ".cv", "+238"),
        Country("KH","KHM","Камбоджа",            "Пномпень",       "Asia",    "South-Eastern Asia",   ".kh", "+855"),
        Country("CM","CMR","Камерун",             "Яунде",          "Africa",  "Middle Africa",        ".cm", "+237"),
        Country("CA","CAN","Канада",              "Оттава",         "Americas","Northern America",     ".ca", "+1"),
        Country("CF","CAF","ЦАР",                 "Банги",          "Africa",  "Middle Africa",        ".cf", "+236"),
        Country("TD","TCD","Чад",                 "Нджамена",       "Africa",  "Middle Africa",        ".td", "+235"),
        Country("CL","CHL","Чили",                "Сантьяго",       "Americas","South America",        ".cl", "+56"),
        Country("CN","CHN","Китай",               "Пекин",          "Asia",    "Eastern Asia",         ".cn", "+86"),
        Country("CO","COL","Колумбия",            "Богота",         "Americas","South America",        ".co", "+57"),
        Country("KM","COM","Коморские острова",   "Морони",         "Africa",  "Eastern Africa",       ".km", "+269"),
        Country("CG","COG","Конго",               "Браззавиль",     "Africa",  "Middle Africa",        ".cg", "+242"),
        Country("CD","COD","ДР Конго",            "Киншаса",        "Africa",  "Middle Africa",        ".cd", "+243"),
        Country("CR","CRI","Коста-Рика",          "Сан-Хосе",       "Americas","Central America",      ".cr", "+506"),
        Country("HR","HRV","Хорватия",            "Загреб",         "Europe",  "Southern Europe",      ".hr", "+385"),
        Country("CU","CUB","Куба",                "Гавана",         "Americas","Caribbean",            ".cu", "+53"),
        Country("CY","CYP","Кипр",                "Никосия",        "Asia",    "Western Asia",         ".cy", "+357"),
        Country("CZ","CZE","Чехия",               "Прага",          "Europe",  "Eastern Europe",       ".cz", "+420"),
        Country("DK","DNK","Дания",               "Копенгаген",     "Europe",  "Northern Europe",      ".dk", "+45"),
        Country("DJ","DJI","Джибути",             "Джибути",        "Africa",  "Eastern Africa",       ".dj", "+253"),
        Country("DO","DOM","Доминиканская Республика","Санто-Доминго","Americas","Caribbean",          ".do", "+1-809"),
        Country("EC","ECU","Эквадор",             "Кито",           "Americas","South America",        ".ec", "+593"),
        Country("EG","EGY","Египет",              "Каир",           "Africa",  "Northern Africa",      ".eg", "+20"),
        Country("SV","SLV","Сальвадор",           "Сан-Сальвадор",  "Americas","Central America",      ".sv", "+503"),
        Country("GQ","GNQ","Экваториальная Гвинея","Малабо",        "Africa",  "Middle Africa",        ".gq", "+240"),
        Country("ER","ERI","Эритрея",             "Асмэра",         "Africa",  "Eastern Africa",       ".er", "+291"),
        Country("EE","EST","Эстония",             "Таллин",         "Europe",  "Northern Europe",      ".ee", "+372"),
        Country("SZ","SWZ","Эсватини",            "Мбабане",        "Africa",  "Southern Africa",      ".sz", "+268"),
        Country("ET","ETH","Эфиопия",             "Аддис-Абеба",    "Africa",  "Eastern Africa",       ".et", "+251"),
        Country("FJ","FJI","Фиджи",               "Сува",           "Oceania", "Melanesia",            ".fj", "+679"),
        Country("FI","FIN","Финляндия",           "Хельсинки",      "Europe",  "Northern Europe",      ".fi", "+358"),
        Country("FR","FRA","Франция",             "Париж",          "Europe",  "Western Europe",       ".fr", "+33"),
        Country("GA","GAB","Габон",               "Либревиль",      "Africa",  "Middle Africa",        ".ga", "+241"),
        Country("GM","GMB","Гамбия",              "Банжул",         "Africa",  "Western Africa",       ".gm", "+220"),
        Country("GE","GEO","Грузия",              "Тбилиси",        "Asia",    "Western Asia",         ".ge", "+995"),
        Country("DE","DEU","Германия",            "Берлин",         "Europe",  "Western Europe",       ".de", "+49"),
        Country("GH","GHA","Гана",                "Аккра",          "Africa",  "Western Africa",       ".gh", "+233"),
        Country("GR","GRC","Греция",              "Афины",          "Europe",  "Southern Europe",      ".gr", "+30"),
        Country("GT","GTM","Гватемала",           "Гватемала-Сити", "Americas","Central America",      ".gt", "+502"),
        Country("GN","GIN","Гвинея",              "Конакри",        "Africa",  "Western Africa",       ".gn", "+224"),
        Country("GW","GNB","Гвинея-Бисау",        "Бисау",          "Africa",  "Western Africa",       ".gw", "+245"),
        Country("GY","GUY","Гайана",              "Джорджтаун",     "Americas","South America",        ".gy", "+592"),
        Country("HT","HTI","Гаити",               "Порт-о-Пренс",   "Americas","Caribbean",            ".ht", "+509"),
        Country("HN","HND","Гондурас",            "Тегусигальпа",   "Americas","Central America",      ".hn", "+504"),
        Country("HU","HUN","Венгрия",             "Будапешт",       "Europe",  "Eastern Europe",       ".hu", "+36"),
        Country("IS","ISL","Исландия",            "Рейкьявик",      "Europe",  "Northern Europe",      ".is", "+354"),
        Country("IN","IND","Индия",               "Нью-Дели",       "Asia",    "Southern Asia",        ".in", "+91"),
        Country("ID","IDN","Индонезия",           "Джакарта",       "Asia",    "South-Eastern Asia",   ".id", "+62"),
        Country("IR","IRN","Иран",                "Тегеран",        "Asia",    "Southern Asia",        ".ir", "+98"),
        Country("IQ","IRQ","Ирак",                "Багдад",         "Asia",    "Western Asia",         ".iq", "+964"),
        Country("IE","IRL","Ирландия",            "Дублин",         "Europe",  "Northern Europe",      ".ie", "+353"),
        Country("IL","ISR","Израиль",             "Иерусалим",      "Asia",    "Western Asia",         ".il", "+972"),
        Country("IT","ITA","Италия",              "Рим",            "Europe",  "Southern Europe",      ".it", "+39"),
        Country("JM","JAM","Ямайка",              "Кингстон",       "Americas","Caribbean",            ".jm", "+1-876"),
        Country("JP","JPN","Япония",              "Токио",          "Asia",    "Eastern Asia",         ".jp", "+81"),
        Country("JO","JOR","Иордания",            "Амман",          "Asia",    "Western Asia",         ".jo", "+962"),
        Country("KZ","KAZ","Казахстан",           "Астана",         "Asia",    "Central Asia",         ".kz", "+7"),
        Country("KE","KEN","Кения",               "Найроби",        "Africa",  "Eastern Africa",       ".ke", "+254"),
        Country("KI","KIR","Кирибати",            "Южная Тарава",   "Oceania", "Micronesia",           ".ki", "+686"),
        Country("KW","KWT","Кувейт",              "Эль-Кувейт",     "Asia",    "Western Asia",         ".kw", "+965"),
        Country("KG","KGZ","Кыргызстан",          "Бишкек",         "Asia",    "Central Asia",         ".kg", "+996"),
        Country("LA","LAO","Лаос",                "Вьентьян",       "Asia",    "South-Eastern Asia",   ".la", "+856"),
        Country("LV","LVA","Латвия",              "Рига",           "Europe",  "Northern Europe",      ".lv", "+371"),
        Country("LB","LBN","Ливан",               "Бейрут",         "Asia",    "Western Asia",         ".lb", "+961"),
        Country("LS","LSO","Лесото",              "Масеру",         "Africa",  "Southern Africa",      ".ls", "+266"),
        Country("LR","LBR","Либерия",             "Монровия",       "Africa",  "Western Africa",       ".lr", "+231"),
        Country("LY","LBY","Ливия",               "Триполи",        "Africa",  "Northern Africa",      ".ly", "+218"),
        Country("LI","LIE","Лихтенштейн",         "Вадуц",          "Europe",  "Western Europe",       ".li", "+423"),
        Country("LT","LTU","Литва",               "Вильнюс",        "Europe",  "Northern Europe",      ".lt", "+370"),
        Country("LU","LUX","Люксембург",           "Люксембург",     "Europe",  "Western Europe",       ".lu", "+352"),
        Country("MG","MDG","Мадагаскар",           "Антананариву",   "Africa",  "Eastern Africa",       ".mg", "+261"),
        Country("MW","MWI","Малави",               "Лилонгве",       "Africa",  "Eastern Africa",       ".mw", "+265"),
        Country("MY","MYS","Малайзия",             "Куала-Лумпур",   "Asia",    "South-Eastern Asia",   ".my", "+60"),
        Country("MV","MDV","Мальдивы",             "Мале",           "Asia",    "Southern Asia",        ".mv", "+960"),
        Country("ML","MLI","Мали",                 "Бамако",         "Africa",  "Western Africa",       ".ml", "+223"),
        Country("MT","MLT","Мальта",               "Валлетта",       "Europe",  "Southern Europe",      ".mt", "+356"),
        Country("MH","MHL","Маршалловы острова",   "Маджуро",        "Oceania", "Micronesia",           ".mh", "+692"),
        Country("MR","MRT","Мавритания",           "Нуакшот",        "Africa",  "Western Africa",       ".mr", "+222"),
        Country("MU","MUS","Маврикий",             "Порт-Луи",       "Africa",  "Eastern Africa",       ".mu", "+230"),
        Country("MX","MEX","Мексика",              "Мехико",         "Americas","Central America",      ".mx", "+52"),
        Country("FM","FSM","Микронезия",           "Паликир",        "Oceania", "Micronesia",           ".fm", "+691"),
        Country("MD","MDA","Молдова",              "Кишинёв",        "Europe",  "Eastern Europe",       ".md", "+373"),
        Country("MC","MCO","Монако",               "Монако",         "Europe",  "Western Europe",       ".mc", "+377"),
        Country("MN","MNG","Монголия",             "Улан-Батор",     "Asia",    "Eastern Asia",         ".mn", "+976"),
        Country("ME","MNE","Черногория",           "Подгорица",      "Europe",  "Southern Europe",      ".me", "+382"),
        Country("MA","MAR","Марокко",              "Рабат",          "Africa",  "Northern Africa",      ".ma", "+212"),
        Country("MZ","MOZ","Мозамбик",             "Мапуту",         "Africa",  "Eastern Africa",       ".mz", "+258"),
        Country("MM","MMR","Мьянма",               "Нейпьидо",       "Asia",    "South-Eastern Asia",   ".mm", "+95"),
        Country("NA","NAM","Намибия",              "Виндхук",        "Africa",  "Southern Africa",      ".na", "+264"),
        Country("NR","NRU","Науру",                "Ярен",           "Oceania", "Micronesia",           ".nr", "+674"),
        Country("NP","NPL","Непал",                "Катманду",       "Asia",    "Southern Asia",        ".np", "+977"),
        Country("NL","NLD","Нидерланды",           "Амстердам",      "Europe",  "Western Europe",       ".nl", "+31"),
        Country("NZ","NZL","Новая Зеландия",       "Веллингтон",     "Oceania", "Australia and NZ",     ".nz", "+64"),
        Country("NI","NIC","Никарагуа",            "Манагуа",        "Americas","Central America",      ".ni", "+505"),
        Country("NE","NER","Нигер",                "Ниамей",         "Africa",  "Western Africa",       ".ne", "+227"),
        Country("NG","NGA","Нигерия",              "Абуджа",         "Africa",  "Western Africa",       ".ng", "+234"),
        Country("NO","NOR","Норвегия",             "Осло",           "Europe",  "Northern Europe",      ".no", "+47"),
        Country("OM","OMN","Оман",                 "Маскат",         "Asia",    "Western Asia",         ".om", "+968"),
        Country("PK","PAK","Пакистан",             "Исламабад",      "Asia",    "Southern Asia",        ".pk", "+92"),
        Country("PW","PLW","Палау",                "Нгерулмуд",      "Oceania", "Micronesia",           ".pw", "+680"),
        Country("PA","PAN","Панама",               "Панама",         "Americas","Central America",      ".pa", "+507"),
        Country("PG","PNG","Папуа — Новая Гвинея", "Порт-Морсби",   "Oceania", "Melanesia",            ".pg", "+675"),
        Country("PY","PRY","Парагвай",             "Асунсьон",       "Americas","South America",        ".py", "+595"),
        Country("PE","PER","Перу",                 "Лима",           "Americas","South America",        ".pe", "+51"),
        Country("PH","PHL","Филиппины",            "Манила",         "Asia",    "South-Eastern Asia",   ".ph", "+63"),
        Country("PL","POL","Польша",               "Варшава",        "Europe",  "Eastern Europe",       ".pl", "+48"),
        Country("PT","PRT","Португалия",           "Лиссабон",       "Europe",  "Southern Europe",      ".pt", "+351"),
        Country("QA","QAT","Катар",                "Доха",           "Asia",    "Western Asia",         ".qa", "+974"),
        Country("RO","ROU","Румыния",              "Бухарест",       "Europe",  "Eastern Europe",       ".ro", "+40"),
        Country("RU","RUS","Россия",               "Москва",         "Europe",  "Eastern Europe",       ".ru", "+7"),
        Country("RW","RWA","Руанда",               "Кигали",         "Africa",  "Eastern Africa",       ".rw", "+250"),
        Country("WS","WSM","Самоа",                "Апиа",           "Oceania", "Polynesia",            ".ws", "+685"),
        Country("SM","SMR","Сан-Марино",           "Сан-Марино",     "Europe",  "Southern Europe",      ".sm", "+378"),
        Country("ST","STP","Сан-Томе и Принсипи",  "Сан-Томе",       "Africa",  "Middle Africa",        ".st", "+239"),
        Country("SA","SAU","Саудовская Аравия",    "Эр-Рияд",        "Asia",    "Western Asia",         ".sa", "+966"),
        Country("SN","SEN","Сенегал",              "Дакар",          "Africa",  "Western Africa",       ".sn", "+221"),
        Country("RS","SRB","Сербия",               "Белград",        "Europe",  "Southern Europe",      ".rs", "+381"),
        Country("SC","SYC","Сейшелы",              "Виктория",       "Africa",  "Eastern Africa",       ".sc", "+248"),
        Country("SL","SLE","Сьерра-Леоне",         "Фритаун",        "Africa",  "Western Africa",       ".sl", "+232"),
        Country("SG","SGP","Сингапур",             "Сингапур",       "Asia",    "South-Eastern Asia",   ".sg", "+65"),
        Country("SK","SVK","Словакия",             "Братислава",     "Europe",  "Eastern Europe",       ".sk", "+421"),
        Country("SI","SVN","Словения",             "Любляна",        "Europe",  "Southern Europe",      ".si", "+386"),
        Country("SB","SLB","Соломоновы острова",   "Хониара",        "Oceania", "Melanesia",            ".sb", "+677"),
        Country("SO","SOM","Сомали",               "Могадишо",       "Africa",  "Eastern Africa",       ".so", "+252"),
        Country("ZA","ZAF","Южная Африка",         "Претория",       "Africa",  "Southern Africa",      ".za", "+27"),
        Country("SS","SSD","Южный Судан",          "Джуба",          "Africa",  "Eastern Africa",       ".ss", "+211"),
        Country("ES","ESP","Испания",              "Мадрид",         "Europe",  "Southern Europe",      ".es", "+34"),
        Country("LK","LKA","Шри-Ланка",            "Коломбо",        "Asia",    "Southern Asia",        ".lk", "+94"),
        Country("SD","SDN","Судан",                "Хартум",         "Africa",  "Northern Africa",      ".sd", "+249"),
        Country("SR","SUR","Суринам",              "Парамарибо",     "Americas","South America",        ".sr", "+597"),
        Country("SE","SWE","Швеция",               "Стокгольм",      "Europe",  "Northern Europe",      ".se", "+46"),
        Country("CH","CHE","Швейцария",            "Берн",           "Europe",  "Western Europe",       ".ch", "+41"),
        Country("SY","SYR","Сирия",                "Дамаск",         "Asia",    "Western Asia",         ".sy", "+963"),
        Country("TW","TWN","Тайвань",              "Тайбэй",         "Asia",    "Eastern Asia",         ".tw", "+886"),
        Country("TJ","TJK","Таджикистан",          "Душанбе",        "Asia",    "Central Asia",         ".tj", "+992"),
        Country("TZ","TZA","Танзания",             "Додома",         "Africa",  "Eastern Africa",       ".tz", "+255"),
        Country("TH","THA","Таиланд",              "Бангкок",        "Asia",    "South-Eastern Asia",   ".th", "+66"),
        Country("TL","TLS","Тимор-Лесте",          "Дили",           "Asia",    "South-Eastern Asia",   ".tl", "+670"),
        Country("TG","TGO","Того",                 "Ломе",           "Africa",  "Western Africa",       ".tg", "+228"),
        Country("TO","TON","Тонга",                "Нукуалофа",      "Oceania", "Polynesia",            ".to", "+676"),
        Country("TT","TTO","Тринидад и Тобаго",    "Порт-оф-Спейн",  "Americas","Caribbean",           ".tt", "+1-868"),
        Country("TN","TUN","Тунис",                "Тунис",          "Africa",  "Northern Africa",      ".tn", "+216"),
        Country("TR","TUR","Турция",               "Анкара",         "Asia",    "Western Asia",         ".tr", "+90"),
        Country("TM","TKM","Туркменистан",         "Ашхабад",        "Asia",    "Central Asia",         ".tm", "+993"),
        Country("TV","TUV","Тувалу",               "Фунафути",       "Oceania", "Polynesia",            ".tv", "+688"),
        Country("UG","UGA","Уганда",               "Кампала",        "Africa",  "Eastern Africa",       ".ug", "+256"),
        Country("UA","UKR","Украина",              "Киев",           "Europe",  "Eastern Europe",       ".ua", "+380"),
        Country("AE","ARE","ОАЭ",                  "Абу-Даби",       "Asia",    "Western Asia",         ".ae", "+971"),
        Country("GB","GBR","Великобритания",       "Лондон",         "Europe",  "Northern Europe",      ".uk", "+44"),
        Country("US","USA","США",                  "Вашингтон",      "Americas","Northern America",     ".us", "+1"),
        Country("UY","URY","Уругвай",              "Монтевидео",     "Americas","South America",        ".uy", "+598"),
        Country("UZ","UZB","Узбекистан",           "Ташкент",        "Asia",    "Central Asia",         ".uz", "+998"),
        Country("VU","VUT","Вануату",              "Порт-Вила",      "Oceania", "Melanesia",            ".vu", "+678"),
        Country("VE","VEN","Венесуэла",            "Каракас",        "Americas","South America",        ".ve", "+58"),
        Country("VN","VNM","Вьетнам",              "Ханой",          "Asia",    "South-Eastern Asia",   ".vn", "+84"),
        Country("YE","YEM","Йемен",                "Сана",           "Asia",    "Western Asia",         ".ye", "+967"),
        Country("ZM","ZMB","Замбия",               "Лусака",         "Africa",  "Eastern Africa",       ".zm", "+260"),
        Country("ZW","ZWE","Зимбабве",             "Харари",         "Africa",  "Eastern Africa",       ".zw", "+263"),
    ]
}


def get_country(iso2: str) -> Optional[Country]:
    return COUNTRIES.get(iso2.upper())


def countries_by_region(region: str) -> List[Country]:
    return [c for c in COUNTRIES.values() if c.region.lower() == region.lower()]


def countries_by_subregion(subregion: str) -> List[Country]:
    return [c for c in COUNTRIES.values() if subregion.lower() in c.subregion.lower()]


def find_country_by_tld(tld: str) -> Optional[Country]:
    tld = tld if tld.startswith(".") else f".{tld}"
    return next((c for c in COUNTRIES.values() if c.tld == tld.lower()), None)


def find_country_by_name(query: str) -> List[Country]:
    q = query.lower()
    return [c for c in COUNTRIES.values() if q in c.name.lower()]


# ─────────────────────────────────────────────────────────────────────────────
#  LINUX КОМАНДЫ
# ─────────────────────────────────────────────────────────────────────────────

LINUX_COMMANDS: Dict[str, LinuxCommand] = {
    cmd.name: cmd for cmd in [

        # ── Файлы и директории ────────────────────────────────────────────
        LinuxCommand(
            name="ls", category=CommandCategory.FILES,
            synopsis="Список файлов директории",
            description="Отображает содержимое директории. По умолчанию сортирует по алфавиту.",
            examples=("ls -lah /var/log", "ls -lt --color=auto", "ls -R ~/projects"),
            args=(LinuxArg("-l","Длинный формат"), LinuxArg("-a","Скрытые файлы"), LinuxArg("-h","Размеры в читаемом виде"),
                  LinuxArg("-t","Сортировка по времени"), LinuxArg("-r","Обратная сортировка"), LinuxArg("-R","Рекурсивно")),
            see_also=("tree","find","exa"),
        ),
        LinuxCommand(
            name="cd", category=CommandCategory.FILES,
            synopsis="Смена текущей директории",
            description="Меняет рабочую директорию. Встроенная команда shell.",
            examples=("cd /etc/nginx", "cd ~", "cd -", "cd ../.."),
            args=(LinuxArg("-","Предыдущая директория"), LinuxArg("~","Домашняя директория")),
            see_also=("pwd","pushd","popd"),
        ),
        LinuxCommand(
            name="pwd", category=CommandCategory.FILES,
            synopsis="Текущая рабочая директория",
            description="Печатает абсолютный путь к текущей рабочей директории.",
            examples=("pwd", "pwd -P"),
            args=(LinuxArg("-P","Физический путь (без симлинков)"), LinuxArg("-L","Логический путь")),
            see_also=("cd",),
        ),
        LinuxCommand(
            name="mkdir", category=CommandCategory.FILES,
            synopsis="Создание директорий",
            description="Создаёт одну или несколько директорий. С ключом -p создаёт весь путь.",
            examples=("mkdir -p /opt/app/{bin,conf,logs}", "mkdir -m 755 /srv/www"),
            args=(LinuxArg("-p","Создать промежуточные директории"), LinuxArg("-m MODE","Установить права")),
            see_also=("rmdir","touch"),
        ),
        LinuxCommand(
            name="rm", category=CommandCategory.FILES,
            synopsis="Удаление файлов и директорий",
            description="Удаляет файлы. С -r — директории рекурсивно. ВНИМАНИЕ: восстановление невозможно.",
            examples=("rm -rf /tmp/cache", "rm -i *.log", "rm -- -oddfile"),
            args=(LinuxArg("-r","Рекурсивно"), LinuxArg("-f","Принудительно (без подтверждения)"),
                  LinuxArg("-i","Интерактивный режим"), LinuxArg("-v","Вербозный вывод")),
            see_also=("shred","unlink","trash-cli"),
        ),
        LinuxCommand(
            name="cp", category=CommandCategory.FILES,
            synopsis="Копирование файлов и директорий",
            description="Копирует файлы или директории (с -r). Поддерживает сохранение атрибутов (-a).",
            examples=("cp -a /src /dst", "cp -uv *.conf /backup/", "cp --reflink=auto big.img dst/"),
            args=(LinuxArg("-a","Архивный режим (сохраняет всё)"), LinuxArg("-r","Рекурсивно"),
                  LinuxArg("-u","Только если источник новее"), LinuxArg("-v","Вербозный вывод"),
                  LinuxArg("-n","Не перезаписывать"), LinuxArg("-p","Сохранить атрибуты")),
            see_also=("mv","rsync","install"),
        ),
        LinuxCommand(
            name="mv", category=CommandCategory.FILES,
            synopsis="Перемещение / переименование файлов",
            description="Перемещает или переименовывает файлы и директории.",
            examples=("mv file.txt /archive/", "mv old_name new_name", "mv -n src dst"),
            args=(LinuxArg("-i","Запрос при перезаписи"), LinuxArg("-n","Не перезаписывать"),
                  LinuxArg("-v","Вербозный вывод"), LinuxArg("-u","Только если источник новее")),
            see_also=("cp","rename"),
        ),
        LinuxCommand(
            name="find", category=CommandCategory.FILES,
            synopsis="Поиск файлов по критериям",
            description="Рекурсивно ищет файлы/директории по имени, типу, правам, времени, размеру и т.д.",
            examples=(
                "find /var/log -name '*.log' -mtime +30 -delete",
                "find . -type f -size +100M -exec ls -lh {} +",
                "find /home -perm /o=w -not -type d",
            ),
            args=(LinuxArg("-name PAT","По имени (glob)"), LinuxArg("-type f/d/l","По типу"),
                  LinuxArg("-mtime N","По времени изменения"), LinuxArg("-size N","По размеру"),
                  LinuxArg("-perm MODE","По правам"), LinuxArg("-exec CMD","Выполнить команду"),
                  LinuxArg("-maxdepth N","Глубина рекурсии"), LinuxArg("-not","Инверсия условия")),
            see_also=("locate","fd","grep"),
        ),
        LinuxCommand(
            name="ln", category=CommandCategory.FILES,
            synopsis="Создание ссылок",
            description="Создаёт жёсткие или символические ссылки на файлы.",
            examples=("ln -s /usr/local/bin/python3 /usr/bin/python", "ln file hardlink"),
            args=(LinuxArg("-s","Символическая ссылка"), LinuxArg("-f","Принудительно"),
                  LinuxArg("-v","Вербозный вывод"), LinuxArg("-r","Относительный путь симлинка")),
            see_also=("readlink","realpath"),
        ),
        LinuxCommand(
            name="touch", category=CommandCategory.FILES,
            synopsis="Создание файла / обновление метки времени",
            description="Создаёт пустой файл или обновляет atime/mtime существующего.",
            examples=("touch newfile.txt", "touch -d '2024-01-01' file", "touch -r ref.txt target.txt"),
            args=(LinuxArg("-a","Только atime"), LinuxArg("-m","Только mtime"),
                  LinuxArg("-d DATE","Установить конкретную дату"), LinuxArg("-r FILE","Скопировать время с файла")),
            see_also=("stat","ls"),
        ),
        LinuxCommand(
            name="stat", category=CommandCategory.FILES,
            synopsis="Подробные метаданные файла",
            description="Отображает inode, права, UID/GID, размер, временны́е метки файла.",
            examples=("stat /etc/passwd", "stat -c '%n %s %U' /var/log/*.log"),
            args=(LinuxArg("-c FMT","Форматированный вывод"), LinuxArg("-f","Статистика файловой системы")),
            see_also=("ls","file","lsattr"),
        ),
        LinuxCommand(
            name="file", category=CommandCategory.FILES,
            synopsis="Определение типа файла",
            description="Использует магические байты для определения реального типа файла (не расширение).",
            examples=("file /usr/bin/python3", "file -i image.png", "file *"),
            args=(LinuxArg("-i","MIME-тип"), LinuxArg("-b","Без имени файла"), LinuxArg("-z","Проверить сжатые")),
            see_also=("xdg-open","mimetype"),
        ),
        LinuxCommand(
            name="du", category=CommandCategory.DISK,
            synopsis="Использование дискового пространства",
            description="Оценивает объём, занимаемый файлами и директориями.",
            examples=("du -sh /*", "du -ah --max-depth=1 /var | sort -hr", "du -c *.log"),
            args=(LinuxArg("-s","Итог для каждого аргумента"), LinuxArg("-h","Читаемый формат"),
                  LinuxArg("-a","Все файлы"), LinuxArg("--max-depth=N","Глубина"), LinuxArg("-c","Общий итог")),
            see_also=("df","ncdu","duf"),
        ),
        LinuxCommand(
            name="df", category=CommandCategory.DISK,
            synopsis="Свободное место на разделах",
            description="Показывает использование смонтированных файловых систем.",
            examples=("df -hT", "df -i", "df --output=source,size,used,avail,pcent,target"),
            args=(LinuxArg("-h","Читаемый формат"), LinuxArg("-T","Тип ФС"), LinuxArg("-i","Иноды"), LinuxArg("-l","Только локальные")),
            see_also=("du","lsblk","mount"),
        ),
        LinuxCommand(
            name="lsblk", category=CommandCategory.DISK,
            synopsis="Блочные устройства",
            description="Отображает дерево блочных устройств, разделов и точек монтирования.",
            examples=("lsblk -f", "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID"),
            args=(LinuxArg("-f","UUID и тип ФС"), LinuxArg("-d","Только устройства без разделов"),
                  LinuxArg("-o COLS","Выбрать столбцы"), LinuxArg("-J","JSON вывод")),
            see_also=("fdisk","blkid","parted"),
        ),
        LinuxCommand(
            name="mount", category=CommandCategory.DISK,
            synopsis="Монтирование файловых систем",
            description="Монтирует устройство к точке монтирования в дереве директорий.",
            examples=("mount /dev/sdb1 /mnt/usb", "mount -t tmpfs -o size=512m tmpfs /tmp/ram",
                      "mount -o remount,ro /"),
            args=(LinuxArg("-t TYPE","Тип ФС"), LinuxArg("-o OPTIONS","Опции"), LinuxArg("-a","Все из /etc/fstab"),
                  LinuxArg("-r","Только чтение")),
            see_also=("umount","fstab","lsblk"),
        ),

        # ── Текст ──────────────────────────────────────────────────────────
        LinuxCommand(
            name="cat", category=CommandCategory.TEXT,
            synopsis="Вывод содержимого файлов",
            description="Конкатенирует и выводит файлы на stdout.",
            examples=("cat /etc/os-release", "cat -n script.sh", "cat a.txt b.txt > combined.txt"),
            args=(LinuxArg("-n","Нумерация строк"), LinuxArg("-A","Показать спецсимволы"), LinuxArg("-s","Сжать пустые строки")),
            see_also=("less","bat","head","tail"),
        ),
        LinuxCommand(
            name="grep", category=CommandCategory.TEXT,
            synopsis="Поиск по шаблону в тексте",
            description="Ищет строки, соответствующие регулярному выражению. Поддерживает ERE (-E) и Perl (-P).",
            examples=(
                "grep -rn 'ERROR' /var/log/ --include='*.log'",
                "grep -P '\\d{1,3}(\\.\\d{1,3}){3}' access.log",
                "ps aux | grep -v grep | grep nginx",
            ),
            args=(LinuxArg("-r","Рекурсивно"), LinuxArg("-n","Номера строк"), LinuxArg("-i","Без учёта регистра"),
                  LinuxArg("-v","Инвертировать"), LinuxArg("-E","Расширенный regex"), LinuxArg("-P","Perl regex"),
                  LinuxArg("-l","Только имена файлов"), LinuxArg("-c","Количество совпадений"),
                  LinuxArg("-A N","N строк после"), LinuxArg("-B N","N строк до")),
            see_also=("sed","awk","rg"),
        ),
        LinuxCommand(
            name="sed", category=CommandCategory.TEXT,
            synopsis="Потоковый редактор текста",
            description="Построчно обрабатывает текст: замена, удаление, вставка, трансформации.",
            examples=(
                "sed -i 's/foo/bar/g' config.cfg",
                "sed -n '10,20p' file.txt",
                "sed '/^#/d' file.conf",
            ),
            args=(LinuxArg("-i[SUF]","Правка на месте"), LinuxArg("-n","Не выводить по умолчанию"),
                  LinuxArg("-e EXPR","Добавить выражение"), LinuxArg("-r/-E","Расширенный regex")),
            see_also=("awk","grep","tr","perl"),
        ),
        LinuxCommand(
            name="awk", category=CommandCategory.TEXT,
            synopsis="Обработка и анализ текста",
            description="Мощный язык для построчной обработки полей. Поддерживает арифметику, массивы, функции.",
            examples=(
                "awk '{print $1, $NF}' access.log",
                "awk -F: '$3 >= 1000 {print $1}' /etc/passwd",
                "awk 'NR%2==0' file.txt",
            ),
            args=(LinuxArg("-F SEP","Разделитель полей"), LinuxArg("-v VAR=VAL","Переменная"),
                  LinuxArg("-f FILE","Скрипт из файла")),
            see_also=("sed","cut","perl"),
        ),
        LinuxCommand(
            name="sort", category=CommandCategory.TEXT,
            synopsis="Сортировка строк",
            description="Сортирует строки файла. Поддерживает числовую, обратную и уникальную сортировку.",
            examples=("sort -t: -k3 -n /etc/passwd", "sort -u file.txt", "du -h | sort -hr"),
            args=(LinuxArg("-n","Числовая"), LinuxArg("-r","Обратная"), LinuxArg("-u","Уникальные"),
                  LinuxArg("-t SEP","Разделитель"), LinuxArg("-k N","По столбцу"), LinuxArg("-h","Читаемые размеры")),
            see_also=("uniq","join","comm"),
        ),
        LinuxCommand(
            name="uniq", category=CommandCategory.TEXT,
            synopsis="Фильтр дублирующихся строк",
            description="Убирает (или показывает) повторяющиеся смежные строки. Требует сортированного ввода.",
            examples=("sort file | uniq -c | sort -rn", "uniq -d file.txt", "uniq -u file.txt"),
            args=(LinuxArg("-c","Счётчик повторений"), LinuxArg("-d","Только дубли"), LinuxArg("-u","Только уникальные")),
            see_also=("sort","comm","diff"),
        ),
        LinuxCommand(
            name="wc", category=CommandCategory.TEXT,
            synopsis="Подсчёт строк, слов, байт",
            description="Считает строки (-l), слова (-w), символы (-c) или байты (-b).",
            examples=("wc -l /etc/passwd", "cat file | wc -w", "find . -name '*.py' | xargs wc -l"),
            args=(LinuxArg("-l","Строки"), LinuxArg("-w","Слова"), LinuxArg("-c","Байты"), LinuxArg("-m","Символы")),
            see_also=("grep","awk"),
        ),
        LinuxCommand(
            name="cut", category=CommandCategory.TEXT,
            synopsis="Извлечение столбцов из строк",
            description="Вырезает поля или диапазоны символов из каждой строки ввода.",
            examples=("cut -d: -f1,3 /etc/passwd", "cut -c1-80 file.txt", "cut -f2- data.tsv"),
            args=(LinuxArg("-d SEP","Разделитель"), LinuxArg("-f N","Поля"), LinuxArg("-c N","Символы")),
            see_also=("awk","tr","paste"),
        ),
        LinuxCommand(
            name="tr", category=CommandCategory.TEXT,
            synopsis="Замена / удаление символов",
            description="Транслитерирует или удаляет символы из stdin.",
            examples=("echo 'Hello' | tr '[:lower:]' '[:upper:]'", "tr -d '\\r' < dos.txt > unix.txt",
                      "tr -s ' ' < file.txt"),
            args=(LinuxArg("-d SET","Удалить символы"), LinuxArg("-s SET","Сжать повторы"), LinuxArg("-c SET","Дополнение")),
            see_also=("sed","awk"),
        ),
        LinuxCommand(
            name="head", category=CommandCategory.TEXT,
            synopsis="Первые строки файла",
            description="Выводит первые N строк (или байт) файла. По умолчанию 10 строк.",
            examples=("head -20 /var/log/syslog", "head -c 1M bigfile | xxd"),
            args=(LinuxArg("-n N","Количество строк"), LinuxArg("-c N","Количество байт")),
            see_also=("tail","cat","less"),
        ),
        LinuxCommand(
            name="tail", category=CommandCategory.TEXT,
            synopsis="Последние строки файла",
            description="Выводит последние N строк. С -f следит за файлом в реальном времени.",
            examples=("tail -f /var/log/nginx/error.log", "tail -n +5 file.txt", "tail -c 100 binary"),
            args=(LinuxArg("-n N","Строк"), LinuxArg("-f","Слежение за файлом"), LinuxArg("-F","Слежение (с рестартом"),
                  LinuxArg("-c N","Байт")),
            see_also=("head","less","multitail"),
        ),
        LinuxCommand(
            name="diff", category=CommandCategory.TEXT,
            synopsis="Сравнение файлов",
            description="Показывает различия между двумя файлами или директориями.",
            examples=("diff -u original.conf new.conf", "diff -rq dir1/ dir2/", "diff --color=always a b | less"),
            args=(LinuxArg("-u","Unified формат"), LinuxArg("-r","Рекурсивно"), LinuxArg("-q","Только сообщить о различиях"),
                  LinuxArg("-i","Без учёта регистра"), LinuxArg("-b","Игнорировать пробелы")),
            see_also=("patch","vimdiff","colordiff"),
        ),
        LinuxCommand(
            name="less", category=CommandCategory.TEXT,
            synopsis="Постраничный просмотр файлов",
            description="Просматривает текст с возможностью прокрутки, поиска (/) и навигации.",
            examples=("less +F /var/log/syslog", "less -N file.txt", "man bash | less"),
            args=(LinuxArg("-N","Номера строк"), LinuxArg("-S","Не переносить длинные строки"),
                  LinuxArg("-R","Цвета ANSI"), LinuxArg("+F","Режим слежения")),
            see_also=("more","bat","most"),
        ),

        # ── Процессы ──────────────────────────────────────────────────────
        LinuxCommand(
            name="ps", category=CommandCategory.PROCESS,
            synopsis="Статус запущенных процессов",
            description="Показывает снимок активных процессов. Широко используется как ps aux.",
            examples=("ps aux --sort=-%mem | head -20", "ps -ef | grep nginx", "ps -u www-data"),
            args=(LinuxArg("a","Все пользователи"), LinuxArg("u","Пользовательский формат"),
                  LinuxArg("x","Без терминала"), LinuxArg("-e","Все процессы"), LinuxArg("-f","Полный формат"),
                  LinuxArg("--sort=COL","Сортировка"), LinuxArg("-p PID","Конкретный PID")),
            see_also=("top","htop","pgrep","pstree"),
        ),
        LinuxCommand(
            name="top", category=CommandCategory.PROCESS,
            synopsis="Динамический мониторинг процессов",
            description="Интерактивный просмотр процессов с сортировкой по CPU/RAM в реальном времени.",
            examples=("top -bn1 | head -20", "top -p 1234,5678", "top -u nginx"),
            args=(LinuxArg("-b","Пакетный режим"), LinuxArg("-n N","Количество итераций"),
                  LinuxArg("-p PID","Фильтр по PID"), LinuxArg("-u USER","Фильтр по пользователю"),
                  LinuxArg("-d N","Интервал обновления")),
            see_also=("htop","atop","glances","btop"),
        ),
        LinuxCommand(
            name="kill", category=CommandCategory.PROCESS,
            synopsis="Отправка сигнала процессу",
            description="Посылает сигнал процессу по PID. По умолчанию SIGTERM (15).",
            examples=("kill -9 1234", "kill -HUP $(cat /run/nginx.pid)", "kill -l"),
            args=(LinuxArg("-s SIGNAL","Имя сигнала"), LinuxArg("-N","Номер сигнала"), LinuxArg("-l","Список сигналов")),
            see_also=("killall","pkill","signal"),
        ),
        LinuxCommand(
            name="killall", category=CommandCategory.PROCESS,
            synopsis="Убить процессы по имени",
            description="Отправляет сигнал всем процессам с заданным именем.",
            examples=("killall -9 chrome", "killall -HUP nginx", "killall -u baduser"),
            args=(LinuxArg("-9","SIGKILL"), LinuxArg("-HUP","SIGHUP"), LinuxArg("-u USER","По пользователю"),
                  LinuxArg("-q","Тихий режим")),
            see_also=("kill","pkill","pgrep"),
        ),
        LinuxCommand(
            name="pkill", category=CommandCategory.PROCESS,
            synopsis="Сигнал процессу по шаблону имени",
            description="Аналог killall, но принимает regex. Может фильтровать по UID, GID, терминалу.",
            examples=("pkill -f 'python manage.py'", "pkill -u deploy gunicorn"),
            args=(LinuxArg("-f","Сравнивать полную командную строку"), LinuxArg("-u USER","По пользователю"),
                  LinuxArg("-x","Точное совпадение")),
            see_also=("kill","pgrep","signal"),
        ),
        LinuxCommand(
            name="pgrep", category=CommandCategory.PROCESS,
            synopsis="Поиск PID по имени процесса",
            description="Возвращает PID процессов, соответствующих шаблону.",
            examples=("pgrep -a python", "pgrep -u root sshd", "kill $(pgrep defunct)"),
            args=(LinuxArg("-a","Показать командную строку"), LinuxArg("-u USER","По пользователю"),
                  LinuxArg("-x","Точное имя"), LinuxArg("-l","Имя + PID")),
            see_also=("pkill","ps","pidof"),
        ),
        LinuxCommand(
            name="nice", category=CommandCategory.PROCESS,
            synopsis="Запуск процесса с приоритетом",
            description="Запускает команду с заданным nice-значением (от -20 до +19). Выше = менее жадный.",
            examples=("nice -n 19 make -j4", "nice -n -5 ffmpeg -i in.mp4 out.mkv"),
            args=(LinuxArg("-n N","Nice value"),),
            see_also=("renice","ionice","chrt"),
        ),
        LinuxCommand(
            name="renice", category=CommandCategory.PROCESS,
            synopsis="Изменение приоритета существующего процесса",
            description="Меняет nice-значение уже запущенного процесса.",
            examples=("renice -n 10 -p 1234", "renice -n -5 -u nginx"),
            args=(LinuxArg("-n N","Nice value"), LinuxArg("-p PID","По PID"), LinuxArg("-u USER","По пользователю")),
            see_also=("nice","ionice"),
        ),
        LinuxCommand(
            name="nohup", category=CommandCategory.PROCESS,
            synopsis="Запуск без привязки к терминалу",
            description="Запускает команду, игнорируя SIGHUP. Процесс продолжает работать после выхода из сессии.",
            examples=("nohup ./server.py &", "nohup python worker.py > worker.log 2>&1 &"),
            args=(LinuxArg("&","Фон"),),
            see_also=("disown","screen","tmux","systemd-run"),
        ),
        LinuxCommand(
            name="strace", category=CommandCategory.PROCESS,
            synopsis="Трассировка системных вызовов",
            description="Перехватывает и записывает системные вызовы, выполняемые процессом.",
            examples=("strace -p 1234 -e trace=network", "strace -o trace.txt ls /", "strace -c find /"),
            args=(LinuxArg("-p PID","Подключиться к процессу"), LinuxArg("-e trace=SET","Фильтр вызовов"),
                  LinuxArg("-o FILE","Вывод в файл"), LinuxArg("-c","Статистика"), LinuxArg("-f","Следить за fork")),
            see_also=("ltrace","perf","ftrace"),
        ),

        # ── Сеть ──────────────────────────────────────────────────────────
        LinuxCommand(
            name="ip", category=CommandCategory.NETWORK,
            synopsis="Управление сетевыми интерфейсами / маршрутами",
            description="Современная замена ifconfig/route. Управляет адресами, маршрутами, соседями, туннелями.",
            examples=(
                "ip addr show eth0",
                "ip route add 10.0.0.0/8 via 192.168.1.1",
                "ip link set eth0 up",
                "ip -s link",
            ),
            args=(LinuxArg("addr","Адреса"), LinuxArg("route","Маршруты"), LinuxArg("link","Интерфейсы"),
                  LinuxArg("neigh","ARP/NDP таблица"), LinuxArg("-s","Статистика"), LinuxArg("-j","JSON вывод")),
            see_also=("ifconfig","ss","netstat","iw"),
        ),
        LinuxCommand(
            name="ss", category=CommandCategory.NETWORK,
            synopsis="Статистика сокетов (замена netstat)",
            description="Показывает TCP/UDP/Unix сокеты, слушающие порты, соединения. Быстрее netstat.",
            examples=("ss -tulnp", "ss -s", "ss -t state established", "ss -xp"),
            args=(LinuxArg("-t","TCP"), LinuxArg("-u","UDP"), LinuxArg("-l","Слушающие"),
                  LinuxArg("-n","Числовые адреса"), LinuxArg("-p","Процессы"), LinuxArg("-s","Сводка")),
            see_also=("netstat","lsof","ip"),
        ),
        LinuxCommand(
            name="ping", category=CommandCategory.NETWORK,
            synopsis="Проверка доступности хоста",
            description="Отправляет ICMP ECHO_REQUEST пакеты и измеряет RTT.",
            examples=("ping -c 4 8.8.8.8", "ping -I eth0 -s 1400 google.com", "ping6 ::1"),
            args=(LinuxArg("-c N","Количество пакетов"), LinuxArg("-i N","Интервал"), LinuxArg("-t TTL","TTL"),
                  LinuxArg("-s N","Размер пакета"), LinuxArg("-W N","Таймаут"), LinuxArg("-I IF","Интерфейс")),
            see_also=("traceroute","mtr","fping"),
        ),
        LinuxCommand(
            name="traceroute", category=CommandCategory.NETWORK,
            synopsis="Маршрут пакетов до хоста",
            description="Показывает каждый прыжок (hop) маршрута до цели с задержками RTT.",
            examples=("traceroute -n 8.8.8.8", "traceroute -T -p 443 google.com", "traceroute6 ipv6.google.com"),
            args=(LinuxArg("-n","Без DNS"), LinuxArg("-T","TCP SYN"), LinuxArg("-U","UDP"),
                  LinuxArg("-m N","Макс. хопов"), LinuxArg("-p PORT","Порт")),
            see_also=("mtr","ping","pathping"),
        ),
        LinuxCommand(
            name="curl", category=CommandCategory.NETWORK,
            synopsis="Передача данных с URL",
            description="Мощный HTTP/FTP/SCP/... клиент. Поддерживает заголовки, тело, аутентификацию, TLS.",
            examples=(
                "curl -s https://api.example.com/v1/status | jq .",
                "curl -X POST -H 'Content-Type: application/json' -d '{\"key\":\"val\"}' https://api.io/",
                "curl -o output.bin -# https://files.example.com/big.tar.gz",
                "curl -L -k --retry 3 --retry-delay 2 https://example.com",
            ),
            args=(LinuxArg("-s","Тихий режим"), LinuxArg("-o FILE","Вывод в файл"), LinuxArg("-O","Оригинальное имя"),
                  LinuxArg("-X METHOD","HTTP метод"), LinuxArg("-H 'K:V'","Заголовок"), LinuxArg("-d DATA","Тело"),
                  LinuxArg("-u USER:PASS","Аутентификация"), LinuxArg("-L","Следовать редиректам"),
                  LinuxArg("-k","Игнорировать TLS"), LinuxArg("-I","Только заголовки"), LinuxArg("--retry N","Повторы")),
            see_also=("wget","httpie","xh"),
        ),
        LinuxCommand(
            name="wget", category=CommandCategory.NETWORK,
            synopsis="Загрузка файлов по HTTP/FTP",
            description="Рекурсивная загрузка, зеркалирование сайтов, продолжение загрузки.",
            examples=("wget -c https://example.com/big.iso", "wget -r -np https://example.com/docs/",
                      "wget -q -O - https://api.io/ | jq ."),
            args=(LinuxArg("-c","Продолжить загрузку"), LinuxArg("-r","Рекурсивно"), LinuxArg("-q","Тихий режим"),
                  LinuxArg("-O FILE","Имя файла"), LinuxArg("-np","Не идти выше")),
            see_also=("curl","aria2c","lftp"),
        ),
        LinuxCommand(
            name="nmap", category=CommandCategory.NETWORK,
            synopsis="Сканер сети и портов",
            description="Обнаруживает хосты, открытые порты, сервисы и ОС. Поддерживает NSE-скрипты.",
            examples=(
                "nmap -sV -O 192.168.1.0/24",
                "nmap -p 80,443,8080 --open 10.0.0.0/8",
                "nmap -sC -sV -oA scan target.com",
            ),
            args=(LinuxArg("-sS","SYN scan"), LinuxArg("-sV","Версии сервисов"), LinuxArg("-O","Определить ОС"),
                  LinuxArg("-A","Агрессивный"), LinuxArg("-p PORTS","Порты"), LinuxArg("-sC","Скрипты по умолчанию"),
                  LinuxArg("-oN/-oX/-oA FILE","Вывод"), LinuxArg("--open","Только открытые")),
            see_also=("masscan","rustscan","zmap"),
        ),
        LinuxCommand(
            name="tcpdump", category=CommandCategory.NETWORK,
            synopsis="Захват сетевых пакетов",
            description="Перехватывает и анализирует сетевой трафик. Сохраняет в .pcap для Wireshark.",
            examples=("tcpdump -i eth0 -nn port 443", "tcpdump -w capture.pcap -C 100",
                      "tcpdump 'tcp and host 10.0.0.1 and not port 22'"),
            args=(LinuxArg("-i IF","Интерфейс"), LinuxArg("-w FILE","Записать в pcap"), LinuxArg("-r FILE","Читать pcap"),
                  LinuxArg("-n","Без DNS"), LinuxArg("-v/-vv/-vvv","Вербозность"), LinuxArg("-c N","Число пакетов")),
            see_also=("wireshark","tshark","scapy"),
        ),
        LinuxCommand(
            name="dig", category=CommandCategory.NETWORK,
            synopsis="DNS запросы",
            description="Выполняет DNS-запросы. Более гибкий, чем nslookup.",
            examples=("dig @8.8.8.8 example.com MX", "dig +short +trace example.com", "dig -x 8.8.8.8"),
            args=(LinuxArg("+short","Краткий вывод"), LinuxArg("+trace","Трассировка"), LinuxArg("-x IP","Обратный"),
                  LinuxArg("@SERVER","DNS сервер"), LinuxArg("TYPE","Тип записи: A,AAAA,MX,TXT,NS...")),
            see_also=("nslookup","host","drill"),
        ),
        LinuxCommand(
            name="iptables", category=CommandCategory.NETWORK,
            synopsis="Файрвол и NAT (IPv4)",
            description="Управляет правилами netfilter для фильтрации и NAT пакетов.",
            examples=(
                "iptables -L -n -v --line-numbers",
                "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT",
                "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
            ),
            args=(LinuxArg("-L","Список правил"), LinuxArg("-A CHAIN","Добавить правило"),
                  LinuxArg("-D CHAIN","Удалить"), LinuxArg("-I N","Вставить"), LinuxArg("-t TABLE","Таблица"),
                  LinuxArg("-n","Числовые адреса"), LinuxArg("-v","Счётчики"), LinuxArg("-F","Очистить")),
            see_also=("nftables","ufw","firewalld"),
        ),

        # ── Права доступа ─────────────────────────────────────────────────
        LinuxCommand(
            name="chmod", category=CommandCategory.PERMISSIONS,
            synopsis="Изменение прав доступа к файлам",
            description="Меняет биты прав (rwx) для владельца, группы и прочих. Поддерживает числовую и символьную запись.",
            examples=("chmod 755 /usr/local/bin/myapp", "chmod u+x,go-w script.sh",
                      "chmod -R 644 /var/www/html"),
            args=(LinuxArg("-R","Рекурсивно"), LinuxArg("-v","Вербозно"),
                  LinuxArg("u/g/o/a","Кому: user/group/other/all"),
                  LinuxArg("+/-/=","Добавить/убрать/установить")),
            see_also=("chown","chgrp","umask","stat","acl"),
        ),
        LinuxCommand(
            name="chown", category=CommandCategory.PERMISSIONS,
            synopsis="Изменение владельца файла",
            description="Меняет пользователя и/или группу-владельца файла.",
            examples=("chown -R www-data:www-data /var/www", "chown root: /usr/bin/myapp"),
            args=(LinuxArg("-R","Рекурсивно"), LinuxArg("USER:GROUP","Владелец:группа"), LinuxArg("--from=","От кого")),
            see_also=("chmod","chgrp","stat"),
        ),
        LinuxCommand(
            name="sudo", category=CommandCategory.PERMISSIONS,
            synopsis="Выполнение команды от имени другого пользователя",
            description="Позволяет запускать команды с привилегиями root или другого пользователя. Конфигурируется через sudoers.",
            examples=("sudo apt update && sudo apt upgrade -y", "sudo -u postgres psql", "sudo -l"),
            args=(LinuxArg("-u USER","От чьего имени"), LinuxArg("-l","Список разрешений"),
                  LinuxArg("-s","Shell"), LinuxArg("-i","Login shell"), LinuxArg("-E","Сохранить окружение")),
            see_also=("su","doas","visudo"),
        ),
        LinuxCommand(
            name="su", category=CommandCategory.PERMISSIONS,
            synopsis="Смена пользователя",
            description="Открывает сессию от имени другого пользователя. Без аргументов — root.",
            examples=("su - postgres", "su -c 'systemctl restart nginx' root"),
            args=(LinuxArg("-","Login shell с профилем"), LinuxArg("-c CMD","Выполнить команду")),
            see_also=("sudo","runuser"),
        ),

        # ── Архивация ─────────────────────────────────────────────────────
        LinuxCommand(
            name="tar", category=CommandCategory.ARCHIVE,
            synopsis="Архивирование и распаковка",
            description="Создаёт и распаковывает .tar архивы, в том числе сжатые (gz, bz2, xz, zst).",
            examples=(
                "tar -czf backup-$(date +%F).tar.gz /etc /home",
                "tar -xJf archive.tar.xz -C /tmp/",
                "tar --zstd -cf snapshot.tar.zst data/",
                "tar -tvf archive.tar.gz | head -20",
            ),
            args=(LinuxArg("-c","Создать"), LinuxArg("-x","Распаковать"), LinuxArg("-t","Содержимое"),
                  LinuxArg("-z","GZIP"), LinuxArg("-j","BZIP2"), LinuxArg("-J","XZ"), LinuxArg("--zstd","Zstandard"),
                  LinuxArg("-f FILE","Файл архива"), LinuxArg("-C DIR","Директория назначения"),
                  LinuxArg("-v","Вербозно"), LinuxArg("--exclude=PAT","Исключить")),
            see_also=("gzip","bzip2","xz","zstd","zip"),
        ),
        LinuxCommand(
            name="rsync", category=CommandCategory.ARCHIVE,
            synopsis="Эффективная синхронизация файлов",
            description="Синхронизирует файлы локально или по SSH. Передаёт только изменения (дельта).",
            examples=(
                "rsync -avz --progress /src/ user@host:/dst/",
                "rsync -a --delete --exclude='.git' /local/ /backup/",
                "rsync -avz -e 'ssh -p 2222' /data/ remote:/data/",
            ),
            args=(LinuxArg("-a","Архивный режим"), LinuxArg("-v","Вербозно"), LinuxArg("-z","Сжатие"),
                  LinuxArg("--delete","Удалять лишние"), LinuxArg("--exclude=","Исключить"),
                  LinuxArg("-n","Dry run"), LinuxArg("--progress","Прогресс"), LinuxArg("-e","Транспорт")),
            see_also=("scp","rclone","unison"),
        ),

        # ── Система ────────────────────────────────────────────────────────
        LinuxCommand(
            name="systemctl", category=CommandCategory.SYSTEM,
            synopsis="Управление systemd-сервисами",
            description="Основной инструмент управления systemd: запуск, остановка, статус, включение сервисов.",
            examples=(
                "systemctl status nginx",
                "systemctl restart --now postgresql",
                "systemctl list-units --type=service --state=failed",
                "systemctl daemon-reload && systemctl enable --now myapp.service",
            ),
            args=(LinuxArg("start/stop/restart/reload","Управление"), LinuxArg("enable/disable","Автозапуск"),
                  LinuxArg("status","Статус"), LinuxArg("list-units","Список юнитов"),
                  LinuxArg("daemon-reload","Перечитать конфиги"), LinuxArg("--now","Действие + enable/disable"),
                  LinuxArg("-t TYPE","Тип юнита"), LinuxArg("--state=","Фильтр состояния")),
            see_also=("journalctl","service","init"),
        ),
        LinuxCommand(
            name="journalctl", category=CommandCategory.SYSTEM,
            synopsis="Просмотр системных логов (journald)",
            description="Читает структурированные логи systemd. Фильтрует по сервису, времени, уровню.",
            examples=(
                "journalctl -u nginx -f",
                "journalctl -p err -S '2024-01-01' -U '2024-01-02'",
                "journalctl --disk-usage && journalctl --vacuum-time=30d",
            ),
            args=(LinuxArg("-u UNIT","Сервис"), LinuxArg("-f","Следить"), LinuxArg("-p LEVEL","Уровень приоритета"),
                  LinuxArg("-S/-U DATE","Начало/конец"), LinuxArg("-n N","Строк"), LinuxArg("-b","Текущая загрузка"),
                  LinuxArg("--no-pager","Без пейджера"), LinuxArg("-o json","JSON формат")),
            see_also=("systemctl","syslog","dmesg"),
        ),
        LinuxCommand(
            name="dmesg", category=CommandCategory.HARDWARE,
            synopsis="Кольцевой буфер ядра",
            description="Показывает сообщения ядра: инициализацию оборудования, ошибки драйверов, сеть.",
            examples=("dmesg -T | tail -50", "dmesg --level=err,warn", "dmesg -w"),
            args=(LinuxArg("-T","Метки времени"), LinuxArg("-H","Читаемый формат"),
                  LinuxArg("--level=","Фильтр уровней"), LinuxArg("-w","Следить")),
            see_also=("journalctl","syslog"),
        ),
        LinuxCommand(
            name="uname", category=CommandCategory.SYSTEM,
            synopsis="Информация о ядре и системе",
            description="Выводит имя ядра, версию, архитектуру и другую системную информацию.",
            examples=("uname -a", "uname -r", "uname -m"),
            args=(LinuxArg("-a","Всё"), LinuxArg("-r","Версия ядра"), LinuxArg("-m","Архитектура"),
                  LinuxArg("-n","Имя хоста"), LinuxArg("-s","Имя ОС")),
            see_also=("hostnamectl","lscpu","neofetch"),
        ),
        LinuxCommand(
            name="uptime", category=CommandCategory.SYSTEM,
            synopsis="Время работы системы и LA",
            description="Показывает текущее время, uptime, число пользователей и load average (1/5/15 мин).",
            examples=("uptime", "uptime -p", "uptime -s"),
            args=(LinuxArg("-p","Читаемый формат"), LinuxArg("-s","Время запуска")),
            see_also=("w","who","last"),
        ),
        LinuxCommand(
            name="free", category=CommandCategory.SYSTEM,
            synopsis="Использование памяти",
            description="Показывает общее, использованное и свободное ОЗУ и swap.",
            examples=("free -h", "free -m -s 2", "watch -n 1 free -h"),
            args=(LinuxArg("-h","Читаемый формат"), LinuxArg("-m","Мегабайты"), LinuxArg("-g","Гигабайты"),
                  LinuxArg("-s N","Обновление каждые N секунд")),
            see_also=("vmstat","htop","/proc/meminfo"),
        ),
        LinuxCommand(
            name="vmstat", category=CommandCategory.SYSTEM,
            synopsis="Статистика виртуальной памяти",
            description="Показывает процессы, память, swap, IO, CPU по интервалам.",
            examples=("vmstat 1 10", "vmstat -s", "vmstat -d"),
            args=(LinuxArg("DELAY COUNT","Интервал и число итераций"), LinuxArg("-s","Сводка"),
                  LinuxArg("-d","Диски"), LinuxArg("-t","Метка времени")),
            see_also=("free","iostat","sar"),
        ),
        LinuxCommand(
            name="crontab", category=CommandCategory.SYSTEM,
            synopsis="Управление задачами cron",
            description="Редактирует, просматривает и удаляет пользовательские cron-задания.",
            examples=("crontab -e", "crontab -l", "crontab -u nginx -l"),
            args=(LinuxArg("-e","Редактировать"), LinuxArg("-l","Список"), LinuxArg("-r","Удалить"),
                  LinuxArg("-u USER","Для пользователя")),
            see_also=("at","systemd.timer","fcron"),
        ),
        LinuxCommand(
            name="env", category=CommandCategory.SHELL,
            synopsis="Переменные окружения",
            description="Выводит переменные окружения или запускает программу с изменённым окружением.",
            examples=("env | sort", "env -i HOME=/tmp bash", "env DEBUG=1 python app.py"),
            args=(LinuxArg("-i","Пустое окружение"), LinuxArg("-u VAR","Убрать переменную")),
            see_also=("export","printenv","set"),
        ),
        LinuxCommand(
            name="echo", category=CommandCategory.SHELL,
            synopsis="Вывод текста на stdout",
            description="Встроенная команда shell для вывода строк. С -e обрабатывает escape-последовательности.",
            examples=("echo -e '\\e[32mGreen\\e[0m'", "echo $PATH", "echo -n 'no newline'"),
            args=(LinuxArg("-e","Escape-последовательности"), LinuxArg("-n","Без переноса строки")),
            see_also=("printf","tput"),
        ),

        # ── Пользователи ──────────────────────────────────────────────────
        LinuxCommand(
            name="useradd", category=CommandCategory.USERS,
            synopsis="Создание пользователя",
            description="Создаёт нового пользователя в системе. Требует root.",
            examples=("useradd -m -s /bin/bash -G sudo alice", "useradd -r -s /sbin/nologin nginx"),
            args=(LinuxArg("-m","Создать домашнюю директорию"), LinuxArg("-s SHELL","Login shell"),
                  LinuxArg("-G GROUPS","Доп. группы"), LinuxArg("-r","Системный пользователь"),
                  LinuxArg("-u UID","Явный UID")),
            see_also=("usermod","userdel","passwd","adduser"),
        ),
        LinuxCommand(
            name="usermod", category=CommandCategory.USERS,
            synopsis="Изменение параметров пользователя",
            description="Меняет группы, shell, домашнюю директорию и другие атрибуты пользователя.",
            examples=("usermod -aG docker alice", "usermod -s /bin/zsh bob", "usermod -L alice"),
            args=(LinuxArg("-aG GROUPS","Добавить в группы"), LinuxArg("-s SHELL","Сменить shell"),
                  LinuxArg("-L","Заблокировать"), LinuxArg("-U","Разблокировать"), LinuxArg("-d DIR","Домашняя")),
            see_also=("useradd","passwd","chsh"),
        ),
        LinuxCommand(
            name="passwd", category=CommandCategory.USERS,
            synopsis="Смена пароля пользователя",
            description="Устанавливает или меняет пароль учётной записи. Root может менять пароли любых пользователей.",
            examples=("passwd alice", "passwd -l alice", "passwd -e alice", "passwd -d alice"),
            args=(LinuxArg("-l","Заблокировать"), LinuxArg("-u","Разблокировать"),
                  LinuxArg("-e","Срок истёк (сменить при следующем входе)"), LinuxArg("-d","Удалить пароль")),
            see_also=("chage","shadow","usermod"),
        ),
        LinuxCommand(
            name="who", category=CommandCategory.USERS,
            synopsis="Залогиненные пользователи",
            description="Показывает кто сейчас вошёл в систему, с какого терминала и когда.",
            examples=("who", "who -H", "who am i"),
            args=(LinuxArg("-H","Заголовок"), LinuxArg("-b","Время последней загрузки"), LinuxArg("-r","Run level")),
            see_also=("w","last","users"),
        ),

        # ── Безопасность ──────────────────────────────────────────────────
        LinuxCommand(
            name="ssh", category=CommandCategory.SECURITY,
            synopsis="Подключение по SSH",
            description="Клиент SSH для удалённого выполнения команд и туннелирования.",
            examples=(
                "ssh -i ~/.ssh/id_ed25519 alice@10.0.0.1",
                "ssh -L 8080:localhost:80 jump.host",
                "ssh -J bastion.example.com prod-server",
            ),
            args=(LinuxArg("-i FILE","Ключ"), LinuxArg("-p PORT","Порт"), LinuxArg("-L","Local tunnel"),
                  LinuxArg("-R","Remote tunnel"), LinuxArg("-D PORT","Dynamic (SOCKS)"),
                  LinuxArg("-J HOST","Jump host"), LinuxArg("-N","Не выполнять команды"),
                  LinuxArg("-o OPT=VAL","Опция")),
            see_also=("scp","sftp","mosh","ssh-keygen"),
        ),
        LinuxCommand(
            name="ssh-keygen", category=CommandCategory.SECURITY,
            synopsis="Генерация SSH-ключей",
            description="Создаёт пары ключей: Ed25519 (рекомендован), RSA, ECDSA. Управляет authorized_keys.",
            examples=(
                "ssh-keygen -t ed25519 -C 'alice@work' -f ~/.ssh/id_ed25519",
                "ssh-keygen -t rsa -b 4096",
                "ssh-keygen -lf ~/.ssh/id_ed25519.pub",
            ),
            args=(LinuxArg("-t TYPE","Тип: ed25519/rsa/ecdsa"), LinuxArg("-b BITS","Длина ключа"),
                  LinuxArg("-C COMMENT","Комментарий"), LinuxArg("-f FILE","Файл"),
                  LinuxArg("-l","Отпечаток"), LinuxArg("-p","Сменить парольную фразу")),
            see_also=("ssh","ssh-copy-id","ssh-agent"),
        ),
        LinuxCommand(
            name="openssl", category=CommandCategory.SECURITY,
            synopsis="Криптографические операции",
            description="Swiss-army knife для TLS/SSL, сертификатов, шифрования, хешей.",
            examples=(
                "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes",
                "openssl s_client -connect example.com:443 -servername example.com",
                "openssl dgst -sha256 -sign key.pem -out sig.bin file.txt",
                "openssl enc -aes-256-cbc -pbkdf2 -in plain.txt -out cipher.bin",
            ),
            args=(LinuxArg("req","Запрос сертификата"), LinuxArg("x509","Работа с сертификатами"),
                  LinuxArg("s_client","TLS клиент"), LinuxArg("dgst","Хеши/подписи"),
                  LinuxArg("enc","Шифрование"), LinuxArg("rsa/ec","Ключи")),
            see_also=("cfssl","certbot","gpg"),
        ),
        LinuxCommand(
            name="gpg", category=CommandCategory.SECURITY,
            synopsis="Шифрование и подпись (OpenPGP)",
            description="GNU Privacy Guard: шифрование, расшифровка, подпись и проверка файлов и сообщений.",
            examples=(
                "gpg --full-generate-key",
                "gpg --encrypt --recipient alice@example.com file.txt",
                "gpg --sign --armor document.pdf",
                "gpg --verify document.pdf.asc document.pdf",
            ),
            args=(LinuxArg("--encrypt/-e","Зашифровать"), LinuxArg("--decrypt/-d","Расшифровать"),
                  LinuxArg("--sign/-s","Подписать"), LinuxArg("--verify","Проверить"),
                  LinuxArg("--list-keys","Список ключей"), LinuxArg("--armor/-a","ASCII вывод"),
                  LinuxArg("--recipient","Получатель")),
            see_also=("openssl","age","minisign"),
        ),
        LinuxCommand(
            name="auditctl", category=CommandCategory.SECURITY,
            synopsis="Управление подсистемой аудита Linux",
            description="Настраивает правила Linux Audit для мониторинга системных вызовов и файлов.",
            examples=("auditctl -l", "auditctl -w /etc/passwd -p wa -k passwd_changes",
                      "auditctl -a always,exit -F arch=b64 -S execve"),
            args=(LinuxArg("-l","Список правил"), LinuxArg("-w FILE","Наблюдать за файлом"),
                  LinuxArg("-p PERMS","Права: r,w,x,a"), LinuxArg("-k KEY","Метка"),
                  LinuxArg("-a ACTION,LIST","Системный вызов"), LinuxArg("-D","Удалить все правила")),
            see_also=("ausearch","aureport","auditd"),
        ),

        # ── Пакеты ────────────────────────────────────────────────────────
        LinuxCommand(
            name="apt", category=CommandCategory.PACKAGE,
            synopsis="Управление пакетами (Debian/Ubuntu)",
            description="Высокоуровневый менеджер пакетов для Debian-based систем.",
            examples=("apt update && apt upgrade -y", "apt install -y nginx curl jq",
                      "apt search python3", "apt show --no-all-versions nginx"),
            args=(LinuxArg("update","Обновить список"), LinuxArg("upgrade","Обновить пакеты"),
                  LinuxArg("install PKG","Установить"), LinuxArg("remove PKG","Удалить"),
                  LinuxArg("purge PKG","Удалить с конфигами"), LinuxArg("autoremove","Зависимости-сироты"),
                  LinuxArg("search QUERY","Поиск"), LinuxArg("show PKG","Информация")),
            see_also=("dpkg","apt-cache","snap"),
        ),
        LinuxCommand(
            name="dnf", category=CommandCategory.PACKAGE,
            synopsis="Управление пакетами (RHEL/Fedora)",
            description="Менеджер пакетов для Fedora, RHEL, CentOS Stream.",
            examples=("dnf install -y htop", "dnf update", "dnf search nginx", "dnf history"),
            args=(LinuxArg("install","Установить"), LinuxArg("remove","Удалить"),
                  LinuxArg("update","Обновить"), LinuxArg("search","Поиск"),
                  LinuxArg("info PKG","Информация"), LinuxArg("history","История")),
            see_also=("rpm","yum","dnf-automatic"),
        ),
        LinuxCommand(
            name="snap", category=CommandCategory.PACKAGE,
            synopsis="Универсальные snap-пакеты",
            description="Устанавливает изолированные snap-пакеты, которые работают на большинстве дистрибутивов.",
            examples=("snap install --classic code", "snap list", "snap refresh"),
            args=(LinuxArg("install","Установить"), LinuxArg("remove","Удалить"),
                  LinuxArg("list","Установленные"), LinuxArg("refresh","Обновить"),
                  LinuxArg("--classic","Полный доступ")),
            see_also=("flatpak","appimage","apt"),
        ),

        # ── Железо ────────────────────────────────────────────────────────
        LinuxCommand(
            name="lscpu", category=CommandCategory.HARDWARE,
            synopsis="Информация о CPU",
            description="Подробные данные о процессоре: архитектура, ядра, потоки, кеши, флаги.",
            examples=("lscpu", "lscpu --json | jq ."),
            args=(LinuxArg("-J","JSON"), LinuxArg("-e","Extended format"), LinuxArg("-a","Online+offline")),
            see_also=("cpuinfo","numactl","lstopo"),
        ),
        LinuxCommand(
            name="lsusb", category=CommandCategory.HARDWARE,
            synopsis="USB устройства",
            description="Перечисляет USB-шины и подключённые устройства.",
            examples=("lsusb", "lsusb -v -d 046d:0825", "lsusb -t"),
            args=(LinuxArg("-v","Детально"), LinuxArg("-t","Дерево"), LinuxArg("-d ID","По Vendor:Product")),
            see_also=("lspci","usb_modeswitch"),
        ),
        LinuxCommand(
            name="lspci", category=CommandCategory.HARDWARE,
            synopsis="PCI устройства",
            description="Показывает PCI/PCI-E устройства: видеокарты, сетевые адаптеры, контроллеры.",
            examples=("lspci -v", "lspci -k | grep -A3 VGA", "lspci -nn"),
            args=(LinuxArg("-v","Детально"), LinuxArg("-k","Модули ядра"), LinuxArg("-nn","ID производителя")),
            see_also=("lsusb","lshw","inxi"),
        ),
        LinuxCommand(
            name="lshw", category=CommandCategory.HARDWARE,
            synopsis="Полная информация об оборудовании",
            description="Детальный отчёт о железе: CPU, RAM, диски, сеть, шины.",
            examples=("lshw -short", "lshw -C network", "lshw -json > hw.json"),
            args=(LinuxArg("-short","Краткий список"), LinuxArg("-C CLASS","Фильтр класса"), LinuxArg("-json","JSON")),
            see_also=("lscpu","lspci","inxi","dmidecode"),
        ),
        LinuxCommand(
            name="sensors", category=CommandCategory.HARDWARE,
            synopsis="Температура и напряжение",
            description="Считывает данные с датчиков температуры, вентиляторов и напряжения (lm-sensors).",
            examples=("sensors", "sensors -j | jq .", "watch -n 1 sensors"),
            args=(LinuxArg("-j","JSON"), LinuxArg("-A","Без адаптеров"), LinuxArg("-f","Fahrenheit")),
            see_also=("hddtemp","nvidia-smi","powertop"),
        ),
    ]
}


def get_command(name: str) -> Optional[LinuxCommand]:
    return LINUX_COMMANDS.get(name.lower())


def commands_by_category(category: CommandCategory) -> List[LinuxCommand]:
    return [c for c in LINUX_COMMANDS.values() if c.category is category]


def search_commands(query: str) -> List[LinuxCommand]:
    """Поиск команд по имени, синопсису и описанию (регистронезависимо)."""
    q = query.lower()
    return [
        c for c in LINUX_COMMANDS.values()
        if q in c.name or q in c.synopsis.lower() or q in c.description.lower()
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Единая точка доступа
# ─────────────────────────────────────────────────────────────────────────────

class DB:
    """Единый фасад для всех баз данных local_os."""

    ports      = PORTS
    extensions = FILE_EXTENSIONS
    http       = HTTP_STATUSES
    countries  = COUNTRIES
    commands   = LINUX_COMMANDS

    # Порты
    get_port            = staticmethod(get_port)
    find_ports_by_service = staticmethod(find_ports_by_service)
    get_risky_ports     = staticmethod(get_risky_ports)

    # Расширения
    get_extension       = staticmethod(get_extension)
    extensions_by_category = staticmethod(extensions_by_category)
    is_safe_to_open     = staticmethod(is_safe_to_open)

    # HTTP
    get_http_status     = staticmethod(get_http_status)
    http_statuses_by_category = staticmethod(http_statuses_by_category)

    # Страны
    get_country         = staticmethod(get_country)
    countries_by_region = staticmethod(countries_by_region)
    countries_by_subregion = staticmethod(countries_by_subregion)
    find_country_by_tld = staticmethod(find_country_by_tld)
    find_country_by_name = staticmethod(find_country_by_name)

    # Команды
    get_command         = staticmethod(get_command)
    commands_by_category = staticmethod(commands_by_category)
    search_commands     = staticmethod(search_commands)

    @staticmethod
    def stats() -> Dict[str, int]:
        return {
            "ports":      len(PORTS),
            "extensions": len(FILE_EXTENSIONS),
            "http_codes": len(HTTP_STATUSES),
            "countries":  len(COUNTRIES),
            "commands":   len(LINUX_COMMANDS),
        }


__all__ = [
    # Типы
    "Protocol", "PortRisk", "PortInfo",
    "FileExtension",
    "HttpStatus",
    "Country",
    "CommandCategory", "LinuxArg", "LinuxCommand",
    # Данные
    "PORTS", "FILE_EXTENSIONS", "HTTP_STATUSES", "COUNTRIES", "LINUX_COMMANDS",
    # Функции
    "get_port", "find_ports_by_service", "get_risky_ports",
    "get_extension", "extensions_by_category", "is_safe_to_open",
    "get_http_status", "http_statuses_by_category",
    "get_country", "countries_by_region", "countries_by_subregion",
    "find_country_by_tld", "find_country_by_name",
    "get_command", "commands_by_category", "search_commands",
    # Фасад
    "DB",
]