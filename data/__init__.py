# data/__init__.py

from .databases import (
    # ── Типы ──────────────────────────────────────────────────────────────
    Protocol,
    PortRisk,
    PortInfo,
    FileExtension,
    HttpStatus,
    Country,
    CommandCategory,
    LinuxArg,
    LinuxCommand,

    # ── Сырые данные ──────────────────────────────────────────────────────
    PORTS,
    FILE_EXTENSIONS,
    HTTP_STATUSES,
    COUNTRIES,
    LINUX_COMMANDS,

    # ── Функции: Порты ─────────────────────────────────────────────────────
    get_port,
    find_ports_by_service,
    get_risky_ports,

    # ── Функции: Расширения ────────────────────────────────────────────────
    get_extension,
    extensions_by_category,
    is_safe_to_open,

    # ── Функции: HTTP ──────────────────────────────────────────────────────
    get_http_status,
    http_statuses_by_category,

    # ── Функции: Страны ────────────────────────────────────────────────────
    get_country,
    countries_by_region,
    countries_by_subregion,
    find_country_by_tld,
    find_country_by_name,

    # ── Функции: Команды ───────────────────────────────────────────────────
    get_command,
    commands_by_category,
    search_commands,

    # ── Фасад ─────────────────────────────────────────────────────────────
    DB,
)

__all__ = [
    # Типы
    "Protocol", "PortRisk", "PortInfo",
    "FileExtension",
    "HttpStatus",
    "Country",
    "CommandCategory", "LinuxArg", "LinuxCommand",
    # Данные
    "PORTS", "FILE_EXTENSIONS", "HTTP_STATUSES", "COUNTRIES", "LINUX_COMMANDS",
    # Функции — Порты
    "get_port", "find_ports_by_service", "get_risky_ports",
    # Функции — Расширения
    "get_extension", "extensions_by_category", "is_safe_to_open",
    # Функции — HTTP
    "get_http_status", "http_statuses_by_category",
    # Функции — Страны
    "get_country", "countries_by_region", "countries_by_subregion",
    "find_country_by_tld", "find_country_by_name",
    # Функции — Команды
    "get_command", "commands_by_category", "search_commands",
    # Фасад
    "DB",
]