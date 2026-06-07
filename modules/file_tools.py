"""
file_tools.py — Продвинутые инструменты работы с файлами
Входит в состав local_os/modules/
Функции: поиск дублей, контроль целостности, diff, дерево,
         пакетное переименование, очистка мусора, статистика
"""

import os
import sys
import re
import csv
import json
import shutil
import hashlib
import difflib
import fnmatch
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ──────────────────────────────────────────────
# Graceful fallback UI (если core.ui недоступен)
# ──────────────────────────────────────────────
try:
    from core.ui import (
        print_header, print_success, print_error,
        print_warning, print_info, print_table, COLOR
    )
except ImportError:
    import shutil as _shutil

    class COLOR:
        RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM     = "\033[2m"
        RED     = "\033[91m"; GREEN   = "\033[92m"; YELLOW  = "\033[93m"
        CYAN    = "\033[96m"; MAGENTA = "\033[95m"; BLUE    = "\033[94m"
        WHITE   = "\033[97m"; GRAY    = "\033[90m"

    def print_header(t):
        w = _shutil.get_terminal_size((80,24)).columns
        print(f"\n{COLOR.CYAN}{COLOR.BOLD}{'═'*w}\n  {t.upper()}\n{'═'*w}{COLOR.RESET}\n")

    def print_success(m): print(f"{COLOR.GREEN}✔  {m}{COLOR.RESET}")
    def print_error(m):   print(f"{COLOR.RED}✘  {m}{COLOR.RESET}", file=sys.stderr)
    def print_warning(m): print(f"{COLOR.YELLOW}⚠  {m}{COLOR.RESET}")
    def print_info(m):    print(f"{COLOR.CYAN}ℹ  {m}{COLOR.RESET}")

    def print_table(headers, rows, title=""):
        if title:
            print(f"\n{COLOR.BOLD}{COLOR.MAGENTA}  {title}{COLOR.RESET}")
        if not rows:
            print(f"  {COLOR.GRAY}(нет данных){COLOR.RESET}"); return
        col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                 for i, h in enumerate(headers)]
        sep  = "┼".join("─"*(w+2) for w in col_w)
        head = "│".join(f" {str(h).upper():^{w}} " for h, w in zip(headers, col_w))
        print(f"  {COLOR.BLUE}┌{'┬'.join('─'*(w+2) for w in col_w)}┐{COLOR.RESET}")
        print(f"  {COLOR.BOLD}{COLOR.BLUE}│{head}│{COLOR.RESET}")
        print(f"  {COLOR.BLUE}├{sep}┤{COLOR.RESET}")
        for row in rows:
            line = "│".join(f" {str(v):<{w}} " for v, w in zip(row, col_w))
            print(f"  {COLOR.BLUE}│{COLOR.RESET}{line}{COLOR.BLUE}│{COLOR.RESET}")
        print(f"  {COLOR.BLUE}└{'┴'.join('─'*(w+2) for w in col_w)}┘{COLOR.RESET}")


# ──────────────────────────────────────────────
# Константы
# ──────────────────────────────────────────────
HASH_ALGO      = "sha256"
CHUNK_SIZE     = 1 << 20          # 1 МБ для чтения файлов
MAX_WORKERS    = min(8, (os.cpu_count() or 2) + 2)
REPORT_DIR     = Path("reports")
INTEGRITY_DIR  = Path("integrity")

JUNK_PATTERNS  = [
    "Thumbs.db", "desktop.ini", ".DS_Store", "*.tmp", "*.temp",
    "~$*", "*.bak", "*.orig", "*.swp", "*.swo", "*.pyc",
    "__pycache__", ".pytest_cache", "*.log",
]

CATEGORY_MAP   = {
    "Изображения": {".jpg",".jpeg",".png",".gif",".bmp",".webp",".svg",".ico",".tiff"},
    "Видео":       {".mp4",".mkv",".avi",".mov",".wmv",".flv",".webm",".m4v"},
    "Аудио":       {".mp3",".wav",".flac",".aac",".ogg",".m4a",".wma"},
    "Документы":   {".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".odt",".ods",".odp"},
    "Текст":       {".txt",".md",".rst",".csv",".json",".xml",".yaml",".yml",".toml",".ini",".cfg"},
    "Архивы":      {".zip",".tar",".gz",".bz2",".xz",".7z",".rar",".zst"},
    "Код":         {".py",".js",".ts",".java",".c",".cpp",".h",".cs",".go",".rs",".rb",".php",".sh",".bat"},
    "Базы данных": {".db",".sqlite",".sqlite3",".sql"},
    "Шрифты":      {".ttf",".otf",".woff",".woff2"},
}


# ──────────────────────────────────────────────
# Прогресс-бар (inline, без зависимостей)
# ──────────────────────────────────────────────
class ProgressBar:
    def __init__(self, total: int, label: str = "", width: int = 40):
        self.total   = max(total, 1)
        self.current = 0
        self.label   = label
        self.width   = width
        self._lock   = threading.Lock()

    def update(self, n: int = 1):
        with self._lock:
            self.current = min(self.current + n, self.total)
            self._render()

    def _render(self):
        pct   = self.current / self.total
        filled = int(self.width * pct)
        bar   = f"{'█'*filled}{'░'*(self.width-filled)}"
        print(f"\r  {COLOR.CYAN}{self.label}{COLOR.RESET} "
              f"{COLOR.BLUE}[{bar}]{COLOR.RESET} "
              f"{COLOR.BOLD}{pct*100:5.1f}%{COLOR.RESET} "
              f"{COLOR.GRAY}{self.current}/{self.total}{COLOR.RESET}",
              end="", flush=True)

    def finish(self):
        self._render()
        print()


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────
def _fmt_size(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ПБ"

def _file_hash(path: Path, algo: str = HASH_ALGO) -> Optional[str]:
    """SHA-256 (или другой алгоритм) файла с чтением по чанкам."""
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def _quick_hash(path: Path) -> Optional[str]:
    """Быстрый хеш: размер + первые/последние 64 КБ. Для pre-filter."""
    try:
        size = path.stat().st_size
        h    = hashlib.md5()
        h.update(str(size).encode())
        with open(path, "rb") as f:
            h.update(f.read(65536))
            if size > 65536:
                f.seek(-65536, 2)
                h.update(f.read(65536))
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def _iter_files(root: Path,
                recursive: bool = True,
                include: str = "*",
                exclude_hidden: bool = True) -> list[Path]:
    """Возвращает список файлов с учётом фильтров."""
    files = []
    glob  = root.rglob if recursive else root.glob
    for p in glob(include):
        if not p.is_file():
            continue
        if exclude_hidden and any(part.startswith(".") for part in p.parts):
            continue
        files.append(p)
    return files

def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"  {COLOR.YELLOW}{prompt} (yes/no): {COLOR.RESET}").strip().lower()
        return ans in ("yes", "y", "да")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ══════════════════════════════════════════════
# 1. ПОИСК ДУБЛЕЙ
# ══════════════════════════════════════════════
class DuplicateFinder:
    """
    Двухпроходный поиск дублей:
      1. Группировка по размеру (мгновенно)
      2. Быстрый хеш первых/последних 64 КБ (фильтр)
      3. Полный SHA-256 только для вероятных дублей
    Параллельное хеширование через ThreadPoolExecutor.
    """

    def __init__(self, root: Path, recursive: bool = True, min_size: int = 1):
        self.root      = root
        self.recursive = recursive
        self.min_size  = min_size  # байт
        self.groups    : list[list[Path]] = []

    def find(self) -> list[list[Path]]:
        print_info(f"Сканирование: {self.root}")
        all_files = [
            p for p in _iter_files(self.root, self.recursive)
            if p.stat().st_size >= self.min_size
        ]
        print_info(f"Найдено файлов: {COLOR.BOLD}{len(all_files)}{COLOR.RESET}")
        if not all_files:
            return []

        # Проход 1: группировка по размеру
        by_size: dict[int, list[Path]] = defaultdict(list)
        for p in all_files:
            by_size[p.stat().st_size].append(p)
        candidates = [g for g in by_size.values() if len(g) > 1]

        flat = [p for g in candidates for p in g]
        print_info(f"Кандидатов по размеру: {COLOR.BOLD}{len(flat)}{COLOR.RESET}")

        # Проход 2: быстрый хеш
        bar = ProgressBar(len(flat), "Быстрый хеш")
        quick: dict[str, list[Path]] = defaultdict(list)
        with ThreadPoolExecutor(MAX_WORKERS) as ex:
            futs = {ex.submit(_quick_hash, p): p for p in flat}
            for fut in as_completed(futs):
                h = fut.result()
                if h:
                    quick[h].append(futs[fut])
                bar.update()
        bar.finish()

        second_pass = [g for g in quick.values() if len(g) > 1]
        flat2 = [p for g in second_pass for p in g]
        print_info(f"Кандидатов для полного хеша: {COLOR.BOLD}{len(flat2)}{COLOR.RESET}")

        # Проход 3: полный SHA-256
        bar2 = ProgressBar(len(flat2), "Полный SHA-256")
        full: dict[str, list[Path]] = defaultdict(list)
        with ThreadPoolExecutor(MAX_WORKERS) as ex:
            futs = {ex.submit(_file_hash, p): p for p in flat2}
            for fut in as_completed(futs):
                h = fut.result()
                if h:
                    full[h].append(futs[fut])
                bar2.update()
        bar2.finish()

        self.groups = sorted(
            [g for g in full.values() if len(g) > 1],
            key=lambda g: -g[0].stat().st_size
        )
        return self.groups

    def report(self):
        if not self.groups:
            print_info("Дублей не найдено.")
            return
        total_waste = sum(
            p.stat().st_size * (len(g) - 1)
            for g in self.groups for p in g[:1]
        )
        rows = []
        for i, group in enumerate(self.groups, 1):
            sz = group[0].stat().st_size
            for j, p in enumerate(group):
                marker = f"[{i}]" if j == 0 else f" ↳{i}"
                rows.append((marker, str(p), _fmt_size(sz)))
        print_table(["Группа", "Путь", "Размер"], rows,
                    title=f"Дубли: {len(self.groups)} групп  |  "
                          f"Потери: {_fmt_size(total_waste)}")

    def delete_duplicates(self, keep: str = "first", dry_run: bool = True):
        """
        keep='first' — сохраняет первый файл в группе (остальные удаляет).
        keep='newest' / 'oldest' — по дате модификации.
        dry_run=True — только показывает что будет удалено.
        """
        if not self.groups:
            print_info("Нечего удалять.")
            return

        to_delete: list[Path] = []
        for group in self.groups:
            if keep == "newest":
                group = sorted(group, key=lambda p: -p.stat().st_mtime)
            elif keep == "oldest":
                group = sorted(group, key=lambda p: p.stat().st_mtime)
            to_delete.extend(group[1:])

        total = sum(p.stat().st_size for p in to_delete)
        print_warning(f"К удалению: {len(to_delete)} файлов  |  "
                      f"Освободится: {_fmt_size(total)}")
        for p in to_delete:
            print(f"  {COLOR.RED}✘{COLOR.RESET} {p}")

        if dry_run:
            print_info("dry_run=True — реальное удаление не выполняется.")
            return

        if not _confirm("Удалить перечисленные файлы?"):
            print_info("Отменено.")
            return

        deleted, errors = 0, 0
        for p in to_delete:
            try:
                p.unlink()
                deleted += 1
            except OSError as e:
                print_error(f"  {p}: {e}")
                errors += 1
        print_success(f"Удалено: {deleted}  |  Ошибок: {errors}")


# ══════════════════════════════════════════════
# 2. КОНТРОЛЬ ЦЕЛОСТНОСТИ (манифест + проверка)
# ══════════════════════════════════════════════
class IntegrityChecker:
    """
    Создаёт манифест (JSON с хешами) для директории,
    затем верифицирует: ADDED / MODIFIED / DELETED / OK.
    """

    def __init__(self, root: Path, algo: str = HASH_ALGO):
        self.root    = root
        self.algo    = algo
        INTEGRITY_DIR.mkdir(exist_ok=True)
        slug         = re.sub(r"[^\w]", "_", str(root))
        self.manifest_path = INTEGRITY_DIR / f"{slug}.json"

    def _build_manifest(self) -> dict:
        files = _iter_files(self.root)
        bar   = ProgressBar(len(files), "Хеширование ")
        result: dict[str, dict] = {}
        with ThreadPoolExecutor(MAX_WORKERS) as ex:
            futs = {ex.submit(_file_hash, p, self.algo): p for p in files}
            for fut in as_completed(futs):
                p = futs[fut]
                h = fut.result()
                bar.update()
                if h:
                    rel = str(p.relative_to(self.root))
                    result[rel] = {
                        "hash":     h,
                        "size":     p.stat().st_size,
                        "mtime":    p.stat().st_mtime,
                    }
        bar.finish()
        return result

    def create(self):
        print_info(f"Создание манифеста: {self.root}")
        manifest = {
            "root":      str(self.root),
            "algo":      self.algo,
            "created":   datetime.now().isoformat(),
            "files":     self._build_manifest(),
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        n = len(manifest["files"])
        print_success(f"Манифест создан: {self.manifest_path}  ({n} файлов)")

    def verify(self) -> dict[str, list[str]]:
        if not self.manifest_path.exists():
            print_error(f"Манифест не найден: {self.manifest_path}")
            print_info("Создайте его командой: integrity create <путь>")
            return {}

        with open(self.manifest_path, encoding="utf-8") as f:
            saved = json.load(f)

        old_files: dict[str, dict] = saved["files"]
        print_info(f"Проверка {len(old_files)} файлов в {self.root}")
        current = self._build_manifest()

        report = {"OK": [], "MODIFIED": [], "DELETED": [], "ADDED": []}

        for rel, info in old_files.items():
            if rel not in current:
                report["DELETED"].append(rel)
            elif current[rel]["hash"] != info["hash"]:
                report["MODIFIED"].append(rel)
            else:
                report["OK"].append(rel)

        for rel in current:
            if rel not in old_files:
                report["ADDED"].append(rel)

        # Вывод
        rows = []
        for status, files in report.items():
            for f in files:
                color = {
                    "OK":       COLOR.GREEN,
                    "MODIFIED": COLOR.YELLOW,
                    "DELETED":  COLOR.RED,
                    "ADDED":    COLOR.CYAN,
                }.get(status, COLOR.RESET)
                rows.append((f"{color}{status}{COLOR.RESET}", f))
        if rows:
            print_table(["Статус", "Файл"], rows,
                        title="Результат проверки целостности")

        print(f"\n  {COLOR.GREEN}OK: {len(report['OK'])}{COLOR.RESET}  "
              f"{COLOR.YELLOW}Изменено: {len(report['MODIFIED'])}{COLOR.RESET}  "
              f"{COLOR.RED}Удалено: {len(report['DELETED'])}{COLOR.RESET}  "
              f"{COLOR.CYAN}Добавлено: {len(report['ADDED'])}{COLOR.RESET}\n")
        return report


# ══════════════════════════════════════════════
# 3. DIFF ДВУХ ФАЙЛОВ
# ══════════════════════════════════════════════
def diff_files(path_a: Path, path_b: Path, context: int = 3):
    """Unified diff с цветовой подсветкой в терминале."""
    try:
        a_lines = path_a.read_text(errors="replace").splitlines(keepends=True)
        b_lines = path_b.read_text(errors="replace").splitlines(keepends=True)
    except OSError as e:
        print_error(f"Ошибка чтения: {e}"); return

    diff = list(difflib.unified_diff(
        a_lines, b_lines,
        fromfile=str(path_a),
        tofile=str(path_b),
        n=context,
    ))
    if not diff:
        print_success("Файлы идентичны.")
        return

    for line in diff:
        if line.startswith("---") or line.startswith("+++"):
            print(f"{COLOR.BOLD}{COLOR.MAGENTA}{line}{COLOR.RESET}", end="")
        elif line.startswith("@@"):
            print(f"{COLOR.CYAN}{line}{COLOR.RESET}", end="")
        elif line.startswith("+"):
            print(f"{COLOR.GREEN}{line}{COLOR.RESET}", end="")
        elif line.startswith("-"):
            print(f"{COLOR.RED}{line}{COLOR.RESET}", end="")
        else:
            print(f"{COLOR.GRAY}{line}{COLOR.RESET}", end="")


# ══════════════════════════════════════════════
# 4. ДЕРЕВО ДИРЕКТОРИЙ
# ══════════════════════════════════════════════
def print_tree(root: Path, max_depth: int = 3, show_hidden: bool = False,
               max_entries: int = 500):
    """Красивое ASCII-дерево с размерами файлов."""
    count = {"files": 0, "dirs": 0}

    def _tree(path: Path, prefix: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(path.iterdir(),
                             key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            print(f"{prefix}  {COLOR.RED}[нет доступа]{COLOR.RESET}")
            return

        if not show_hidden:
            entries = [e for e in entries if not e.name.startswith(".")]

        for i, entry in enumerate(entries):
            if count["files"] + count["dirs"] >= max_entries:
                print(f"{prefix}  {COLOR.GRAY}… (обрезано){COLOR.RESET}")
                return
            connector = "└── " if i == len(entries)-1 else "├── "
            ext_prefix = prefix + ("    " if i == len(entries)-1 else "│   ")

            if entry.is_dir():
                count["dirs"] += 1
                print(f"{prefix}{COLOR.BLUE}{connector}{COLOR.BOLD}"
                      f"{entry.name}/{COLOR.RESET}")
                _tree(entry, ext_prefix, depth + 1)
            else:
                count["files"] += 1
                sz = _fmt_size(entry.stat().st_size)
                ext = entry.suffix.lower()
                col = (COLOR.GREEN if ext in {".py",".js",".ts",".go",".rs"}
                       else COLOR.YELLOW if ext in {".md",".txt",".json",".yaml"}
                       else COLOR.MAGENTA if ext in {".jpg",".png",".gif",".svg"}
                       else COLOR.RESET)
                print(f"{prefix}{connector}"
                      f"{col}{entry.name}{COLOR.RESET}  "
                      f"{COLOR.GRAY}{sz}{COLOR.RESET}")

    print(f"\n{COLOR.BOLD}{COLOR.CYAN}{root.resolve()}{COLOR.RESET}")
    _tree(root, "", 0)
    print(f"\n  {COLOR.GRAY}{count['dirs']} директорий, "
          f"{count['files']} файлов{COLOR.RESET}\n")


# ══════════════════════════════════════════════
# 5. СТАТИСТИКА ДИРЕКТОРИИ
# ══════════════════════════════════════════════
def dir_stats(root: Path):
    """Размер по категориям, топ-10 крупных файлов, общая статистика."""
    files = _iter_files(root, recursive=True, exclude_hidden=False)
    if not files:
        print_info("Файлов не найдено."); return

    total_size  = 0
    cat_size    : dict[str, int] = defaultdict(int)
    cat_count   : dict[str, int] = defaultdict(int)
    large_files : list[tuple[int, Path]] = []

    for p in files:
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        total_size += sz
        large_files.append((sz, p))
        ext  = p.suffix.lower()
        cat  = next((c for c, exts in CATEGORY_MAP.items() if ext in exts), "Прочее")
        cat_size[cat]  += sz
        cat_count[cat] += 1

    # Таблица категорий
    cat_rows = sorted(cat_size.items(), key=lambda x: -x[1])
    print_table(
        ["Категория", "Файлов", "Размер", "Доля"],
        [(c, cat_count[c], _fmt_size(s),
          f"{s/total_size*100:.1f}%") for c, s in cat_rows],
        title="Статистика по категориям",
    )

    # Топ-10 крупных файлов
    top10 = sorted(large_files, key=lambda x: -x[0])[:10]
    print_table(
        ["Размер", "Файл"],
        [(_fmt_size(sz), str(p)) for sz, p in top10],
        title="Топ-10 крупных файлов",
    )

    print_info(f"Итого: {COLOR.BOLD}{len(files)}{COLOR.RESET} файлов  |  "
               f"{COLOR.BOLD}{_fmt_size(total_size)}{COLOR.RESET}")


# ══════════════════════════════════════════════
# 6. ПОИСК МУСОРА
# ══════════════════════════════════════════════
def find_junk(root: Path, dry_run: bool = True,
              extra_patterns: Optional[list[str]] = None):
    """Находит и опционально удаляет мусорные файлы по паттернам."""
    patterns = JUNK_PATTERNS + (extra_patterns or [])
    junk     : list[Path] = []

    for p in root.rglob("*"):
        if not p.exists():
            continue
        name = p.name
        if any(fnmatch.fnmatch(name, pat) for pat in patterns):
            junk.append(p)

    if not junk:
        print_success("Мусора не найдено."); return

    total = sum(
        p.stat().st_size for p in junk if p.is_file() and p.exists()
    )
    rows = [(p.name, str(p.parent), _fmt_size(p.stat().st_size)
             if p.is_file() else "dir") for p in junk]
    print_table(["Имя", "Расположение", "Размер"], rows,
                title=f"Мусор: {len(junk)} объектов  |  {_fmt_size(total)}")

    if dry_run:
        print_info("dry_run=True — реальное удаление не выполняется.")
        return

    if not _confirm(f"Удалить {len(junk)} объектов?"):
        print_info("Отменено."); return

    deleted, errors = 0, 0
    for p in junk:
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            deleted += 1
        except OSError as e:
            print_error(f"  {p}: {e}"); errors += 1
    print_success(f"Удалено: {deleted}  |  Ошибок: {errors}")


# ══════════════════════════════════════════════
# 7. ПАКЕТНОЕ ПЕРЕИМЕНОВАНИЕ
# ══════════════════════════════════════════════
def batch_rename(root: Path, pattern: str, replacement: str,
                 glob: str = "*", dry_run: bool = True,
                 recursive: bool = False):
    """
    Пакетное переименование по regex.
    pattern     — regex для поиска в имени файла
    replacement — строка замены (поддерживает \\1, \\2 … группы)
    """
    files = list((root.rglob if recursive else root.glob)(glob))
    files = [f for f in files if f.is_file()]

    if not files:
        print_info("Файлов по маске не найдено."); return

    try:
        rx = re.compile(pattern)
    except re.error as e:
        print_error(f"Неверный regex: {e}"); return

    plan: list[tuple[Path, Path]] = []
    for p in files:
        new_name = rx.sub(replacement, p.name)
        if new_name != p.name:
            plan.append((p, p.with_name(new_name)))

    if not plan:
        print_info("Нет файлов, удовлетворяющих шаблону."); return

    print_table(
        ["Было", "Станет"],
        [(str(src.name), str(dst.name)) for src, dst in plan],
        title=f"План переименования ({len(plan)} файлов)",
    )

    if dry_run:
        print_info("dry_run=True — реальное переименование не выполняется.")
        return

    if not _confirm(f"Переименовать {len(plan)} файлов?"):
        print_info("Отменено."); return

    ok, errors = 0, 0
    for src, dst in plan:
        try:
            if dst.exists():
                print_warning(f"  Пропуск (уже существует): {dst.name}")
                continue
            src.rename(dst)
            ok += 1
        except OSError as e:
            print_error(f"  {src.name}: {e}"); errors += 1
    print_success(f"Переименовано: {ok}  |  Ошибок: {errors}")


# ══════════════════════════════════════════════
# 8. ЭКСПОРТ ОТЧЁТА
# ══════════════════════════════════════════════
def export_report(data: list[dict], name: str, fmt: str = "csv"):
    """Сохраняет список словарей в CSV или JSON."""
    REPORT_DIR.mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORT_DIR / f"{name}_{ts}.{fmt}"
    try:
        if fmt == "json":
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        else:
            if not data:
                print_warning("Нет данных для экспорта."); return
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=data[0].keys())
                w.writeheader()
                w.writerows(data)
        print_success(f"Отчёт сохранён → {COLOR.BOLD}{path}{COLOR.RESET}")
    except OSError as e:
        print_error(f"Ошибка записи: {e}")


# ══════════════════════════════════════════════
# Публичное API модуля (для terminal.py)
# ══════════════════════════════════════════════
def run_file_tools():
    """Интерактивное меню модуля file_tools."""
    print_header("File Tools")

    MENU = {
        "1": ("Поиск дублей",             _menu_duplicates),
        "2": ("Контроль целостности",      _menu_integrity),
        "3": ("Diff двух файлов",          _menu_diff),
        "4": ("Дерево директории",         _menu_tree),
        "5": ("Статистика директории",     _menu_stats),
        "6": ("Поиск и удаление мусора",   _menu_junk),
        "7": ("Пакетное переименование",   _menu_rename),
        "0": ("Назад",                     None),
    }

    while True:
        print(f"\n{COLOR.BOLD}  Выберите операцию:{COLOR.RESET}")
        for k, (label, _) in MENU.items():
            bullet = f"{COLOR.CYAN}[{k}]{COLOR.RESET}"
            print(f"    {bullet} {label}")
        try:
            choice = input(f"\n  {COLOR.CYAN}>{COLOR.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if choice == "0":
            break
        entry = MENU.get(choice)
        if entry:
            try:
                entry[1]()
            except KeyboardInterrupt:
                print_info("Отменено.")
        else:
            print_error("Неверный выбор.")


def _ask_path(prompt: str) -> Optional[Path]:
    try:
        raw = input(f"  {COLOR.CYAN}{prompt}: {COLOR.RESET}").strip()
        if not raw:
            return None
        p = Path(raw).expanduser().resolve()
        if not p.exists():
            print_error(f"Путь не существует: {p}")
            return None
        return p
    except (EOFError, KeyboardInterrupt):
        return None


def _menu_duplicates():
    root = _ask_path("Директория для поиска дублей")
    if not root: return
    try:
        min_kb = int(input(f"  {COLOR.CYAN}Мин. размер файла (КБ, по умолч. 1): {COLOR.RESET}").strip() or "1")
    except ValueError:
        min_kb = 1
    finder = DuplicateFinder(root, min_size=min_kb * 1024)
    finder.find()
    finder.report()
    if finder.groups and _confirm("Удалить дубли? (оставить первый файл)"):
        finder.delete_duplicates(dry_run=False)


def _menu_integrity():
    root = _ask_path("Директория")
    if not root: return
    try:
        action = input(f"  {COLOR.CYAN}[1] Создать манифест  [2] Проверить: {COLOR.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return
    ic = IntegrityChecker(root)
    if action == "1":
        ic.create()
    elif action == "2":
        ic.verify()
    else:
        print_error("Неверный выбор.")


def _menu_diff():
    a = _ask_path("Файл A")
    if not a: return
    b = _ask_path("Файл B")
    if not b: return
    diff_files(a, b)


def _menu_tree():
    root = _ask_path("Директория")
    if not root: return
    try:
        depth = int(input(f"  {COLOR.CYAN}Глубина (по умолч. 3): {COLOR.RESET}").strip() or "3")
    except ValueError:
        depth = 3
    print_tree(root, max_depth=depth)


def _menu_stats():
    root = _ask_path("Директория")
    if not root: return
    dir_stats(root)


def _menu_junk():
    root = _ask_path("Директория")
    if not root: return
    find_junk(root, dry_run=False)


def _menu_rename():
    root = _ask_path("Директория")
    if not root: return
    try:
        pattern     = input(f"  {COLOR.CYAN}Regex-паттерн: {COLOR.RESET}").strip()
        replacement = input(f"  {COLOR.CYAN}Замена: {COLOR.RESET}").strip()
        glob_pat    = input(f"  {COLOR.CYAN}Маска файлов (по умолч. *): {COLOR.RESET}").strip() or "*"
    except (EOFError, KeyboardInterrupt):
        return
    batch_rename(root, pattern, replacement, glob=glob_pat, dry_run=False)


# ──────────────────────────────────────────────
# Standalone-запуск
# ──────────────────────────────────────────────
if __name__ == "__main__":
    run_file_tools()