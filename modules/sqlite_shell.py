"""
sqlite_shell.py — Продвинутый мини SQLite CLI
Входит в состав local_os/modules/
"""

import sqlite3
import os
import sys
import time
import csv
import json
import re
import shutil
try:
    import readline  # история команд (Unix/macOS)
except ImportError:
    readline = None
from pathlib import Path
from typing import Optional, Any
from datetime import datetime

# ──────────────────────────────────────────────
# Попытка импорта модулей проекта (graceful fallback)
# ──────────────────────────────────────────────
try:
    from core.ui import (
        print_header, print_success, print_error,
        print_warning, print_info, print_table, COLOR
    )
except ImportError:
    # Standalone-режим: собственный минимальный UI
    class COLOR:
        RESET   = "\033[0m"
        BOLD    = "\033[1m"
        DIM     = "\033[2m"
        RED     = "\033[91m"
        GREEN   = "\033[92m"
        YELLOW  = "\033[93m"
        CYAN    = "\033[96m"
        MAGENTA = "\033[95m"
        BLUE    = "\033[94m"
        WHITE   = "\033[97m"
        GRAY    = "\033[90m"

    def print_header(title: str):
        w = shutil.get_terminal_size((80, 24)).columns
        print(f"\n{COLOR.CYAN}{COLOR.BOLD}{'═' * w}")
        print(f"  {title.upper()}")
        print(f"{'═' * w}{COLOR.RESET}\n")

    def print_success(msg):  print(f"{COLOR.GREEN}✔  {msg}{COLOR.RESET}")
    def print_error(msg):    print(f"{COLOR.RED}✘  {msg}{COLOR.RESET}", file=sys.stderr)
    def print_warning(msg):  print(f"{COLOR.YELLOW}⚠  {msg}{COLOR.RESET}")
    def print_info(msg):     print(f"{COLOR.CYAN}ℹ  {msg}{COLOR.RESET}")

    def print_table(headers: list[str], rows: list[tuple], title: str = ""):
        """Минималистичная таблица с автошириной колонок."""
        if title:
            print(f"\n{COLOR.BOLD}{COLOR.MAGENTA}  {title}{COLOR.RESET}")
        if not rows:
            print(f"  {COLOR.GRAY}(нет данных){COLOR.RESET}")
            return
        col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
                 for i, h in enumerate(headers)]
        sep = "┼".join("─" * (w + 2) for w in col_w)
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
HISTORY_FILE   = Path.home() / ".local_os_sqlite_history"
MAX_HISTORY    = 500
DEFAULT_LIMIT  = 100          # строк по умолчанию при SELECT *
EXPORT_DIR     = Path("exports")

DANGEROUS_CMDS = re.compile(
    r"^\s*(drop\s+(database|table|index|trigger|view)|"
    r"truncate|delete\s+from\s+\S+\s*$|"
    r"alter\s+table.*drop)",
    re.IGNORECASE,
)

HELP_TEXT = f"""
{COLOR.CYAN}{COLOR.BOLD}╔══════════════════════════════════════════════════╗
║           SQLite Shell — Справка по командам      ║
╚══════════════════════════════════════════════════╝{COLOR.RESET}

{COLOR.BOLD}Встроенные команды:{COLOR.RESET}
  {COLOR.GREEN}.open   <файл>{COLOR.RESET}          открыть / создать БД
  {COLOR.GREEN}.close{COLOR.RESET}                  закрыть текущую БД
  {COLOR.GREEN}.tables{COLOR.RESET}                 список таблиц
  {COLOR.GREEN}.schema [таблица]{COLOR.RESET}       DDL таблицы / всей БД
  {COLOR.GREEN}.info{COLOR.RESET}                   информация о БД
  {COLOR.GREEN}.indexes [таблица]{COLOR.RESET}      список индексов
  {COLOR.GREEN}.views{COLOR.RESET}                  список представлений
  {COLOR.GREEN}.triggers{COLOR.RESET}               список триггеров
  {COLOR.GREEN}.size{COLOR.RESET}                   размер БД
  {COLOR.GREEN}.limit <N>{COLOR.RESET}              лимит строк SELECT (0 = без лимита)
  {COLOR.GREEN}.export <таблица> [csv|json]{COLOR.RESET}  экспорт таблицы
  {COLOR.GREEN}.import <csv> <таблица>{COLOR.RESET} импорт CSV в таблицу
  {COLOR.GREEN}.dump [таблица]{COLOR.RESET}         SQL-дамп
  {COLOR.GREEN}.history{COLOR.RESET}                история запросов
  {COLOR.GREEN}.clear{COLOR.RESET}                  очистить экран
  {COLOR.GREEN}.help{COLOR.RESET}                   эта справка
  {COLOR.GREEN}.exit / .quit{COLOR.RESET}           выход

{COLOR.BOLD}SQL-режим:{COLOR.RESET}
  Многострочный ввод — заканчивайте оператор символом {COLOR.YELLOW};{COLOR.RESET}
  Отмена ввода      — {COLOR.YELLOW}Ctrl+C{COLOR.RESET}
  Пустая строка     — продолжение многострочного запроса

{COLOR.BOLD}Горячие клавиши:{COLOR.RESET}
  {COLOR.YELLOW}↑ / ↓{COLOR.RESET}  история команд    {COLOR.YELLOW}Ctrl+L{COLOR.RESET}  очистить экран
  {COLOR.YELLOW}Ctrl+C{COLOR.RESET}  отменить ввод     {COLOR.YELLOW}Ctrl+D{COLOR.RESET}  выход
"""


# ──────────────────────────────────────────────
# QueryStats: статистика последнего запроса
# ──────────────────────────────────────────────
class QueryStats:
    def __init__(self):
        self.reset()

    def reset(self):
        self.elapsed  : float = 0.0
        self.rows     : int   = 0
        self.changes  : int   = 0

    def show(self):
        parts = [f"время: {self.elapsed*1000:.2f} мс"]
        if self.rows:
            parts.append(f"строк: {self.rows}")
        if self.changes:
            parts.append(f"изменено: {self.changes}")
        print(f"  {COLOR.GRAY}[ {' │ '.join(parts)} ]{COLOR.RESET}\n")


# ──────────────────────────────────────────────
# SQLiteShell — основной класс
# ──────────────────────────────────────────────
class SQLiteShell:
    """
    Интерактивный SQLite-терминал с историей, экспортом,
    многострочным вводом и защитой от деструктивных операций.
    """

    def __init__(self):
        self.conn      : Optional[sqlite3.Connection] = None
        self.db_path   : Optional[Path]               = None
        self.stats     : QueryStats                   = QueryStats()
        self.row_limit : int                          = DEFAULT_LIMIT
        self._setup_readline()
        EXPORT_DIR.mkdir(exist_ok=True)

    # ── readline / история ────────────────────
    def _setup_readline(self):
        try:
            readline.set_history_length(MAX_HISTORY)
            if HISTORY_FILE.exists():
                readline.read_history_file(HISTORY_FILE)
            import atexit
            atexit.register(readline.write_history_file, HISTORY_FILE)
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self._completer)
        except Exception:
            pass  # Windows или недоступен readline

    def _completer(self, text: str, state: int) -> Optional[str]:
        """Tab-completion: встроенные команды + имена таблиц."""
        options = [
            ".open", ".close", ".tables", ".schema", ".info",
            ".indexes", ".views", ".triggers", ".size", ".limit",
            ".export", ".import", ".dump", ".history", ".clear",
            ".help", ".exit", ".quit",
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE",
            "DROP", "ALTER", "BEGIN", "COMMIT", "ROLLBACK",
            "FROM", "WHERE", "ORDER BY", "GROUP BY", "HAVING",
            "LIMIT", "OFFSET", "JOIN", "LEFT JOIN", "INNER JOIN",
        ]
        if self.conn:
            options += self._get_table_names()
        matches = [o for o in options if o.upper().startswith(text.upper())]
        return matches[state] if state < len(matches) else None

    # ── соединение ────────────────────────────
    def _require_connection(self) -> bool:
        if self.conn is None:
            print_error("Нет открытой базы данных. Используйте: .open <файл>")
            return False
        return True

    def open_db(self, path_str: str):
        path = Path(path_str).expanduser().resolve()
        try:
            if self.conn:
                self.close_db(silent=True)
            self.conn    = sqlite3.connect(str(path))
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.db_path = path
            existed = path.exists() and path.stat().st_size > 0
            verb = "Открыта" if existed else "Создана"
            print_success(f"{verb}: {COLOR.BOLD}{path}{COLOR.RESET}")
        except sqlite3.Error as e:
            print_error(f"Не удалось открыть БД: {e}")

    def close_db(self, silent: bool = False):
        if self.conn:
            self.conn.close()
            self.conn    = None
            self.db_path = None
            if not silent:
                print_success("База данных закрыта.")
        elif not silent:
            print_warning("Нет открытой базы данных.")

    # ── мета-команды (.xxx) ───────────────────
    def _cmd_tables(self, _):
        if not self._require_connection(): return
        names = self._get_table_names()
        if not names:
            print_info("Таблиц нет.")
            return
        # показать с числом строк
        rows = []
        for n in names:
            try:
                cnt = self.conn.execute(f'SELECT COUNT(*) FROM "{n}"').fetchone()[0]
            except Exception:
                cnt = "?"
            rows.append((n, cnt))
        print_table(["Таблица", "Строк"], rows, title=f"Таблицы ({len(names)})")

    def _cmd_schema(self, arg: str):
        if not self._require_connection(): return
        if arg:
            sql = ("SELECT sql FROM sqlite_master "
                   "WHERE type='table' AND name=? AND sql IS NOT NULL")
            row = self.conn.execute(sql, (arg,)).fetchone()
            if row:
                self._pretty_sql(row[0])
            else:
                print_warning(f"Таблица «{arg}» не найдена.")
        else:
            rows = self.conn.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
            ).fetchall()
            for r in rows:
                self._pretty_sql(r[0])
                print()

    def _cmd_info(self, _):
        if not self._require_connection(): return
        pragma_rows = []
        for key in ("page_size", "page_count", "journal_mode",
                    "cache_size", "foreign_keys", "wal_checkpoint"):
            try:
                val = self.conn.execute(f"PRAGMA {key}").fetchone()
                pragma_rows.append((key, val[0] if val else "—"))
            except Exception:
                pass
        size_bytes = self.db_path.stat().st_size if self.db_path else 0
        pragma_rows.append(("file_size", _fmt_size(size_bytes)))
        pragma_rows.append(("path", str(self.db_path)))
        print_table(["Параметр", "Значение"], pragma_rows, title="Информация о БД")

    def _cmd_indexes(self, arg: str):
        if not self._require_connection(): return
        sql = ("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'"
               + (" AND tbl_name=?" if arg else "") + " ORDER BY tbl_name, name")
        params = (arg,) if arg else ()
        rows = self.conn.execute(sql, params).fetchall()
        if not rows:
            print_info("Индексов нет.")
            return
        print_table(["Индекс", "Таблица", "DDL"],
                    [(r[0], r[1], (r[2] or "авто")[:60]) for r in rows],
                    title="Индексы")

    def _cmd_views(self, _):
        if not self._require_connection(): return
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
        ).fetchall()
        if not rows:
            print_info("Представлений нет.")
        else:
            print_table(["Представление"], [(r[0],) for r in rows], title="Views")

    def _cmd_triggers(self, _):
        if not self._require_connection(): return
        rows = self.conn.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).fetchall()
        if not rows:
            print_info("Триггеров нет.")
        else:
            print_table(["Триггер", "Таблица", "DDL"],
                        [(r[0], r[1], (r[2] or "")[:50]) for r in rows],
                        title="Триггеры")

    def _cmd_size(self, _):
        if not self._require_connection(): return
        if self.db_path:
            sz = self.db_path.stat().st_size
            print_info(f"Размер файла: {COLOR.BOLD}{_fmt_size(sz)}{COLOR.RESET}")
        else:
            print_warning("Путь к файлу неизвестен (in-memory?).")

    def _cmd_limit(self, arg: str):
        if not arg:
            print_info(f"Текущий лимит: {COLOR.BOLD}{self.row_limit}{COLOR.RESET}"
                       f"  (0 = без лимита)")
            return
        try:
            n = int(arg)
            self.row_limit = max(0, n)
            label = "без лимита" if self.row_limit == 0 else str(self.row_limit)
            print_success(f"Лимит строк установлен: {label}")
        except ValueError:
            print_error("Ожидается целое число.")

    def _cmd_export(self, arg: str):
        if not self._require_connection(): return
        parts = arg.split()
        if not parts:
            print_error("Использование: .export <таблица> [csv|json]")
            return
        table  = parts[0]
        fmt    = parts[1].lower() if len(parts) > 1 else "csv"
        if fmt not in ("csv", "json"):
            print_error("Формат: csv или json")
            return
        try:
            rows = self.conn.execute(f'SELECT * FROM "{table}"').fetchall()
            if not rows:
                print_warning("Таблица пуста — файл не создан.")
                return
            cols = [d[0] for d in self.conn.execute(
                f'SELECT * FROM "{table}" LIMIT 0').description]
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            out  = EXPORT_DIR / f"{table}_{ts}.{fmt}"
            if fmt == "csv":
                with open(out, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(cols)
                    w.writerows(rows)
            else:
                data = [dict(zip(cols, r)) for r in rows]
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            print_success(f"Экспортировано {len(rows)} строк → {COLOR.BOLD}{out}{COLOR.RESET}")
        except sqlite3.Error as e:
            print_error(f"Ошибка экспорта: {e}")

    def _cmd_import(self, arg: str):
        if not self._require_connection(): return
        parts = arg.split(maxsplit=1)
        if len(parts) < 2:
            print_error("Использование: .import <файл.csv> <таблица>")
            return
        csv_path, table = Path(parts[0]), parts[1]
        if not csv_path.exists():
            print_error(f"Файл не найден: {csv_path}")
            return
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                cols   = reader.fieldnames
                if not cols:
                    print_error("CSV файл пуст или без заголовков.")
                    return
                placeholders = ", ".join("?" * len(cols))
                col_list     = ", ".join(f'"{c}"' for c in cols)
                self.conn.execute(
                    f'CREATE TABLE IF NOT EXISTS "{table}" '
                    f'({", ".join(f"{chr(34)}{c}{chr(34)} TEXT" for c in cols)})'
                )
                rows = list(reader)
                self.conn.executemany(
                    f'INSERT INTO "{table}" ({col_list}) VALUES ({placeholders})',
                    [tuple(r[c] for c in cols) for r in rows]
                )
                self.conn.commit()
            print_success(f"Импортировано {len(rows)} строк в «{table}»")
        except (sqlite3.Error, csv.Error, OSError) as e:
            print_error(f"Ошибка импорта: {e}")

    def _cmd_dump(self, arg: str):
        if not self._require_connection(): return
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = EXPORT_DIR / f"dump_{ts}.sql"
        try:
            with open(out, "w", encoding="utf-8") as f:
                for line in self.conn.iterdump():
                    if arg and not re.search(
                        rf'\b{re.escape(arg)}\b', line, re.IGNORECASE
                    ):
                        continue
                    f.write(line + "\n")
            print_success(f"Дамп сохранён → {COLOR.BOLD}{out}{COLOR.RESET}")
        except OSError as e:
            print_error(f"Не удалось записать дамп: {e}")

    def _cmd_history(self, _):
        try:
            n = readline.get_current_history_length()
            start = max(1, n - 30)
            rows  = [(i, readline.get_history_item(i)) for i in range(start, n + 1)]
            print_table(["#", "Команда"], rows, title="История (последние 30)")
        except Exception:
            print_warning("История недоступна.")

    def _cmd_clear(self, _):
        os.system("cls" if sys.platform == "win32" else "clear")

    # ── SQL-выполнение ────────────────────────
    def execute_sql(self, sql: str):
        if not self._require_connection(): return
        sql = sql.strip()
        if not sql:
            return

        # Предупреждение о деструктивных операциях
        if DANGEROUS_CMDS.match(sql):
            print_warning("⚡ Деструктивная операция!")
            try:
                confirm = input(f"  {COLOR.YELLOW}Подтвердите (yes/no): {COLOR.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if confirm.lower() not in ("yes", "y", "да"):
                print_info("Отменено.")
                return

        self.stats.reset()
        t0 = time.perf_counter()
        try:
            cursor = self.conn.execute(sql)
            self.conn.commit()
            self.stats.elapsed = time.perf_counter() - t0
            self.stats.changes = self.conn.total_changes

            if cursor.description:
                # SELECT-подобный запрос
                limit  = self.row_limit if self.row_limit > 0 else None
                rows   = cursor.fetchmany(limit) if limit else cursor.fetchall()
                cols   = [d[0] for d in cursor.description]
                self.stats.rows = len(rows)
                if rows:
                    print_table(cols, [tuple(r) for r in rows])
                else:
                    print_info("Результат пуст.")
                # предупреждение об обрезке
                if limit and len(rows) == limit:
                    remaining = cursor.fetchone()
                    if remaining:
                        print_warning(
                            f"Показано {limit} строк (лимит). "
                            f"Измените лимит: .limit <N>"
                        )
            else:
                verb = sql.split()[0].upper()
                print_success(
                    f"{verb}: затронуто строк — "
                    f"{COLOR.BOLD}{self.conn.total_changes}{COLOR.RESET}"
                )
        except sqlite3.Error as e:
            self.stats.elapsed = time.perf_counter() - t0
            print_error(f"SQL ошибка: {e}")
        finally:
            self.stats.show()

    # ── вспомогательные ───────────────────────
    def _get_table_names(self) -> list[str]:
        try:
            return [r[0] for r in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()]
        except Exception:
            return []

    @staticmethod
    def _pretty_sql(sql: str):
        """Подсветка ключевых слов SQL в терминале."""
        keywords = re.compile(
            r'\b(SELECT|FROM|WHERE|INSERT|INTO|VALUES|UPDATE|SET|DELETE|'
            r'CREATE|TABLE|INDEX|VIEW|TRIGGER|DROP|ALTER|ADD|COLUMN|'
            r'PRIMARY|KEY|FOREIGN|REFERENCES|NOT|NULL|UNIQUE|DEFAULT|'
            r'BEGIN|COMMIT|ROLLBACK|ON|AS|AND|OR|IN|LIKE|BETWEEN|'
            r'ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|JOIN|LEFT|RIGHT|'
            r'INNER|OUTER|CROSS|INTEGER|TEXT|REAL|BLOB|BOOLEAN|'
            r'IF|EXISTS|AUTOINCREMENT|PRAGMA)\b',
            re.IGNORECASE,
        )
        colored = keywords.sub(
            lambda m: f"{COLOR.CYAN}{COLOR.BOLD}{m.group()}{COLOR.RESET}", sql
        )
        print(f"  {colored}")

    # ── главный цикл ──────────────────────────
    def run(self):
        print_header("SQLite Shell")
        print(f"  {COLOR.GRAY}Введите .help для справки, .open <файл> для открытия БД{COLOR.RESET}\n")

        DISPATCH = {
            ".open":     self.open_db,
            ".close":    lambda _: self.close_db(),
            ".tables":   self._cmd_tables,
            ".schema":   self._cmd_schema,
            ".info":     self._cmd_info,
            ".indexes":  self._cmd_indexes,
            ".views":    self._cmd_views,
            ".triggers": self._cmd_triggers,
            ".size":     self._cmd_size,
            ".limit":    self._cmd_limit,
            ".export":   self._cmd_export,
            ".import":   self._cmd_import,
            ".dump":     self._cmd_dump,
            ".history":  self._cmd_history,
            ".clear":    self._cmd_clear,
            ".help":     lambda _: print(HELP_TEXT),
        }

        buffer: list[str] = []   # многострочный SQL

        while True:
            # Формируем приглашение
            if self.db_path:
                db_name = self.db_path.name
                prompt  = (f"{COLOR.MAGENTA}{COLOR.BOLD}{db_name}{COLOR.RESET}"
                           f"{COLOR.CYAN}>{COLOR.RESET} "
                           if not buffer else
                           f"{'·' * (len(db_name)+1)} {COLOR.CYAN}…{COLOR.RESET} ")
            else:
                prompt = (f"{COLOR.GRAY}sqlite{COLOR.RESET}"
                          f"{COLOR.CYAN}>{COLOR.RESET} "
                          if not buffer else
                          f"       {COLOR.CYAN}…{COLOR.RESET} ")

            try:
                line = input(prompt)
            except KeyboardInterrupt:
                if buffer:
                    buffer.clear()
                    print(f"\n  {COLOR.GRAY}Ввод отменён.{COLOR.RESET}")
                else:
                    print()
                continue
            except EOFError:
                print(f"\n{COLOR.GRAY}До свидания.{COLOR.RESET}")
                break

            stripped = line.strip()

            # Выход
            if stripped in (".exit", ".quit"):
                print(f"\n{COLOR.GRAY}До свидания.{COLOR.RESET}")
                break

            # Пустая строка: если есть буфер — ничего, иначе игнор
            if not stripped:
                continue

            # Мета-команды
            if stripped.startswith(".") and not buffer:
                parts   = stripped.split(maxsplit=1)
                cmd     = parts[0].lower()
                arg     = parts[1] if len(parts) > 1 else ""
                handler = DISPATCH.get(cmd)
                if handler:
                    handler(arg)
                else:
                    print_error(f"Неизвестная команда: {cmd}  (введите .help)")
                continue

            # Многострочный SQL: буферизуем до ';'
            buffer.append(line)
            full_sql = " ".join(buffer)
            if full_sql.rstrip().endswith(";"):
                sql = full_sql.rstrip().rstrip(";").strip()
                buffer.clear()
                if sql:
                    self.execute_sql(sql)

        # Завершение
        self.close_db(silent=True)

    # ── точка входа модуля ────────────────────
    @classmethod
    def start(cls, db_path: Optional[str] = None):
        """Вызывается из terminal.py или main.py."""
        shell = cls()
        if db_path:
            shell.open_db(db_path)
        shell.run()


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────
def _fmt_size(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


# ──────────────────────────────────────────────
# Standalone запуск
# ──────────────────────────────────────────────
if __name__ == "__main__":
    db_arg = sys.argv[1] if len(sys.argv) > 1 else None
    SQLiteShell.start(db_arg)