"""
scheduler.py — Планировщик фоновых задач для local_os
======================================================
Поддерживает:
  • Одноразовые и повторяющиеся задачи (cron-like выражения)
  • Приоритеты, теги, зависимости между задачами
  • Персистентность (SQLite)
  • История выполнения с метриками
  • Graceful shutdown, потокобезопасность
  • Хуки: on_success / on_failure / on_timeout
  • Throttling / jitter для предотвращения thundering herd
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

# ─── Логгер ─────────────────────────────────────────────────────────────────

logger = logging.getLogger("local_os.scheduler")


# ─── Константы ──────────────────────────────────────────────────────────────

DB_PATH          = Path("data/scheduler.db")
MAX_HISTORY      = 500          # записей истории на задачу
DEFAULT_TIMEOUT  = 300          # секунд
TICK_INTERVAL    = 1.0          # секунд
MAX_RETRY        = 3
RETRY_BACKOFF    = 2.0          # экспоненциальный коэффициент


# ─── Перечисления ────────────────────────────────────────────────────────────

class TaskStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"
    CANCELLED = "cancelled"
    TIMEOUT   = "timeout"
    SKIPPED   = "skipped"


class Priority(int, Enum):
    CRITICAL = 0
    HIGH     = 1
    NORMAL   = 2
    LOW      = 3
    IDLE     = 4


class TriggerType(str, Enum):
    ONCE     = "once"
    INTERVAL = "interval"
    CRON     = "cron"
    MANUAL   = "manual"


# ─── Cron-парсер ─────────────────────────────────────────────────────────────

class CronExpression:
    """
    Поддерживает поля: minute hour dom month dow
    Допустимы: * , - /   Например: "*/5 * * * *"
    """

    FIELDS = ("minute", "hour", "dom", "month", "dow")
    RANGES = {
        "minute": (0, 59),
        "hour":   (0, 23),
        "dom":    (1, 31),
        "month":  (1, 12),
        "dow":    (0, 6),
    }

    def __init__(self, expression: str) -> None:
        self.raw = expression.strip()
        parts = self.raw.split()
        if len(parts) != 5:
            raise ValueError(f"Cron-выражение должно содержать 5 полей: '{expression}'")
        self._parsed: dict[str, set[int]] = {
            name: self._parse_field(part, *self.RANGES[name])
            for name, part in zip(self.FIELDS, parts)
        }

    # ── внутренний парсинг ──────────────────────────────────────────────────

    @staticmethod
    def _parse_field(expr: str, lo: int, hi: int) -> set[int]:
        result: set[int] = set()
        for segment in expr.split(","):
            segment = segment.strip()
            step = 1
            if "/" in segment:
                segment, step_s = segment.split("/", 1)
                step = int(step_s)
            if segment == "*":
                result.update(range(lo, hi + 1, step))
            elif "-" in segment:
                a, b = segment.split("-", 1)
                result.update(range(int(a), int(b) + 1, step))
            else:
                val = int(segment)
                if step > 1:
                    result.update(range(val, hi + 1, step))
                else:
                    result.add(val)
        return result

    # ── публичный API ───────────────────────────────────────────────────────

    def matches(self, dt: datetime) -> bool:
        return (
            dt.minute  in self._parsed["minute"]
            and dt.hour   in self._parsed["hour"]
            and dt.day    in self._parsed["dom"]
            and dt.month  in self._parsed["month"]
            and dt.weekday() % 7 in self._parsed["dow"]   # Python: 0=Mon
        )

    def next_run(self, after: datetime) -> datetime:
        """Возвращает ближайший момент после `after`, совпадающий с cron."""
        dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        # Ограничим поиск одним годом, чтобы не зависнуть на невалидном cron
        deadline = dt + timedelta(days=366)
        while dt < deadline:
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)
        raise ValueError(f"Не удалось найти следующий запуск для '{self.raw}'")

    def __repr__(self) -> str:
        return f"CronExpression({self.raw!r})"


# ─── Триггеры ─────────────────────────────────────────────────────────────────

@dataclass
class Trigger:
    type: TriggerType
    run_at: Optional[datetime] = None       # ONCE / следующий CRON/INTERVAL
    interval_seconds: Optional[float] = None
    cron_expr: Optional[CronExpression] = None
    jitter_seconds: float = 0.0             # случайный сдвиг

    # ── фабрики ─────────────────────────────────────────────────────────────

    @classmethod
    def once(cls, when: datetime, jitter: float = 0.0) -> "Trigger":
        return cls(type=TriggerType.ONCE, run_at=when, jitter_seconds=jitter)

    @classmethod
    def interval(cls, seconds: float, jitter: float = 0.0) -> "Trigger":
        if seconds <= 0:
            raise ValueError("interval_seconds должен быть > 0")
        run_at = _now() + timedelta(seconds=seconds)
        return cls(type=TriggerType.INTERVAL, run_at=run_at,
                   interval_seconds=seconds, jitter_seconds=jitter)

    @classmethod
    def cron(cls, expression: str, jitter: float = 0.0) -> "Trigger":
        expr = CronExpression(expression)
        run_at = expr.next_run(_now())
        return cls(type=TriggerType.CRON, run_at=run_at,
                   cron_expr=expr, jitter_seconds=jitter)

    @classmethod
    def manual(cls) -> "Trigger":
        return cls(type=TriggerType.MANUAL)

    # ── вспомогательное ─────────────────────────────────────────────────────

    def is_due(self, now: Optional[datetime] = None) -> bool:
        if self.type == TriggerType.MANUAL:
            return False
        now = now or _now()
        return self.run_at is not None and now >= self.run_at

    def advance(self) -> None:
        """Вычисляет следующий run_at для повторяющихся триггеров."""
        import random
        now = _now()
        jitter = random.uniform(0, self.jitter_seconds) if self.jitter_seconds else 0.0
        if self.type == TriggerType.INTERVAL and self.interval_seconds:
            self.run_at = now + timedelta(seconds=self.interval_seconds + jitter)
        elif self.type == TriggerType.CRON and self.cron_expr:
            self.run_at = self.cron_expr.next_run(now) + timedelta(seconds=jitter)
        else:
            self.run_at = None  # ONCE → больше не повторяется

    def to_dict(self) -> dict:
        return {
            "type":             self.type.value,
            "run_at":           self.run_at.isoformat() if self.run_at else None,
            "interval_seconds": self.interval_seconds,
            "cron_expr":        self.cron_expr.raw if self.cron_expr else None,
            "jitter_seconds":   self.jitter_seconds,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Trigger":
        t = TriggerType(d["type"])
        run_at = datetime.fromisoformat(d["run_at"]) if d.get("run_at") else None
        cron_expr = CronExpression(d["cron_expr"]) if d.get("cron_expr") else None
        return cls(
            type=t,
            run_at=run_at,
            interval_seconds=d.get("interval_seconds"),
            cron_expr=cron_expr,
            jitter_seconds=d.get("jitter_seconds", 0.0),
        )


# ─── Результат выполнения ─────────────────────────────────────────────────────

@dataclass
class RunRecord:
    run_id:      str
    task_id:     str
    started_at:  datetime
    finished_at: Optional[datetime] = None
    status:      TaskStatus = TaskStatus.RUNNING
    return_value: Any = None
    error:       Optional[str] = None
    duration_ms: Optional[float] = None

    def finish(self, status: TaskStatus,
               return_value: Any = None, error: Optional[str] = None) -> None:
        self.finished_at = _now()
        self.status      = status
        self.return_value = return_value
        self.error       = error
        self.duration_ms = (
            (self.finished_at - self.started_at).total_seconds() * 1000
        )


# ─── Описание задачи ─────────────────────────────────────────────────────────

@dataclass
class Task:
    task_id:    str
    name:       str
    func:       Callable
    trigger:    Trigger
    args:       tuple        = field(default_factory=tuple)
    kwargs:     dict         = field(default_factory=dict)
    priority:   Priority     = Priority.NORMAL
    tags:       list[str]    = field(default_factory=list)
    depends_on: list[str]    = field(default_factory=list)   # task_id зависимостей
    timeout:    float        = DEFAULT_TIMEOUT
    max_retries: int         = MAX_RETRY
    enabled:    bool         = True
    description: str         = ""

    # хуки — не сериализуются в БД
    on_success: Optional[Callable[["Task", RunRecord], None]] = field(
        default=None, repr=False, compare=False)
    on_failure: Optional[Callable[["Task", RunRecord], None]] = field(
        default=None, repr=False, compare=False)
    on_timeout: Optional[Callable[["Task", RunRecord], None]] = field(
        default=None, repr=False, compare=False)

    # runtime-состояние (не хранится)
    _retry_count: int = field(default=0, init=False, repr=False, compare=False)
    _last_run:   Optional[RunRecord] = field(
        default=None, init=False, repr=False, compare=False)

    # ── сериализация ────────────────────────────────────────────────────────

    def to_row(self) -> dict:
        return {
            "task_id":     self.task_id,
            "name":        self.name,
            "trigger":     json.dumps(self.trigger.to_dict()),
            "args":        json.dumps(list(self.args)),
            "kwargs":      json.dumps(self.kwargs),
            "priority":    self.priority.value,
            "tags":        json.dumps(self.tags),
            "depends_on":  json.dumps(self.depends_on),
            "timeout":     self.timeout,
            "max_retries": self.max_retries,
            "enabled":     int(self.enabled),
            "description": self.description,
            "func_name":   getattr(self.func, "__qualname__", repr(self.func)),
        }


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_id() -> str:
    return uuid.uuid4().hex[:12]


# ─── Персистентный слой ───────────────────────────────────────────────────────

class SchedulerDB:
    """Тонкая обёртка над SQLite для персистентности метаданных задач и истории."""

    SCHEMA_TASKS = """
        CREATE TABLE IF NOT EXISTS tasks (
            task_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            trigger     TEXT NOT NULL,
            args        TEXT NOT NULL DEFAULT '[]',
            kwargs      TEXT NOT NULL DEFAULT '{}',
            priority    INTEGER NOT NULL DEFAULT 2,
            tags        TEXT NOT NULL DEFAULT '[]',
            depends_on  TEXT NOT NULL DEFAULT '[]',
            timeout     REAL NOT NULL DEFAULT 300,
            max_retries INTEGER NOT NULL DEFAULT 3,
            enabled     INTEGER NOT NULL DEFAULT 1,
            description TEXT NOT NULL DEFAULT '',
            func_name   TEXT NOT NULL DEFAULT ''
        )
    """

    SCHEMA_HISTORY = """
        CREATE TABLE IF NOT EXISTS run_history (
            run_id       TEXT PRIMARY KEY,
            task_id      TEXT NOT NULL,
            started_at   TEXT NOT NULL,
            finished_at  TEXT,
            status       TEXT NOT NULL,
            return_value TEXT,
            error        TEXT,
            duration_ms  REAL,
            FOREIGN KEY(task_id) REFERENCES tasks(task_id)
        )
    """

    def __init__(self, path: Path = DB_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._local = threading.local()
        self._migrate()

    @contextmanager
    def _conn(self):
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(
                str(self._path), check_same_thread=False,
                isolation_level=None,       # autocommit
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        yield self._local.conn

    def _migrate(self) -> None:
        with self._conn() as c:
            c.execute(self.SCHEMA_TASKS)
            c.execute(self.SCHEMA_HISTORY)
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_history_task "
                "ON run_history(task_id, started_at DESC)"
            )

    # ── задачи ──────────────────────────────────────────────────────────────

    def upsert_task(self, row: dict) -> None:
        cols   = ", ".join(row.keys())
        placeh = ", ".join(f":{k}" for k in row.keys())
        with self._conn() as c:
            c.execute(
                f"INSERT OR REPLACE INTO tasks ({cols}) VALUES ({placeh})", row
            )

    def delete_task(self, task_id: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM tasks WHERE task_id=?", (task_id,))

    def load_tasks(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM tasks").fetchall()
        return [dict(r) for r in rows]

    def update_trigger(self, task_id: str, trigger_json: str) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE tasks SET trigger=? WHERE task_id=?",
                (trigger_json, task_id),
            )

    # ── история ─────────────────────────────────────────────────────────────

    def save_run(self, rec: RunRecord) -> None:
        with self._conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO run_history
                   (run_id, task_id, started_at, finished_at, status,
                    return_value, error, duration_ms)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    rec.run_id,
                    rec.task_id,
                    rec.started_at.isoformat(),
                    rec.finished_at.isoformat() if rec.finished_at else None,
                    rec.status.value,
                    json.dumps(rec.return_value) if rec.return_value is not None else None,
                    rec.error,
                    rec.duration_ms,
                ),
            )
            # Ограничиваем историю
            c.execute(
                """DELETE FROM run_history WHERE task_id=? AND run_id NOT IN (
                       SELECT run_id FROM run_history
                       WHERE task_id=?
                       ORDER BY started_at DESC LIMIT ?
                   )""",
                (rec.task_id, rec.task_id, MAX_HISTORY),
            )

    def get_history(
        self, task_id: str, limit: int = 20
    ) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                """SELECT * FROM run_history WHERE task_id=?
                   ORDER BY started_at DESC LIMIT ?""",
                (task_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                """SELECT
                       task_id,
                       COUNT(*)                              AS total_runs,
                       SUM(status='success')                AS successes,
                       SUM(status='failed')                 AS failures,
                       SUM(status='timeout')                AS timeouts,
                       ROUND(AVG(duration_ms), 2)           AS avg_ms,
                       MAX(started_at)                      AS last_run
                   FROM run_history
                   GROUP BY task_id"""
            ).fetchall()
        return [dict(r) for r in rows]


# ─── Исполнитель задачи ───────────────────────────────────────────────────────

class _TaskExecutor:
    """Запускает функцию задачи в отдельном потоке с таймаутом."""

    def __init__(self, task: Task, db: SchedulerDB,
                 dependency_ok: Callable[[str], bool]) -> None:
        self._task         = task
        self._db           = db
        self._dep_ok       = dependency_ok
        self._result_lock  = threading.Lock()

    def run(self) -> RunRecord:
        task = self._task
        rec  = RunRecord(
            run_id=_make_id(),
            task_id=task.task_id,
            started_at=_now(),
        )

        # ── проверка зависимостей ────────────────────────────────────────────
        for dep_id in task.depends_on:
            if not self._dep_ok(dep_id):
                rec.finish(TaskStatus.SKIPPED,
                           error=f"Зависимость '{dep_id}' не выполнена")
                self._db.save_run(rec)
                logger.warning("[%s] Пропущена: зависимость '%s' не готова",
                               task.name, dep_id)
                return rec

        logger.info("[%s] Запуск (run_id=%s, priority=%s)",
                    task.name, rec.run_id, task.priority.name)

        result_box: list = []
        error_box:  list = []

        def _target() -> None:
            try:
                rv = task.func(*task.args, **task.kwargs)
                result_box.append(rv)
            except Exception:
                error_box.append(traceback.format_exc())

        thread = threading.Thread(target=_target, daemon=True,
                                  name=f"task-{task.task_id[:6]}")
        thread.start()
        thread.join(timeout=task.timeout)

        if thread.is_alive():
            # Поток всё ещё работает → timeout
            rec.finish(TaskStatus.TIMEOUT,
                       error=f"Превышен таймаут {task.timeout}s")
            self._db.save_run(rec)
            logger.error("[%s] Таймаут (%ss)", task.name, task.timeout)
            if task.on_timeout:
                _safe_call(task.on_timeout, task, rec)
            return rec

        if error_box:
            task._retry_count += 1
            if task._retry_count <= task.max_retries:
                backoff = RETRY_BACKOFF ** (task._retry_count - 1)
                logger.warning("[%s] Ошибка (попытка %d/%d), повтор через %.1fs",
                               task.name, task._retry_count,
                               task.max_retries, backoff)
                time.sleep(backoff)
                return self.run()              # рекурсивный retry
            rec.finish(TaskStatus.FAILED, error=error_box[0])
            self._db.save_run(rec)
            logger.error("[%s] Провалена: %s", task.name,
                         error_box[0].splitlines()[-1])
            if task.on_failure:
                _safe_call(task.on_failure, task, rec)
        else:
            task._retry_count = 0
            rv = result_box[0] if result_box else None
            rec.finish(TaskStatus.SUCCESS, return_value=rv)
            self._db.save_run(rec)
            logger.info("[%s] Успешно за %.1fms", task.name, rec.duration_ms)
            if task.on_success:
                _safe_call(task.on_success, task, rec)

        task._last_run = rec
        return rec


def _safe_call(fn: Callable, *args) -> None:
    try:
        fn(*args)
    except Exception:
        logger.warning("Хук упал: %s", traceback.format_exc())


# ─── Основной планировщик ─────────────────────────────────────────────────────

class Scheduler:
    """
    Потокобезопасный планировщик фоновых задач с персистентностью.

    Использование
    -------------
    >>> sched = Scheduler()
    >>> sched.add(
    ...     name="Резервное копирование",
    ...     func=backup_database,
    ...     trigger=Trigger.cron("0 3 * * *"),
    ...     tags=["backup", "db"],
    ... )
    >>> sched.start()
    ...
    >>> sched.stop()
    """

    def __init__(self, db_path: Path = DB_PATH,
                 tick: float = TICK_INTERVAL) -> None:
        self._db    = SchedulerDB(db_path)
        self._tick  = tick
        self._tasks: dict[str, Task] = {}
        self._lock  = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running_ids: set[str] = set()

        logger.info("Scheduler инициализирован (db=%s)", db_path)

    # ── управление жизненным циклом ──────────────────────────────────────────

    def start(self, daemon: bool = True) -> "Scheduler":
        """Запускает фоновый поток-диспетчер."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Scheduler уже запущен")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=daemon, name="scheduler-main"
        )
        self._thread.start()
        logger.info("Scheduler запущен")
        return self

    def stop(self, wait: float = 5.0) -> None:
        """Останавливает диспетчер; ждёт завершения активных задач до `wait` сек."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=wait)
        logger.info("Scheduler остановлен")

    def __enter__(self) -> "Scheduler":
        return self.start()

    def __exit__(self, *_) -> None:
        self.stop()

    # ── регистрация задач ────────────────────────────────────────────────────

    def add(
        self,
        func: Callable,
        trigger: Trigger,
        *,
        name: str = "",
        task_id: Optional[str] = None,
        args: tuple = (),
        kwargs: Optional[dict] = None,
        priority: Priority = Priority.NORMAL,
        tags: Optional[list[str]] = None,
        depends_on: Optional[list[str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRY,
        enabled: bool = True,
        description: str = "",
        on_success: Optional[Callable] = None,
        on_failure: Optional[Callable] = None,
        on_timeout: Optional[Callable] = None,
    ) -> str:
        """Регистрирует задачу и возвращает её task_id."""
        task_id = task_id or _make_id()
        name    = name    or getattr(func, "__name__", repr(func))
        task = Task(
            task_id=task_id,
            name=name,
            func=func,
            trigger=trigger,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            tags=tags or [],
            depends_on=depends_on or [],
            timeout=timeout,
            max_retries=max_retries,
            enabled=enabled,
            description=description,
            on_success=on_success,
            on_failure=on_failure,
            on_timeout=on_timeout,
        )
        with self._lock:
            self._tasks[task_id] = task
        self._db.upsert_task(task.to_row())
        logger.debug("Задача зарегистрирована: %s (%s)", name, task_id)
        return task_id

    def remove(self, task_id: str) -> None:
        with self._lock:
            self._tasks.pop(task_id, None)
        self._db.delete_task(task_id)

    def enable(self, task_id: str) -> None:
        self._set_enabled(task_id, True)

    def disable(self, task_id: str) -> None:
        self._set_enabled(task_id, False)

    def _set_enabled(self, task_id: str, value: bool) -> None:
        with self._lock:
            if task := self._tasks.get(task_id):
                task.enabled = value
        with self._lock:
            row = self._tasks.get(task_id)
        if row:
            self._db.upsert_task(row.to_row())

    def run_now(self, task_id: str) -> Optional[RunRecord]:
        """Запускает задачу немедленно, игнорируя расписание."""
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"Задача '{task_id}' не найдена")
        return self._dispatch(task)

    # ── основной цикл ────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick_once()
            except Exception:
                logger.exception("Ошибка в основном цикле планировщика")
            self._stop_event.wait(timeout=self._tick)

    def _tick_once(self) -> None:
        now = _now()
        with self._lock:
            due = sorted(
                (t for t in self._tasks.values()
                 if t.enabled
                 and t.task_id not in self._running_ids
                 and t.trigger.is_due(now)),
                key=lambda t: t.priority.value,
            )

        for task in due:
            threading.Thread(
                target=self._dispatch_safe,
                args=(task,),
                daemon=True,
                name=f"exec-{task.task_id[:6]}",
            ).start()

    def _dispatch_safe(self, task: Task) -> None:
        with self._lock:
            self._running_ids.add(task.task_id)
        try:
            self._dispatch(task)
        finally:
            with self._lock:
                self._running_ids.discard(task.task_id)
            task.trigger.advance()
            self._db.update_trigger(
                task.task_id,
                json.dumps(task.trigger.to_dict()),
            )

    def _dispatch(self, task: Task) -> RunRecord:
        executor = _TaskExecutor(
            task=task,
            db=self._db,
            dependency_ok=self._dependency_satisfied,
        )
        return executor.run()

    def _dependency_satisfied(self, dep_id: str) -> bool:
        with self._lock:
            dep = self._tasks.get(dep_id)
        if dep is None:
            return False
        return (
            dep._last_run is not None
            and dep._last_run.status == TaskStatus.SUCCESS
        )

    # ── публичное API для мониторинга ────────────────────────────────────────

    def list_tasks(self) -> list[dict]:
        with self._lock:
            tasks = list(self._tasks.values())
        result = []
        for t in tasks:
            entry = {
                "task_id":    t.task_id,
                "name":       t.name,
                "enabled":    t.enabled,
                "priority":   t.priority.name,
                "tags":       t.tags,
                "trigger":    t.trigger.to_dict(),
                "running":    t.task_id in self._running_ids,
                "last_status": (
                    t._last_run.status.value if t._last_run else "never"
                ),
                "description": t.description,
            }
            result.append(entry)
        return result

    def get_history(self, task_id: str, limit: int = 20) -> list[dict]:
        return self._db.get_history(task_id, limit)

    def get_stats(self) -> list[dict]:
        raw   = self._db.get_stats()
        names = {t.task_id: t.name for t in self._tasks.values()}
        for r in raw:
            r["name"] = names.get(r["task_id"], r["task_id"])
        return raw

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ─── Декораторный API ─────────────────────────────────────────────────────────

_default_scheduler: Optional[Scheduler] = None


def get_default_scheduler() -> Scheduler:
    global _default_scheduler
    if _default_scheduler is None:
        _default_scheduler = Scheduler()
    return _default_scheduler


def scheduled(
    trigger: Trigger,
    *,
    name: str = "",
    priority: Priority = Priority.NORMAL,
    tags: Optional[list[str]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    **kwargs,
):
    """
    Декоратор для регистрации функции в планировщике по умолчанию.

    >>> @scheduled(Trigger.cron("*/10 * * * *"), tags=["monitor"])
    ... def check_disk():
    ...     ...
    """
    def decorator(fn: Callable) -> Callable:
        sched = get_default_scheduler()
        sched.add(
            fn,
            trigger=trigger,
            name=name or fn.__name__,
            priority=priority,
            tags=tags,
            timeout=timeout,
            **kwargs,
        )
        return fn
    return decorator


# ─── UI-интеграция (используется terminal.py) ─────────────────────────────────

class SchedulerModule:
    """
    Адаптер для интеграции с роутингом core/terminal.py.
    Все методы возвращают данные — вывод на экране делает ui.py.
    """

    def __init__(self, scheduler: Optional[Scheduler] = None) -> None:
        self.scheduler = scheduler or get_default_scheduler()

    # ── команды меню ────────────────────────────────────────────────────────

    def cmd_list(self) -> list[dict]:
        return self.scheduler.list_tasks()

    def cmd_add_demo(self) -> str:
        """Добавляет демонстрационную задачу (используется из меню)."""
        def _demo_task():
            logger.info("Демо-задача выполнена в %s", _now().isoformat())

        tid = self.scheduler.add(
            _demo_task,
            trigger=Trigger.interval(30),
            name="Демо-задача",
            tags=["demo"],
            description="Тестовая задача каждые 30 секунд",
        )
        return tid

    def cmd_remove(self, task_id: str) -> None:
        self.scheduler.remove(task_id)

    def cmd_run_now(self, task_id: str) -> RunRecord:
        return self.scheduler.run_now(task_id)

    def cmd_enable(self, task_id: str) -> None:
        self.scheduler.enable(task_id)

    def cmd_disable(self, task_id: str) -> None:
        self.scheduler.disable(task_id)

    def cmd_history(self, task_id: str, limit: int = 10) -> list[dict]:
        return self.scheduler.get_history(task_id, limit)

    def cmd_stats(self) -> list[dict]:
        return self.scheduler.get_stats()

    def cmd_start(self) -> None:
        if not self.scheduler.is_running:
            self.scheduler.start()

    def cmd_stop(self) -> None:
        self.scheduler.stop()

    def status(self) -> dict:
        return {
            "running":    self.scheduler.is_running,
            "task_count": len(self.scheduler._tasks),
            "active":     len(self.scheduler._running_ids),
        }