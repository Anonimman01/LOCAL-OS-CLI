"""
vault.py — Менеджер паролей
Входит в состав local_os/modules/
Шифрование: Fernet (AES-128-CBC) + PBKDF2-HMAC-SHA256
Функции: хранение, генерация, поиск, TOTP, аудит, экспорт/импорт
"""

import os
import sys
import re
import csv
import json
import time
import hmac
import math
import base64
import struct
import hashlib
import secrets
import string
import getpass
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

# ──────────────────────────────────────────────
# Зависимость: cryptography
# ──────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Установите: pip install cryptography", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────────────────────────
# Graceful fallback UI
# ──────────────────────────────────────────────
try:
    from core.ui import (
        print_header, print_success, print_error,
        print_warning, print_info, print_table, COLOR
    )
except ImportError:
    import shutil as _sh

    class COLOR:
        RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM     = "\033[2m"
        RED     = "\033[91m"; GREEN   = "\033[92m"; YELLOW  = "\033[93m"
        CYAN    = "\033[96m"; MAGENTA = "\033[95m"; BLUE    = "\033[94m"
        WHITE   = "\033[97m"; GRAY    = "\033[90m"

    def print_header(t):
        w = _sh.get_terminal_size((80, 24)).columns
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
VAULT_DIR         = Path("vault_data")
DEFAULT_VAULT     = VAULT_DIR / "default.vault"
BACKUP_DIR        = VAULT_DIR / "backups"
EXPORT_DIR        = Path("exports")

PBKDF2_ITERATIONS = 600_000       # OWASP 2023 рекомендация
SALT_SIZE         = 32            # байт
VERSION           = 2             # версия формата файла

# Автоблокировка: секунды бездействия
AUTO_LOCK_SECS    = 300

# Категории записей
CATEGORIES = ["Веб", "Email", "SSH", "API-ключ", "Банк", "Wi-Fi", "Прочее"]

# Уровни силы пароля
STRENGTH_LABELS = {
    0: (COLOR.RED     if "COLOR" in dir() else "", "Очень слабый"),
    1: (COLOR.RED     if "COLOR" in dir() else "", "Слабый"),
    2: (COLOR.YELLOW  if "COLOR" in dir() else "", "Средний"),
    3: (COLOR.GREEN   if "COLOR" in dir() else "", "Сильный"),
    4: (COLOR.MAGENTA if "COLOR" in dir() else "", "Очень сильный"),
}


# ══════════════════════════════════════════════
# Утилиты
# ══════════════════════════════════════════════
def _fmt_dt(ts: Optional[float]) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

def _mask(s: str, visible: int = 3) -> str:
    """Маскирует строку: abc•••••"""
    if len(s) <= visible:
        return "•" * len(s)
    return s[:visible] + "•" * (len(s) - visible)

def _clipboard(text: str):
    """Копирует текст в буфер обмена (если доступно)."""
    try:
        if sys.platform == "darwin":
            import subprocess
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
            return True
        elif sys.platform.startswith("linux"):
            import subprocess
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=text.encode(), check=True)
            return True
        elif sys.platform == "win32":
            import subprocess
            subprocess.run(["clip"], input=text.encode(), check=True)
            return True
    except Exception:
        pass
    return False

def _clear_clipboard_after(seconds: int = 30):
    """Очищает буфер обмена через N секунд."""
    def _clear():
        time.sleep(seconds)
        _clipboard("")
    t = threading.Thread(target=_clear, daemon=True)
    t.start()


# ══════════════════════════════════════════════
# Сила пароля + entropy
# ══════════════════════════════════════════════
def password_strength(pwd: str) -> dict:
    """
    Возвращает score 0-4, entropy (бит), список слабостей.
    """
    score    = 0
    issues   : list[str] = []
    char_set = 0

    if len(pwd) < 8:
        issues.append("Слишком короткий (< 8 символов)")
    elif len(pwd) >= 16:
        score += 1

    if re.search(r"[a-z]", pwd): char_set += 26
    else: issues.append("Нет строчных букв")

    if re.search(r"[A-Z]", pwd): char_set += 26
    else: issues.append("Нет заглавных букв")

    if re.search(r"\d", pwd): char_set += 10
    else: issues.append("Нет цифр")

    if re.search(r"[^a-zA-Z0-9]", pwd): char_set += 32
    else: issues.append("Нет спецсимволов")

    entropy = len(pwd) * math.log2(char_set) if char_set else 0

    if entropy >= 60: score += 2
    elif entropy >= 40: score += 1

    # Паттерны
    if re.search(r"(.)\1{2,}", pwd):
        issues.append("Повторяющиеся символы")
        score = max(0, score - 1)
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwert|asdf)",
                 pwd.lower()):
        issues.append("Последовательные символы")
        score = max(0, score - 1)

    score = min(4, max(0, score))
    return {"score": score, "entropy": entropy, "issues": issues}

def _strength_bar(score: int) -> str:
    filled = "█" * (score + 1)
    empty  = "░" * (4 - score)
    col, label = STRENGTH_LABELS.get(score, ("", ""))
    return f"{col}{filled}{empty} {label}{COLOR.RESET}"


# ══════════════════════════════════════════════
# Генератор паролей
# ══════════════════════════════════════════════
def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
    custom_symbols: str = "",
) -> str:
    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        syms = custom_symbols if custom_symbols else "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars += syms
    if exclude_ambiguous:
        chars = chars.translate(str.maketrans("", "", "Il1O0o"))

    if not chars:
        raise ValueError("Пустой набор символов")

    # Гарантируем наличие каждого класса
    pool   : list[str] = []
    if use_upper:   pool.append(secrets.choice(string.ascii_uppercase))
    if use_digits:  pool.append(secrets.choice(string.digits))
    if use_symbols: pool.append(secrets.choice("!@#$%^&*"))
    pool.append(secrets.choice(string.ascii_lowercase))

    remaining = length - len(pool)
    pool += [secrets.choice(chars) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(pool)
    return "".join(pool)

def generate_passphrase(words: int = 5, separator: str = "-") -> str:
    """EFF-стиль passphrase из случайных слов (встроенный короткий список)."""
    wordlist = [
        "apple","brave","cloud","delta","eagle","frost","grace","honor",
        "ivory","jewel","kings","lunar","maple","nerve","ocean","prism",
        "quest","river","storm","tiger","ultra","vivid","whisp","xenon",
        "yield","zebra","amber","blaze","coral","dwarf","ember","flare",
        "globe","haste","index","jolly","knack","lemon","magic","north",
        "onset","peace","quark","rally","solar","torch","unity","valor",
        "waltz","xylem","yacht","zonal","abode","boxer","crisp","drape",
    ]
    return separator.join(secrets.choice(wordlist) for _ in range(words))


# ══════════════════════════════════════════════
# TOTP (RFC 6238) — без зависимостей
# ══════════════════════════════════════════════
def totp_generate(secret_b32: str, digits: int = 6, period: int = 30) -> tuple[str, int]:
    """Возвращает (код, секунд до истечения)."""
    try:
        key      = base64.b32decode(secret_b32.upper().replace(" ", ""))
        counter  = int(time.time()) // period
        msg      = struct.pack(">Q", counter)
        mac      = hmac.new(key, msg, hashlib.sha1).digest()
        offset   = mac[-1] & 0x0F
        code_int = struct.unpack(">I", mac[offset:offset+4])[0] & 0x7FFFFFFF
        code     = str(code_int % (10 ** digits)).zfill(digits)
        remaining = period - int(time.time()) % period
        return code, remaining
    except Exception as e:
        raise ValueError(f"TOTP ошибка: {e}")


# ══════════════════════════════════════════════
# Запись хранилища
# ══════════════════════════════════════════════
class Entry:
    __slots__ = (
        "id", "title", "username", "password", "url",
        "notes", "category", "tags", "totp_secret",
        "created_at", "updated_at", "accessed_at",
        "password_history",
    )

    def __init__(self, **kw):
        now = time.time()
        self.id              : str         = kw.get("id", _new_id())
        self.title           : str         = kw.get("title", "")
        self.username        : str         = kw.get("username", "")
        self.password        : str         = kw.get("password", "")
        self.url             : str         = kw.get("url", "")
        self.notes           : str         = kw.get("notes", "")
        self.category        : str         = kw.get("category", "Прочее")
        self.tags            : list[str]   = kw.get("tags", [])
        self.totp_secret     : str         = kw.get("totp_secret", "")
        self.created_at      : float       = kw.get("created_at", now)
        self.updated_at      : float       = kw.get("updated_at", now)
        self.accessed_at     : Optional[float] = kw.get("accessed_at")
        self.password_history: list[dict]  = kw.get("password_history", [])

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        return cls(**d)

    def touch(self):
        self.accessed_at = time.time()

    def update_password(self, new_pwd: str):
        if self.password:
            self.password_history.append({
                "password": self.password,
                "changed":  time.time(),
            })
            if len(self.password_history) > 10:
                self.password_history.pop(0)
        self.password   = new_pwd
        self.updated_at = time.time()

def _new_id() -> str:
    return secrets.token_hex(8)


# ══════════════════════════════════════════════
# Криптографическое ядро
# ══════════════════════════════════════════════
class VaultCrypto:
    """PBKDF2-HMAC-SHA256 → Fernet key → шифрование JSON."""

    @staticmethod
    def derive_key(master_pwd: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        raw = kdf.derive(master_pwd.encode("utf-8"))
        return base64.urlsafe_b64encode(raw)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        return Fernet(key).encrypt(data)

    @staticmethod
    def decrypt(token: bytes, key: bytes) -> bytes:
        return Fernet(key).decrypt(token)


# ══════════════════════════════════════════════
# Vault — основной класс
# ══════════════════════════════════════════════
class Vault:
    """
    Зашифрованное хранилище паролей.
    Формат файла (бинарный):
      [4 байта] magic  "VLT\x02"
      [4 байта] PBKDF2 iterations (big-endian uint32)
      [32 байта] salt
      [остаток]  Fernet-токен с JSON-payload
    """

    MAGIC = b"VLT\x02"

    def __init__(self, path: Path = DEFAULT_VAULT):
        self.path      : Path              = path
        self._entries  : dict[str, Entry]  = {}
        self._key      : Optional[bytes]   = None
        self._salt     : Optional[bytes]   = None
        self._locked   : bool              = True
        self._last_act : float             = 0.0
        self._lock_obj : threading.Lock    = threading.Lock()
        VAULT_DIR.mkdir(exist_ok=True)
        BACKUP_DIR.mkdir(exist_ok=True)

    # ── Состояние ─────────────────────────────
    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def _activity(self):
        self._last_act = time.time()

    def check_auto_lock(self):
        if not self._locked and self._last_act:
            if time.time() - self._last_act > AUTO_LOCK_SECS:
                self.lock()
                print_warning("Хранилище автоматически заблокировано (таймаут).")

    # ── Создание / открытие ───────────────────
    def create(self, master_pwd: str):
        """Создаёт новое хранилище с мастер-паролем."""
        self._salt = os.urandom(SALT_SIZE)
        self._key  = VaultCrypto.derive_key(master_pwd, self._salt)
        self._entries = {}
        self._locked  = False
        self._last_act = time.time()
        self._save()
        print_success(f"Хранилище создано: {COLOR.BOLD}{self.path}{COLOR.RESET}")

    def open(self, master_pwd: str) -> bool:
        """Открывает существующее хранилище."""
        if not self.path.exists():
            print_error(f"Файл не найден: {self.path}")
            return False
        try:
            raw = self.path.read_bytes()
            if not raw.startswith(self.MAGIC):
                print_error("Неверный формат файла."); return False

            iterations = struct.unpack(">I", raw[4:8])[0]
            salt       = raw[8:40]
            token      = raw[40:]

            # Перебираем итерации из файла (совместимость версий)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32, salt=salt,
                iterations=iterations,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
            plaintext = VaultCrypto.decrypt(token, key)

            self._salt    = salt
            self._key     = key
            self._entries = {
                e["id"]: Entry.from_dict(e)
                for e in json.loads(plaintext)
            }
            self._locked   = False
            self._last_act = time.time()
            return True

        except InvalidToken:
            print_error("Неверный мастер-пароль.")
            return False
        except Exception as e:
            print_error(f"Ошибка открытия: {e}")
            return False

    def lock(self):
        with self._lock_obj:
            self._key     = None
            self._entries = {}
            self._locked  = True

    def _save(self):
        if self._locked or self._key is None:
            raise RuntimeError("Хранилище заблокировано.")
        payload   = json.dumps(
            [e.to_dict() for e in self._entries.values()],
            ensure_ascii=False, default=str
        ).encode("utf-8")
        token     = VaultCrypto.encrypt(payload, self._key)
        raw       = (self.MAGIC
                     + struct.pack(">I", PBKDF2_ITERATIONS)
                     + self._salt
                     + token)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(raw)
        tmp.replace(self.path)

    def _require_unlocked(self) -> bool:
        self.check_auto_lock()
        if self._locked:
            print_error("Хранилище заблокировано. Откройте его сначала.")
            return False
        self._activity()
        return True

    # ── Резервная копия ───────────────────────
    def backup(self):
        if not self.path.exists():
            print_warning("Нет файла для резервной копии."); return
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = BACKUP_DIR / f"{self.path.stem}_{ts}.vault"
        import shutil
        shutil.copy2(self.path, dst)
        print_success(f"Резервная копия: {COLOR.BOLD}{dst}{COLOR.RESET}")
        # Оставляем последние 10 копий
        copies = sorted(BACKUP_DIR.glob("*.vault"))
        for old in copies[:-10]:
            old.unlink()

    # ── CRUD ──────────────────────────────────
    def add(self, entry: Entry) -> str:
        if not self._require_unlocked(): return ""
        self._entries[entry.id] = entry
        self._save()
        print_success(f"Добавлено: {COLOR.BOLD}{entry.title}{COLOR.RESET}  [{entry.id}]")
        return entry.id

    def get(self, entry_id: str) -> Optional[Entry]:
        if not self._require_unlocked(): return None
        e = self._entries.get(entry_id)
        if e:
            e.touch()
            self._save()
        return e

    def update(self, entry: Entry):
        if not self._require_unlocked(): return
        entry.updated_at = time.time()
        self._entries[entry.id] = entry
        self._save()
        print_success(f"Обновлено: {COLOR.BOLD}{entry.title}{COLOR.RESET}")

    def delete(self, entry_id: str) -> bool:
        if not self._require_unlocked(): return False
        entry = self._entries.pop(entry_id, None)
        if not entry:
            print_error(f"Запись не найдена: {entry_id}")
            return False
        self._save()
        print_success(f"Удалено: {COLOR.BOLD}{entry.title}{COLOR.RESET}")
        return True

    # ── Поиск ─────────────────────────────────
    def search(self, query: str, field: str = "all") -> list[Entry]:
        if not self._require_unlocked(): return []
        q = query.lower()
        results = []
        for e in self._entries.values():
            target = {
                "title":    e.title,
                "username": e.username,
                "url":      e.url,
                "notes":    e.notes,
                "tags":     " ".join(e.tags),
                "all": " ".join([e.title, e.username, e.url,
                                 e.notes, " ".join(e.tags)]),
            }.get(field, e.title)
            if q in target.lower():
                results.append(e)
        return sorted(results, key=lambda x: x.title.lower())

    def list_entries(self, category: Optional[str] = None,
                     tag: Optional[str] = None) -> list[Entry]:
        if not self._require_unlocked(): return []
        entries = list(self._entries.values())
        if category:
            entries = [e for e in entries if e.category == category]
        if tag:
            entries = [e for e in entries if tag in e.tags]
        return sorted(entries, key=lambda x: x.title.lower())

    # ── Смена мастер-пароля ───────────────────
    def change_master(self, old_pwd: str, new_pwd: str) -> bool:
        if not self._require_unlocked(): return False
        # Валидируем старый пароль
        test_key = VaultCrypto.derive_key(old_pwd, self._salt)
        if test_key != self._key:
            print_error("Неверный текущий мастер-пароль.")
            return False
        st = password_strength(new_pwd)
        if st["score"] < 2:
            print_warning("Слабый мастер-пароль! Рекомендуем более сложный.")
        self.backup()
        new_salt  = os.urandom(SALT_SIZE)
        new_key   = VaultCrypto.derive_key(new_pwd, new_salt)
        self._salt = new_salt
        self._key  = new_key
        self._save()
        print_success("Мастер-пароль изменён. Резервная копия создана.")
        return True

    # ── Аудит безопасности ────────────────────
    def audit(self) -> dict:
        if not self._require_unlocked(): return {}

        weak, reused, old, no_2fa = [], [], [], []
        pwd_map: dict[str, list[str]] = defaultdict(list)

        threshold = time.time() - 90 * 86400  # 90 дней

        for e in self._entries.values():
            st = password_strength(e.password)
            if st["score"] < 2:
                weak.append(e)
            if e.updated_at < threshold:
                old.append(e)
            if not e.totp_secret and e.category in ("Веб", "Email", "Банк"):
                no_2fa.append(e)
            if e.password:
                pwd_hash = hashlib.sha256(e.password.encode()).hexdigest()
                pwd_map[pwd_hash].append(e.title)

        for titles in pwd_map.values():
            if len(titles) > 1:
                reused.extend(titles)
        reused = list(set(reused))

        rows = []
        for e in weak:
            rows.append((e.title, f"{COLOR.RED}Слабый{COLOR.RESET}", e.category))
        for title in reused:
            rows.append((title, f"{COLOR.YELLOW}Повтор{COLOR.RESET}", "—"))
        for e in old:
            rows.append((e.title, f"{COLOR.MAGENTA}>90 дней{COLOR.RESET}", _fmt_dt(e.updated_at)))
        for e in no_2fa:
            rows.append((e.title, f"{COLOR.CYAN}Нет 2FA{COLOR.RESET}", e.category))

        if rows:
            print_table(["Запись", "Проблема", "Доп. инфо"], rows,
                        title="Аудит безопасности")
        else:
            print_success("Проблем не обнаружено. Хранилище в порядке.")

        score = 100
        score -= len(weak) * 10
        score -= len(reused) * 5
        score -= len(old) * 3
        score -= len(no_2fa) * 2
        score = max(0, score)

        col = (COLOR.GREEN if score >= 80 else
               COLOR.YELLOW if score >= 50 else COLOR.RED)
        print(f"\n  {COLOR.BOLD}Оценка безопасности: {col}{score}/100{COLOR.RESET}\n")

        return {"weak": weak, "reused": reused, "old": old, "no_2fa": no_2fa}

    # ── Экспорт / импорт ──────────────────────
    def export_csv(self, path: Optional[Path] = None) -> Path:
        """Экспорт в незашифрованный CSV. Предупреждает пользователя."""
        if not self._require_unlocked(): return Path()
        EXPORT_DIR.mkdir(exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        out  = path or EXPORT_DIR / f"vault_export_{ts}.csv"
        fields = ["id","title","username","password","url",
                  "notes","category","tags","created_at","updated_at"]
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for e in self._entries.values():
                row = e.to_dict()
                row["tags"] = ",".join(row.get("tags", []))
                row["created_at"] = _fmt_dt(row["created_at"])
                row["updated_at"] = _fmt_dt(row["updated_at"])
                w.writerow({k: row.get(k, "") for k in fields})
        print_success(f"Экспорт: {COLOR.BOLD}{out}{COLOR.RESET}")
        print_warning("CSV не зашифрован! Храните в защищённом месте.")
        return out

    def import_csv(self, path: Path) -> int:
        """Импорт из CSV (формат export_csv или BitWarden-совместимый)."""
        if not self._require_unlocked(): return 0
        if not path.exists():
            print_error(f"Файл не найден: {path}"); return 0
        imported = 0
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                e = Entry(
                    title    = row.get("title") or row.get("name", ""),
                    username = row.get("username") or row.get("login_username", ""),
                    password = row.get("password") or row.get("login_password", ""),
                    url      = row.get("url")      or row.get("login_uri", ""),
                    notes    = row.get("notes", ""),
                    category = row.get("category", "Прочее"),
                    tags     = [t.strip() for t in
                                row.get("tags", "").split(",") if t.strip()],
                )
                self._entries[e.id] = e
                imported += 1
        self._save()
        print_success(f"Импортировано записей: {COLOR.BOLD}{imported}{COLOR.RESET}")
        return imported

    # ── Отображение ───────────────────────────
    def show_list(self, entries: Optional[list[Entry]] = None, masked: bool = True):
        if entries is None:
            entries = self.list_entries()
        if not entries:
            print_info("Записей нет.")
            return
        rows = []
        for e in entries:
            pwd_col = (_mask(e.password) if masked
                       else f"{COLOR.GREEN}{e.password}{COLOR.RESET}")
            totp = f"{COLOR.CYAN}✔{COLOR.RESET}" if e.totp_secret else "—"
            rows.append((
                e.id[:8],
                e.title,
                e.username or "—",
                pwd_col,
                e.category,
                totp,
                _fmt_dt(e.updated_at),
            ))
        print_table(
            ["ID", "Название", "Пользователь", "Пароль", "Категория", "2FA", "Обновлено"],
            rows, title=f"Записи ({len(entries)})"
        )

    def show_entry(self, entry: Entry, reveal: bool = False):
        """Подробный вид одной записи."""
        st = password_strength(entry.password)
        lines = [
            ("ID",           entry.id),
            ("Название",     f"{COLOR.BOLD}{entry.title}{COLOR.RESET}"),
            ("Категория",    entry.category),
            ("Пользователь", entry.username or "—"),
            ("Пароль",       entry.password if reveal else _mask(entry.password, 0)),
            ("Сила пароля",  _strength_bar(st["score"])),
            ("Entropy",      f"{st['entropy']:.1f} бит"),
            ("URL",          entry.url or "—"),
            ("Теги",         ", ".join(entry.tags) if entry.tags else "—"),
            ("2FA",          "✔ настроен" if entry.totp_secret else "✘ нет"),
            ("Заметки",      entry.notes or "—"),
            ("Создано",      _fmt_dt(entry.created_at)),
            ("Обновлено",    _fmt_dt(entry.updated_at)),
            ("Открывалось",  _fmt_dt(entry.accessed_at)),
        ]
        w = max(len(k) for k, _ in lines)
        print(f"\n  {COLOR.CYAN}{'─'*50}{COLOR.RESET}")
        for k, v in lines:
            print(f"  {COLOR.BOLD}{k:<{w}}{COLOR.RESET}  {v}")
        print(f"  {COLOR.CYAN}{'─'*50}{COLOR.RESET}\n")


# ══════════════════════════════════════════════
# Интерактивное меню
# ══════════════════════════════════════════════
def _ask(prompt: str, secret: bool = False, default: str = "") -> str:
    try:
        if secret:
            val = getpass.getpass(f"  {COLOR.CYAN}{prompt}: {COLOR.RESET}")
        else:
            val = input(f"  {COLOR.CYAN}{prompt}{' ['+default+']' if default else ''}: "
                        f"{COLOR.RESET}").strip()
        return val or default
    except (EOFError, KeyboardInterrupt):
        return ""

def _confirm(prompt: str) -> bool:
    try:
        return input(f"  {COLOR.YELLOW}{prompt} (yes/no): "
                     f"{COLOR.RESET}").strip().lower() in ("yes", "y", "да")
    except (EOFError, KeyboardInterrupt):
        return False


# ──────────────────────────────────────────────
_vault = Vault()      # глобальный экземпляр для интерактивного режима
# ──────────────────────────────────────────────

def _ensure_open() -> bool:
    if _vault.is_locked:
        print_warning("Хранилище закрыто.")
        pwd = _ask("Мастер-пароль", secret=True)
        if not pwd:
            return False
        if _vault.path.exists():
            return _vault.open(pwd)
        else:
            print_warning("Хранилище не существует. Создать новое?")
            if _confirm("Создать"):
                _vault.create(pwd)
                return True
            return False
    return True


def _menu_add():
    if not _ensure_open(): return
    print(f"\n  {COLOR.BOLD}Новая запись{COLOR.RESET}")
    title = _ask("Название (обязательно)")
    if not title:
        print_warning("Название обязательно."); return

    username = _ask("Имя пользователя")
    url      = _ask("URL")
    category = _ask(f"Категория ({'/'.join(CATEGORIES)})", default="Веб")
    if category not in CATEGORIES:
        category = "Прочее"

    # Пароль: ввести или сгенерировать
    pwd_choice = _ask("[1] Ввести пароль  [2] Сгенерировать  [3] Passphrase", default="2")
    if pwd_choice == "1":
        pwd = _ask("Пароль", secret=True)
    elif pwd_choice == "3":
        n   = int(_ask("Слов в пароле-фразе", default="5"))
        pwd = generate_passphrase(n)
        print_info(f"Сгенерирована фраза: {COLOR.BOLD}{pwd}{COLOR.RESET}")
    else:
        length = int(_ask("Длина пароля", default="20"))
        pwd    = generate_password(length)
        print_info(f"Сгенерирован пароль: {COLOR.BOLD}{pwd}{COLOR.RESET}")

    st = password_strength(pwd)
    print(f"  Сила: {_strength_bar(st['score'])}  |  entropy: {st['entropy']:.1f} бит")
    for issue in st["issues"]:
        print_warning(f"  {issue}")

    notes    = _ask("Заметки")
    tags_raw = _ask("Теги (через запятую)")
    tags     = [t.strip() for t in tags_raw.split(",") if t.strip()]
    totp     = _ask("TOTP secret (Base32, Enter — пропустить)")

    e = Entry(title=title, username=username, password=pwd,
              url=url, notes=notes, category=category,
              tags=tags, totp_secret=totp)
    _vault.add(e)

    if _confirm("Скопировать пароль в буфер обмена?"):
        if _clipboard(pwd):
            _clear_clipboard_after(30)
            print_info("Пароль скопирован. Очистится через 30 сек.")
        else:
            print_warning("Буфер обмена недоступен.")


def _menu_search():
    if not _ensure_open(): return
    q = _ask("Поиск")
    if not q: return
    results = _vault.search(q)
    if not results:
        print_info("Ничего не найдено."); return
    _vault.show_list(results)

    eid = _ask("ID для просмотра (Enter — отмена)")
    if not eid: return
    # Ищем по префиксу
    match = next((e for e in results if e.id.startswith(eid)), None)
    if not match:
        print_error("Запись не найдена."); return
    reveal = _confirm("Показать пароль?")
    entry  = _vault.get(match.id)
    if entry:
        _vault.show_entry(entry, reveal=reveal)
        if _confirm("Скопировать пароль?"):
            if _clipboard(entry.password):
                _clear_clipboard_after(30)
                print_info("Скопировано. Очистится через 30 сек.")


def _menu_list():
    if not _ensure_open(): return
    cat = _ask(f"Фильтр по категории (Enter — все): ")
    cat = cat if cat in CATEGORIES else None
    entries = _vault.list_entries(category=cat)
    _vault.show_list(entries)


def _menu_delete():
    if not _ensure_open(): return
    eid = _ask("ID записи для удаления")
    if not eid: return
    match = next((e for e in _vault.list_entries() if e.id.startswith(eid)), None)
    if not match:
        print_error("Запись не найдена."); return
    print_warning(f"Удалить: {COLOR.BOLD}{match.title}{COLOR.RESET}?")
    if _confirm("Подтвердить удаление"):
        _vault.delete(match.id)


def _menu_generate():
    print(f"\n  {COLOR.BOLD}Генератор паролей{COLOR.RESET}")
    mode = _ask("[1] Случайный  [2] Passphrase", default="1")
    if mode == "2":
        n   = int(_ask("Количество слов", default="5"))
        sep = _ask("Разделитель", default="-")
        pwd = generate_passphrase(n, sep)
    else:
        length  = int(_ask("Длина", default="20"))
        symbols = _ask("Спецсимволы? (yes/no)", default="yes") in ("yes","y","да")
        pwd     = generate_password(length, use_symbols=symbols)

    st = password_strength(pwd)
    print(f"\n  {COLOR.BOLD}{COLOR.GREEN}{pwd}{COLOR.RESET}")
    print(f"  Сила: {_strength_bar(st['score'])}  |  entropy: {st['entropy']:.1f} бит\n")

    if _confirm("Скопировать в буфер?"):
        if _clipboard(pwd):
            _clear_clipboard_after(30)
            print_info("Скопировано. Очистится через 30 сек.")


def _menu_totp():
    if not _ensure_open(): return
    q = _ask("Название записи (поиск)")
    if not q: return
    results = _vault.search(q)
    results = [e for e in results if e.totp_secret]
    if not results:
        print_info("Записей с TOTP не найдено."); return
    for e in results:
        try:
            code, remaining = totp_generate(e.totp_secret)
            bar_w = 20
            filled = int(bar_w * remaining / 30)
            bar   = f"{COLOR.GREEN}{'█'*filled}{COLOR.GRAY}{'░'*(bar_w-filled)}{COLOR.RESET}"
            print(f"  {COLOR.BOLD}{e.title:<30}{COLOR.RESET}"
                  f"  {COLOR.CYAN}{COLOR.BOLD}{code}{COLOR.RESET}"
                  f"  {bar} {remaining}с")
        except ValueError as err:
            print_error(f"  {e.title}: {err}")


def _menu_audit():
    if not _ensure_open(): return
    _vault.audit()


def _menu_change_master():
    if not _ensure_open(): return
    old = _ask("Текущий мастер-пароль", secret=True)
    new = _ask("Новый мастер-пароль", secret=True)
    if not new:
        print_warning("Пустой пароль недопустим."); return
    confirm = _ask("Повторите новый пароль", secret=True)
    if new != confirm:
        print_error("Пароли не совпадают."); return
    _vault.change_master(old, new)


def _menu_export():
    if not _ensure_open(): return
    print_warning("Экспорт создаёт незашифрованный CSV-файл!")
    if _confirm("Продолжить"):
        _vault.export_csv()


def _menu_import():
    if not _ensure_open(): return
    path = Path(_ask("Путь к CSV-файлу").strip()).expanduser()
    _vault.import_csv(path)


def run_vault():
    """Точка входа для terminal.py."""
    print_header("Менеджер паролей")

    MENU = {
        "1": ("Список записей",         _menu_list),
        "2": ("Добавить запись",         _menu_add),
        "3": ("Поиск",                   _menu_search),
        "4": ("Удалить запись",          _menu_delete),
        "5": ("Генератор паролей",       _menu_generate),
        "6": ("TOTP-коды",               _menu_totp),
        "7": ("Аудит безопасности",      _menu_audit),
        "8": ("Сменить мастер-пароль",   _menu_change_master),
        "9": ("Экспорт CSV",             _menu_export),
        "i": ("Импорт CSV",              _menu_import),
        "l": ("Заблокировать",           lambda: (_vault.lock(), print_success("Заблокировано."))),
        "0": ("Назад",                   None),
    }

    while True:
        status = (f"{COLOR.GREEN}● Открыто{COLOR.RESET} "
                  f"({COLOR.BOLD}{_vault.entry_count}{COLOR.RESET} зап.)"
                  if not _vault.is_locked
                  else f"{COLOR.RED}● Заблокировано{COLOR.RESET}")
        print(f"\n  {COLOR.GRAY}Статус: {status}{COLOR.RESET}")
        print(f"  {COLOR.BOLD}Операции:{COLOR.RESET}")
        for k, (label, _) in MENU.items():
            print(f"    {COLOR.CYAN}[{k}]{COLOR.RESET} {label}")
        try:
            choice = input(f"\n  {COLOR.CYAN}>{COLOR.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if choice == "0":
            break
        entry = MENU.get(choice)
        if entry and entry[1]:
            try:
                entry[1]()
            except KeyboardInterrupt:
                print_info("Отменено.")
        elif not entry:
            print_error("Неверный выбор.")

    _vault.lock()


# ──────────────────────────────────────────────
# Standalone
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Vault — менеджер паролей")
    parser.add_argument("--vault", default=str(DEFAULT_VAULT), help="Путь к файлу хранилища")
    args = parser.parse_args()
    _vault.path = Path(args.vault)
    run_vault()