"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    local_os · modules · crypto.py                           ║
║          Enterprise-Grade Cryptographic Operations Module                    ║
║                                                                              ║
║  Features:                                                                   ║
║    • Multi-algorithm hashing  (MD5, SHA-1/256/384/512, BLAKE2b/s, SHA3)     ║
║    • Symmetric file encryption/decryption (AES-256-GCM via Fernet + raw)   ║
║    • Asymmetric RSA key generation, encryption, signing & verification       ║
║    • PBKDF2 / scrypt / Argon2-id key derivation                             ║
║    • HMAC message authentication                                             ║
║    • Secure random token / password generation                               ║
║    • Base64 / hex encode-decode helpers                                      ║
║    • Integrity manifest creation & verification                              ║
║    • Interactive terminal menu integrated with core.ui                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Author  : local_os project
License : MIT
Python  : ≥ 3.10
Deps    : cryptography >= 41.0, rich
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import hashlib
import hmac
import json
import os
import secrets
import string
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Generator

# ─── third-party ─────────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    import base64 as _b64
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich import print as rprint
    _RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    _RICH_AVAILABLE = False
    _console = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
#  Constants & Enumerations
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_SIZE: int = 65_536          # 64 KiB  – streaming I/O buffer
RSA_KEY_BITS: int = 4096          # RSA modulus size (corporate baseline)
AES_KEY_BYTES: int = 32           # 256-bit AES
PBKDF2_ITERATIONS: int = 600_000  # NIST 2023 recommended minimum
SCRYPT_N: int = 2 ** 17           # CPU/memory cost
SCRYPT_R: int = 8
SCRYPT_P: int = 1
SALT_BYTES: int = 32
TOKEN_BYTES: int = 32

_MANIFEST_VERSION = "1.0"
_FERNET_EXT = ".fenc"
_AES_GCM_EXT = ".aesgcm"
_RSA_PUB_EXT = ".pub.pem"
_RSA_PRIV_EXT = ".priv.pem"


class HashAlgo(str, Enum):
    MD5       = "md5"
    SHA1      = "sha1"
    SHA256    = "sha256"
    SHA384    = "sha384"
    SHA512    = "sha512"
    SHA3_256  = "sha3_256"
    SHA3_512  = "sha3_512"
    BLAKE2B   = "blake2b"
    BLAKE2S   = "blake2s"


class KDFAlgo(str, Enum):
    PBKDF2 = "pbkdf2"
    SCRYPT = "scrypt"


class EncMode(str, Enum):
    FERNET  = "fernet"
    AES_GCM = "aesgcm"


# ─────────────────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "Package 'cryptography' is not installed.\n"
            "Run: pip install cryptography"
        )


def _print(msg: str, style: str = "") -> None:
    if _RICH_AVAILABLE and _console:
        _console.print(msg, style=style)
    else:
        print(msg)


def _panel(title: str, content: str, border_style: str = "cyan") -> None:
    if _RICH_AVAILABLE and _console:
        _console.print(Panel(content, title=title, border_style=border_style))
    else:
        print(f"\n[{title}]\n{content}")


def _prompt(label: str, default: str = "", password: bool = False) -> str:
    if _RICH_AVAILABLE:
        return Prompt.ask(label, default=default, password=password)
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default


def _confirm(label: str, default: bool = False) -> bool:
    if _RICH_AVAILABLE:
        return Confirm.ask(label, default=default)
    answer = input(f"{label} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def _int_prompt(label: str, default: int = 0) -> int:
    if _RICH_AVAILABLE:
        return IntPrompt.ask(label, default=default)
    raw = input(f"{label} [{default}]: ").strip()
    return int(raw) if raw.isdigit() else default


def _file_chunks(path: Path) -> Generator[bytes, None, None]:
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            yield chunk


def _progress_bar(description: str = "Processing") -> Progress:
    return Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeElapsedColumn(),
        console=_console,
        transient=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HashResult:
    algorithm : str
    hex_digest : str
    file_path  : str
    size_bytes : int
    elapsed_ms : float

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class ManifestEntry:
    path      : str
    algorithm : str
    digest    : str
    size      : int
    mtime     : float


@dataclass
class IntegrityManifest:
    version   : str = _MANIFEST_VERSION
    created   : float = field(default_factory=time.time)
    algorithm : str = HashAlgo.SHA256
    entries   : list[ManifestEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version"   : self.version,
            "created"   : self.created,
            "algorithm" : self.algorithm,
            "entries"   : [e.__dict__ for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IntegrityManifest":
        obj = cls(
            version   = data.get("version", _MANIFEST_VERSION),
            created   = data.get("created", 0.0),
            algorithm = data.get("algorithm", HashAlgo.SHA256),
        )
        obj.entries = [ManifestEntry(**e) for e in data.get("entries", [])]
        return obj


# ─────────────────────────────────────────────────────────────────────────────
#  1. Hashing
# ─────────────────────────────────────────────────────────────────────────────

def hash_data(data: bytes, algorithm: HashAlgo | str = HashAlgo.SHA256) -> str:
    """
    Hash arbitrary bytes with the specified algorithm.
    Returns lowercase hex digest.
    """
    algo = str(algorithm).lower()
    if algo in ("blake2b",):
        h = hashlib.blake2b(data)
    elif algo in ("blake2s",):
        h = hashlib.blake2s(data)
    else:
        h = hashlib.new(algo, data)
    return h.hexdigest()


def hash_file(
    path: Path | str,
    algorithm: HashAlgo | str = HashAlgo.SHA256,
    *,
    verbose: bool = False,
) -> HashResult:
    """
    Stream-hash a file. Supports arbitrarily large files.
    Returns a HashResult dataclass.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    algo = str(algorithm).lower()
    if algo == "blake2b":
        h = hashlib.blake2b()
    elif algo == "blake2s":
        h = hashlib.blake2s()
    else:
        h = hashlib.new(algo)

    size = path.stat().st_size
    processed = 0
    t0 = time.perf_counter()

    if verbose and _RICH_AVAILABLE:
        with _progress_bar(f"Hashing [{algo.upper()}]") as prog:
            task = prog.add_task("", total=size)
            for chunk in _file_chunks(path):
                h.update(chunk)
                processed += len(chunk)
                prog.update(task, advance=len(chunk))
    else:
        for chunk in _file_chunks(path):
            h.update(chunk)

    elapsed = (time.perf_counter() - t0) * 1000
    return HashResult(
        algorithm  = algo.upper(),
        hex_digest = h.hexdigest(),
        file_path  = str(path.resolve()),
        size_bytes = size,
        elapsed_ms = round(elapsed, 2),
    )


def hash_file_multi(
    path: Path | str,
    algorithms: list[HashAlgo | str] | None = None,
) -> dict[str, HashResult]:
    """
    Hash a single file with multiple algorithms in one streaming pass.
    Efficient: file is read only once.
    """
    if algorithms is None:
        algorithms = [HashAlgo.SHA256, HashAlgo.SHA512, HashAlgo.BLAKE2B]

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    hashers: dict[str, object] = {}
    for algo in algorithms:
        a = str(algo).lower()
        if a == "blake2b":
            hashers[a] = hashlib.blake2b()
        elif a == "blake2s":
            hashers[a] = hashlib.blake2s()
        else:
            hashers[a] = hashlib.new(a)

    size = path.stat().st_size
    t0 = time.perf_counter()

    for chunk in _file_chunks(path):
        for h in hashers.values():
            h.update(chunk)  # type: ignore[attr-defined]

    elapsed = (time.perf_counter() - t0) * 1000
    return {
        algo: HashResult(
            algorithm  = algo.upper(),
            hex_digest = h.hexdigest(),  # type: ignore[attr-defined]
            file_path  = str(path.resolve()),
            size_bytes = size,
            elapsed_ms = round(elapsed, 2),
        )
        for algo, h in hashers.items()
    }


def verify_hash(path: Path | str, expected: str, algorithm: HashAlgo | str = HashAlgo.SHA256) -> bool:
    """
    Constant-time hash comparison to prevent timing attacks.
    """
    result = hash_file(path, algorithm)
    return hmac.compare_digest(result.hex_digest.lower(), expected.strip().lower())


# ─────────────────────────────────────────────────────────────────────────────
#  2. Key Derivation
# ─────────────────────────────────────────────────────────────────────────────

def derive_key_pbkdf2(
    password: str | bytes,
    salt: bytes | None = None,
    *,
    iterations: int = PBKDF2_ITERATIONS,
    key_length: int = AES_KEY_BYTES,
    hash_algo: str = "sha256",
) -> tuple[bytes, bytes]:
    """
    Derive a cryptographic key via PBKDF2-HMAC.
    Returns (key, salt).
    """
    _require_crypto()
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    pwd = password.encode() if isinstance(password, str) else password
    kdf = PBKDF2HMAC(
        algorithm  = hashes.SHA256() if hash_algo == "sha256" else hashes.SHA512(),
        length     = key_length,
        salt       = salt,
        iterations = iterations,
        backend    = default_backend(),
    )
    key = kdf.derive(pwd)
    return key, salt


def derive_key_scrypt(
    password: str | bytes,
    salt: bytes | None = None,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
    key_length: int = AES_KEY_BYTES,
) -> tuple[bytes, bytes]:
    """
    Derive a cryptographic key via scrypt.
    Returns (key, salt).
    """
    _require_crypto()
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    pwd = password.encode() if isinstance(password, str) else password
    kdf = Scrypt(salt=salt, length=key_length, n=n, r=r, p=p, backend=default_backend())
    key = kdf.derive(pwd)
    return key, salt


def _fernet_key_from_raw(raw_key: bytes) -> bytes:
    """Convert 32-byte raw key to URL-safe base64 Fernet key."""
    return _b64.urlsafe_b64encode(raw_key)


# ─────────────────────────────────────────────────────────────────────────────
#  3. Symmetric Encryption — Fernet (AES-128-CBC + HMAC-SHA256)
# ─────────────────────────────────────────────────────────────────────────────

def fernet_generate_key() -> bytes:
    """Generate a new random Fernet key (URL-safe base64)."""
    _require_crypto()
    return Fernet.generate_key()


def fernet_encrypt_file(
    src: Path | str,
    dst: Path | str | None = None,
    *,
    key: bytes | None = None,
    password: str | None = None,
    kdf: KDFAlgo = KDFAlgo.PBKDF2,
) -> tuple[Path, bytes, bytes | None]:
    """
    Encrypt *src* with Fernet.

    Either *key* or *password* must be provided.
    Returns (output_path, key_used, salt_if_password_based).
    """
    _require_crypto()
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)

    salt: bytes | None = None

    if password is not None:
        raw, salt = (derive_key_scrypt if kdf == KDFAlgo.SCRYPT else derive_key_pbkdf2)(password)
        fernet_key = _fernet_key_from_raw(raw)
    elif key is not None:
        fernet_key = key
    else:
        raise ValueError("Provide either 'key' or 'password'.")

    f = Fernet(fernet_key)
    plaintext = src.read_bytes()
    ciphertext = f.encrypt(plaintext)

    dst_path = Path(dst) if dst else src.with_suffix(src.suffix + _FERNET_EXT)

    # Header: magic(4) + salt_len(2) + salt(variable)
    if salt:
        header = b"LOFS" + struct.pack(">H", len(salt)) + salt
    else:
        header = b"LOFK" + struct.pack(">H", 0)

    dst_path.write_bytes(header + ciphertext)
    return dst_path, fernet_key, salt


def fernet_decrypt_file(
    src: Path | str,
    dst: Path | str | None = None,
    *,
    key: bytes | None = None,
    password: str | None = None,
) -> Path:
    """
    Decrypt a Fernet-encrypted file produced by :func:`fernet_encrypt_file`.
    Returns the output path.
    """
    _require_crypto()
    src = Path(src)
    raw_bytes = src.read_bytes()

    magic = raw_bytes[:4]
    salt_len = struct.unpack(">H", raw_bytes[4:6])[0]
    header_end = 6 + salt_len
    ciphertext = raw_bytes[header_end:]

    if magic == b"LOFS":
        salt = raw_bytes[6:header_end]
        if password is None:
            raise ValueError("File was encrypted with a password; supply 'password'.")
        raw, _ = derive_key_pbkdf2(password, salt)
        fernet_key = _fernet_key_from_raw(raw)
    elif magic == b"LOFK":
        if key is None:
            raise ValueError("File was encrypted with a key; supply 'key'.")
        fernet_key = key
    else:
        raise ValueError("Not a local_os Fernet-encrypted file (bad magic bytes).")

    f = Fernet(fernet_key)
    try:
        plaintext = f.decrypt(ciphertext)
    except InvalidToken as exc:
        raise ValueError("Decryption failed: wrong key/password or corrupted file.") from exc

    # Strip .fenc if present, else append .dec
    name = src.name
    if name.endswith(_FERNET_EXT):
        out_name = name[: -len(_FERNET_EXT)]
    else:
        out_name = name + ".dec"

    dst_path = Path(dst) if dst else src.parent / out_name
    dst_path.write_bytes(plaintext)
    return dst_path


# ─────────────────────────────────────────────────────────────────────────────
#  4. Symmetric Encryption — AES-256-GCM (authenticated)
# ─────────────────────────────────────────────────────────────────────────────

_GCM_NONCE_BYTES = 12
_GCM_MAGIC = b"LOGCM"   # local_os GCM marker


def aesgcm_encrypt_file(
    src: Path | str,
    dst: Path | str | None = None,
    *,
    key: bytes | None = None,
    password: str | None = None,
    kdf: KDFAlgo = KDFAlgo.PBKDF2,
    aad: bytes | None = None,
) -> tuple[Path, bytes, bytes | None]:
    """
    Encrypt *src* with AES-256-GCM (AEAD).

    Wire format:
        magic(5) | salt_flag(1) | [salt(32)] | nonce(12) | ciphertext+tag

    Returns (output_path, raw_key, salt).
    """
    _require_crypto()
    src = Path(src)
    if not src.is_file():
        raise FileNotFoundError(src)

    salt: bytes | None = None

    if password is not None:
        key, salt = (derive_key_scrypt if kdf == KDFAlgo.SCRYPT else derive_key_pbkdf2)(password)
    elif key is None:
        key = os.urandom(AES_KEY_BYTES)

    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES-GCM requires exactly {AES_KEY_BYTES} bytes key.")

    nonce = os.urandom(_GCM_NONCE_BYTES)
    aesgcm = AESGCM(key)
    plaintext = src.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    flag = b"\x01" if salt else b"\x00"
    salt_block = salt if salt else b""
    header = _GCM_MAGIC + flag + salt_block + nonce

    dst_path = Path(dst) if dst else src.with_suffix(src.suffix + _AES_GCM_EXT)
    dst_path.write_bytes(header + ciphertext)
    return dst_path, key, salt


def aesgcm_decrypt_file(
    src: Path | str,
    dst: Path | str | None = None,
    *,
    key: bytes | None = None,
    password: str | None = None,
    aad: bytes | None = None,
) -> Path:
    """
    Decrypt an AES-256-GCM file produced by :func:`aesgcm_encrypt_file`.
    """
    _require_crypto()
    src = Path(src)
    raw = src.read_bytes()

    magic = raw[:5]
    if magic != _GCM_MAGIC:
        raise ValueError("Not a local_os AES-GCM file.")

    flag = raw[5:6]
    offset = 6

    if flag == b"\x01":
        salt = raw[offset: offset + SALT_BYTES]
        offset += SALT_BYTES
        if password is None:
            raise ValueError("File was password-encrypted; supply 'password'.")
        key, _ = derive_key_pbkdf2(password, salt)
    else:
        if key is None:
            raise ValueError("File was key-encrypted; supply 'key'.")

    nonce = raw[offset: offset + _GCM_NONCE_BYTES]
    offset += _GCM_NONCE_BYTES
    ciphertext = raw[offset:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError("AES-GCM decryption failed: wrong key/password or corrupted file.") from exc

    name = src.name
    if name.endswith(_AES_GCM_EXT):
        out_name = name[: -len(_AES_GCM_EXT)]
    else:
        out_name = name + ".dec"

    dst_path = Path(dst) if dst else src.parent / out_name
    dst_path.write_bytes(plaintext)
    return dst_path


# ─────────────────────────────────────────────────────────────────────────────
#  5. Asymmetric RSA
# ─────────────────────────────────────────────────────────────────────────────

def rsa_generate_keypair(
    key_size: int = RSA_KEY_BITS,
    *,
    private_key_password: str | None = None,
) -> tuple[bytes, bytes]:
    """
    Generate an RSA key pair.
    Returns (private_pem, public_pem).
    """
    _require_crypto()
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size        = key_size,
        backend         = default_backend(),
    )

    enc_algo = (
        serialization.BestAvailableEncryption(private_key_password.encode())
        if private_key_password
        else serialization.NoEncryption()
    )

    private_pem = private_key.private_bytes(
        encoding   = serialization.Encoding.PEM,
        format     = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = enc_algo,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding = serialization.Encoding.PEM,
        format   = serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def rsa_save_keypair(
    directory: Path | str,
    basename: str = "id_rsa",
    *,
    private_pem: bytes,
    public_pem: bytes,
) -> tuple[Path, Path]:
    """
    Persist PEM files.  Returns (private_path, public_path).
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv = directory / (basename + _RSA_PRIV_EXT)
    pub  = directory / (basename + _RSA_PUB_EXT)
    priv.write_bytes(private_pem)
    priv.chmod(0o600)  # owner-read-only
    pub.write_bytes(public_pem)
    return priv, pub


def rsa_encrypt(public_pem: bytes, plaintext: bytes) -> bytes:
    """Encrypt up to RSA limit bytes with RSA-OAEP-SHA256."""
    _require_crypto()
    pub = serialization.load_pem_public_key(public_pem, backend=default_backend())
    return pub.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf       = asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label     = None,
        ),
    )


def rsa_decrypt(private_pem: bytes, ciphertext: bytes, *, password: str | None = None) -> bytes:
    """Decrypt RSA-OAEP ciphertext."""
    _require_crypto()
    pwd = password.encode() if password else None
    priv = serialization.load_pem_private_key(private_pem, password=pwd, backend=default_backend())
    return priv.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf       = asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label     = None,
        ),
    )


def rsa_sign(private_pem: bytes, data: bytes, *, password: str | None = None) -> bytes:
    """Sign *data* with RSA-PSS-SHA512."""
    _require_crypto()
    pwd = password.encode() if password else None
    priv = serialization.load_pem_private_key(private_pem, password=pwd, backend=default_backend())
    return priv.sign(
        data,
        asym_padding.PSS(
            mgf        = asym_padding.MGF1(hashes.SHA512()),
            salt_length = asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA512(),
    )


def rsa_verify(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS-SHA512 signature. Returns True on success."""
    _require_crypto()
    pub = serialization.load_pem_public_key(public_pem, backend=default_backend())
    try:
        pub.verify(
            signature, data,
            asym_padding.PSS(
                mgf        = asym_padding.MGF1(hashes.SHA512()),
                salt_length = asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA512(),
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  6. HMAC
# ─────────────────────────────────────────────────────────────────────────────

def hmac_sign(key: bytes, data: bytes, algorithm: str = "sha256") -> str:
    """Compute HMAC and return hex digest."""
    mac = hmac.new(key, data, algorithm)
    return mac.hexdigest()


def hmac_verify(key: bytes, data: bytes, expected_hex: str, algorithm: str = "sha256") -> bool:
    """Constant-time HMAC verification."""
    computed = hmac_sign(key, data, algorithm)
    return hmac.compare_digest(computed, expected_hex.lower())


# ─────────────────────────────────────────────────────────────────────────────
#  7. Secure Random & Token Utilities
# ─────────────────────────────────────────────────────────────────────────────

def generate_token(nbytes: int = TOKEN_BYTES) -> str:
    """Cryptographically secure URL-safe token (hex)."""
    return secrets.token_hex(nbytes)


def generate_password(
    length: int = 24,
    *,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """
    Generate a cryptographically random password.

    Ambiguous characters removed when *exclude_ambiguous* is True:
    0, O, I, l, 1, |
    """
    AMBIGUOUS = set("0OIl1|")
    pool = ""
    required_chars: list[str] = []

    if upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required_chars.append(secrets.choice(chars))
    if lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required_chars.append(secrets.choice(chars))
    if digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required_chars.append(secrets.choice(chars))
    if symbols:
        chars = "!@#$%^&*()-_=+[]{};<>?"
        pool += chars
        required_chars.append(secrets.choice(chars))

    if not pool:
        raise ValueError("At least one character class must be enabled.")

    remaining = length - len(required_chars)
    if remaining < 0:
        raise ValueError(f"length must be ≥ {len(required_chars)} for chosen options.")

    password_chars = required_chars + [secrets.choice(pool) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_salt(nbytes: int = SALT_BYTES) -> bytes:
    """Generate a cryptographically random salt."""
    return os.urandom(nbytes)


# ─────────────────────────────────────────────────────────────────────────────
#  8. Encoding Helpers
# ─────────────────────────────────────────────────────────────────────────────

def b64_encode(data: bytes, *, url_safe: bool = False) -> str:
    if url_safe:
        return _b64.urlsafe_b64encode(data).decode()
    return _b64.b64encode(data).decode()


def b64_decode(text: str, *, url_safe: bool = False) -> bytes:
    if url_safe:
        return _b64.urlsafe_b64decode(text.encode())
    return _b64.b64decode(text.encode())


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(text: str) -> bytes:
    return bytes.fromhex(text.strip())


# ─────────────────────────────────────────────────────────────────────────────
#  9. Integrity Manifest
# ─────────────────────────────────────────────────────────────────────────────

def create_manifest(
    directory: Path | str,
    output: Path | str | None = None,
    *,
    algorithm: HashAlgo | str = HashAlgo.SHA256,
    recursive: bool = True,
    exclude_patterns: list[str] | None = None,
) -> IntegrityManifest:
    """
    Walk *directory* and create an integrity manifest (JSON).
    """
    directory = Path(directory)
    exclude_patterns = exclude_patterns or [".manifest.json"]

    manifest = IntegrityManifest(algorithm=str(algorithm))
    pattern = "**/*" if recursive else "*"

    files = [p for p in directory.glob(pattern)
             if p.is_file() and not any(ex in p.name for ex in exclude_patterns)]

    if _RICH_AVAILABLE:
        with _progress_bar("Building manifest") as prog:
            task = prog.add_task("", total=len(files))
            for fp in files:
                result = hash_file(fp, algorithm)
                manifest.entries.append(ManifestEntry(
                    path      = str(fp.relative_to(directory)),
                    algorithm = result.algorithm,
                    digest    = result.hex_digest,
                    size      = result.size_bytes,
                    mtime     = fp.stat().st_mtime,
                ))
                prog.update(task, advance=1)
    else:
        for fp in files:
            result = hash_file(fp, algorithm)
            manifest.entries.append(ManifestEntry(
                path      = str(fp.relative_to(directory)),
                algorithm = result.algorithm,
                digest    = result.hex_digest,
                size      = result.size_bytes,
                mtime     = fp.stat().st_mtime,
            ))

    out_path = Path(output) if output else directory / ".manifest.json"
    out_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    return manifest


def verify_manifest(
    directory: Path | str,
    manifest_path: Path | str | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """
    Verify all files in *directory* against a manifest.

    Returns:
        ok_files      – paths that passed
        failed_files  – paths with wrong digest
        missing_files – paths absent from disk
    """
    directory = Path(directory)
    manifest_path = Path(manifest_path) if manifest_path else directory / ".manifest.json"

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = IntegrityManifest.from_dict(data)

    ok: list[str] = []
    failed: list[str] = []
    missing: list[str] = []

    for entry in manifest.entries:
        file_path = directory / entry.path
        if not file_path.exists():
            missing.append(entry.path)
            continue
        result = hash_file(file_path, entry.algorithm)
        if hmac.compare_digest(result.hex_digest, entry.digest):
            ok.append(entry.path)
        else:
            failed.append(entry.path)

    return ok, failed, missing


# ─────────────────────────────────────────────────────────────────────────────
#  10. Interactive Terminal Menu
# ─────────────────────────────────────────────────────────────────────────────

class CryptoModule:
    """
    Terminal-facing wrapper — integrates with core.terminal routing.
    All public methods are menu handlers callable by the router.
    """

    NAME = "🔐 Crypto Tools"
    DESCRIPTION = "Hashing · Encryption · RSA · HMAC · Passwords · Manifests"

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _display_hash_result(result: HashResult) -> None:
        if not _RICH_AVAILABLE:
            print(f"\n[{result.algorithm}] {result.hex_digest}")
            return
        table = Table(show_header=False, border_style="cyan", padding=(0, 1))
        table.add_column("Key",   style="bold cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Algorithm",  result.algorithm)
        table.add_row("Digest",     f"[bold green]{result.hex_digest}[/]")
        table.add_row("File",       result.file_path)
        table.add_row("Size",       f"{result.size_bytes:,} bytes")
        table.add_row("Time",       f"{result.elapsed_ms} ms")
        _console.print(table)

    @staticmethod
    def _choose_algo(prompt_text: str = "Algorithm") -> HashAlgo:
        choices = [a.value for a in HashAlgo]
        if _RICH_AVAILABLE:
            _console.print(
                "[cyan]Algorithms:[/] " + ", ".join(choices)
            )
        raw = _prompt(prompt_text, default="sha256").lower()
        try:
            return HashAlgo(raw)
        except ValueError:
            _print(f"[yellow]Unknown algo '{raw}', defaulting to sha256.[/yellow]")
            return HashAlgo.SHA256

    # ── menu handlers ─────────────────────────────────────────────────────────

    def menu_hash_file(self) -> None:
        """Hash a single file."""
        path_str = _prompt("File path")
        path = Path(path_str)
        algo = self._choose_algo()
        try:
            result = hash_file(path, algo, verbose=True)
            self._display_hash_result(result)
        except FileNotFoundError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_hash_multi(self) -> None:
        """Hash a file with all algorithms simultaneously."""
        path_str = _prompt("File path")
        path = Path(path_str)
        try:
            results = hash_file_multi(path, list(HashAlgo))
            if _RICH_AVAILABLE:
                table = Table(title="Multi-Hash Results", border_style="cyan")
                table.add_column("Algorithm", style="bold cyan")
                table.add_column("Digest",    style="green")
                for algo, r in results.items():
                    table.add_row(r.algorithm, r.hex_digest)
                _console.print(table)
            else:
                for algo, r in results.items():
                    print(f"{r.algorithm}: {r.hex_digest}")
        except FileNotFoundError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_verify_hash(self) -> None:
        """Verify a file against a known digest."""
        path_str = _prompt("File path")
        expected = _prompt("Expected digest (hex)")
        algo = self._choose_algo()
        try:
            ok = verify_hash(Path(path_str), expected, algo)
            if ok:
                _print("[bold green]✓ Hash matches — file is intact.[/bold green]")
            else:
                _print("[bold red]✗ Hash MISMATCH — file may be corrupted or tampered.[/bold red]")
        except FileNotFoundError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_encrypt_file(self) -> None:
        """Encrypt a file (Fernet or AES-GCM)."""
        path_str  = _prompt("File to encrypt")
        mode_raw  = _prompt("Mode [fernet/aesgcm]", default="aesgcm").lower()
        mode      = EncMode.AES_GCM if "gcm" in mode_raw else EncMode.FERNET
        use_pwd   = _confirm("Use password (instead of random key)?", default=True)

        password: str | None = None
        key: bytes | None = None

        if use_pwd:
            password = _prompt("Passphrase", password=True)
            password2 = _prompt("Confirm passphrase", password=True)
            if password != password2:
                _print("[red]Passphrases do not match.[/red]")
                return
        else:
            key = os.urandom(AES_KEY_BYTES)
            _print(f"[yellow]Random key (hex): {key.hex()}[/yellow]")
            _print("[yellow]⚠  Store this key — it cannot be recovered![/yellow]")

        try:
            fn = fernet_encrypt_file if mode == EncMode.FERNET else aesgcm_encrypt_file
            out, used_key, salt = fn(Path(path_str), key=key, password=password)
            _print(f"[green]✓ Encrypted → {out}[/green]")
            if not use_pwd:
                _print(f"[dim]Key (hex): {used_key.hex()}[/dim]")
        except Exception as e:
            _print(f"[red]✗ Encryption failed: {e}[/red]")

    def menu_decrypt_file(self) -> None:
        """Decrypt a Fernet or AES-GCM encrypted file."""
        path_str = _prompt("Encrypted file path")
        path = Path(path_str)

        auto_mode = path.suffix == _AES_GCM_EXT or _AES_GCM_EXT in path.name
        if auto_mode:
            mode = EncMode.AES_GCM
        else:
            mode_raw = _prompt("Mode [fernet/aesgcm]", default="fernet").lower()
            mode = EncMode.AES_GCM if "gcm" in mode_raw else EncMode.FERNET

        use_pwd = _confirm("Decrypt with password?", default=True)

        password: str | None = None
        key: bytes | None = None

        if use_pwd:
            password = _prompt("Passphrase", password=True)
        else:
            key_hex = _prompt("Key (hex)")
            try:
                key = bytes.fromhex(key_hex.strip())
            except ValueError:
                _print("[red]Invalid hex key.[/red]")
                return

        try:
            fn = fernet_decrypt_file if mode == EncMode.FERNET else aesgcm_decrypt_file
            out = fn(path, key=key, password=password)
            _print(f"[green]✓ Decrypted → {out}[/green]")
        except ValueError as e:
            _print(f"[red]✗ {e}[/red]")
        except Exception as e:
            _print(f"[red]✗ Unexpected error: {e}[/red]")

    def menu_rsa_keygen(self) -> None:
        """Generate RSA key pair and save to disk."""
        directory = _prompt("Output directory", default="./keys")
        basename  = _prompt("Key basename", default="id_rsa")
        bits_str  = _prompt("Key size [2048/3072/4096]", default="4096")
        try:
            bits = int(bits_str)
        except ValueError:
            bits = RSA_KEY_BITS

        use_pwd = _confirm("Password-protect private key?", default=True)
        password: str | None = None
        if use_pwd:
            password = _prompt("Private key passphrase", password=True)

        _print(f"[cyan]Generating {bits}-bit RSA key pair …[/cyan]")
        t0 = time.perf_counter()
        try:
            priv_pem, pub_pem = rsa_generate_keypair(bits, private_key_password=password)
            priv_path, pub_path = rsa_save_keypair(
                directory, basename, private_pem=priv_pem, public_pem=pub_pem
            )
            elapsed = time.perf_counter() - t0
            _print(f"[green]✓ Private key → {priv_path}  (chmod 600)[/green]")
            _print(f"[green]✓ Public  key → {pub_path}[/green]")
            _print(f"[dim]Generated in {elapsed:.2f}s[/dim]")
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_rsa_sign_verify(self) -> None:
        """Sign or verify a file with RSA-PSS-SHA512."""
        action = _prompt("Action [sign/verify]", default="sign").lower()

        if action == "sign":
            file_str = _prompt("File to sign")
            priv_pem_path = _prompt("Private key path (.priv.pem)")
            pwd = _prompt("Key passphrase (leave blank if none)", password=True)
            try:
                data = Path(file_str).read_bytes()
                priv_pem = Path(priv_pem_path).read_bytes()
                sig = rsa_sign(priv_pem, data, password=pwd or None)
                sig_path = Path(file_str).with_suffix(".sig")
                sig_path.write_bytes(sig)
                _print(f"[green]✓ Signature → {sig_path}[/green]")
                _print(f"[dim]Signature (hex): {sig.hex()[:64]}…[/dim]")
            except Exception as e:
                _print(f"[red]✗ {e}[/red]")

        else:  # verify
            file_str   = _prompt("Signed file")
            sig_str    = _prompt("Signature file (.sig)")
            pub_pem_path = _prompt("Public key path (.pub.pem)")
            try:
                data    = Path(file_str).read_bytes()
                sig     = Path(sig_str).read_bytes()
                pub_pem = Path(pub_pem_path).read_bytes()
                valid = rsa_verify(pub_pem, data, sig)
                if valid:
                    _print("[bold green]✓ Signature VALID.[/bold green]")
                else:
                    _print("[bold red]✗ Signature INVALID or file tampered.[/bold red]")
            except Exception as e:
                _print(f"[red]✗ {e}[/red]")

    def menu_hmac(self) -> None:
        """Compute or verify HMAC."""
        action = _prompt("Action [sign/verify]", default="sign").lower()
        key_hex = _prompt("HMAC key (hex, leave blank to generate)")
        if not key_hex.strip():
            key = generate_salt(32)
            _print(f"[yellow]Generated key: {key.hex()}[/yellow]")
        else:
            key = bytes.fromhex(key_hex.strip())

        data_str = _prompt("Data (text) or file path")
        path = Path(data_str)
        if path.is_file():
            data = path.read_bytes()
        else:
            data = data_str.encode()

        algo = _prompt("Hash algorithm [sha256/sha512]", default="sha256").lower()

        if action == "sign":
            result = hmac_sign(key, data, algo)
            _print(f"[green]HMAC-{algo.upper()}: {result}[/green]")
        else:
            expected = _prompt("Expected HMAC hex")
            ok = hmac_verify(key, data, expected, algo)
            if ok:
                _print("[bold green]✓ HMAC valid.[/bold green]")
            else:
                _print("[bold red]✗ HMAC mismatch.[/bold red]")

    def menu_password_generator(self) -> None:
        """Generate secure random passwords."""
        count  = _int_prompt("How many passwords?", default=5)
        length = _int_prompt("Password length", default=24)
        sym    = _confirm("Include symbols?", default=True)
        amb    = _confirm("Exclude ambiguous chars (0,O,I,l)?", default=True)

        if _RICH_AVAILABLE:
            table = Table(title="Generated Passwords", border_style="cyan")
            table.add_column("#", style="dim")
            table.add_column("Password", style="bold green")
            table.add_column("Entropy bits", style="cyan")
            import math
            pool_size = 0
            if True:  pool_size += 26  # upper
            if True:  pool_size += 26  # lower
            if True:  pool_size += 10  # digits
            if sym:   pool_size += 22  # symbols
            if amb:   pool_size -= 6
            entropy = length * math.log2(max(pool_size, 1))
            for i in range(count):
                pw = generate_password(length, symbols=sym, exclude_ambiguous=amb)
                table.add_row(str(i + 1), pw, f"{entropy:.1f}")
            _console.print(table)
        else:
            for i in range(count):
                print(generate_password(length, symbols=sym, exclude_ambiguous=amb))

    def menu_token_generator(self) -> None:
        """Generate cryptographically secure random tokens."""
        nbytes = _int_prompt("Token bytes", default=TOKEN_BYTES)
        count  = _int_prompt("How many?", default=3)
        fmt    = _prompt("Format [hex/b64/b64url]", default="hex").lower()

        for i in range(count):
            raw = os.urandom(nbytes)
            if fmt == "b64":
                token = b64_encode(raw)
            elif "url" in fmt:
                token = b64_encode(raw, url_safe=True)
            else:
                token = raw.hex()
            _print(f"[green]{i+1}. {token}[/green]")

    def menu_manifest_create(self) -> None:
        """Create an integrity manifest for a directory."""
        directory = _prompt("Directory to scan")
        algo = self._choose_algo("Hash algorithm")
        recursive = _confirm("Recursive?", default=True)
        try:
            manifest = create_manifest(
                directory, algorithm=algo, recursive=recursive
            )
            total = len(manifest.entries)
            _print(f"[green]✓ Manifest created: {total} file(s) indexed.[/green]")
        except Exception as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_manifest_verify(self) -> None:
        """Verify a directory against its integrity manifest."""
        directory = _prompt("Directory to verify")
        try:
            ok, failed, missing = verify_manifest(directory)
            if _RICH_AVAILABLE:
                table = Table(title="Manifest Verification", border_style="cyan")
                table.add_column("Status")
                table.add_column("Count", justify="right")
                table.add_row("[green]✓ OK[/green]",       str(len(ok)))
                table.add_row("[red]✗ FAILED[/red]",       str(len(failed)))
                table.add_row("[yellow]? MISSING[/yellow]", str(len(missing)))
                _console.print(table)
                if failed:
                    _console.print("[red]Failed files:[/red]")
                    for f in failed:
                        _console.print(f"  [red]• {f}[/red]")
                if missing:
                    _console.print("[yellow]Missing files:[/yellow]")
                    for m in missing:
                        _console.print(f"  [yellow]• {m}[/yellow]")
            else:
                print(f"OK: {len(ok)}  FAILED: {len(failed)}  MISSING: {len(missing)}")
        except FileNotFoundError as e:
            _print(f"[red]✗ {e}[/red]")

    def menu_encode_decode(self) -> None:
        """Base64 / Hex encode & decode helpers."""
        direction = _prompt("Action [encode/decode]", default="encode").lower()
        fmt       = _prompt("Format [hex/b64/b64url]", default="b64").lower()
        src       = _prompt("Input (text or file path)")

        path = Path(src)
        if path.is_file():
            data_bytes = path.read_bytes()
        else:
            data_bytes = src.encode()

        if direction == "encode":
            if fmt == "hex":
                result = hex_encode(data_bytes)
            elif "url" in fmt:
                result = b64_encode(data_bytes, url_safe=True)
            else:
                result = b64_encode(data_bytes)
            _print(f"[green]{result}[/green]")
        else:
            try:
                if fmt == "hex":
                    decoded = hex_decode(data_bytes.decode())
                elif "url" in fmt:
                    decoded = b64_decode(data_bytes.decode(), url_safe=True)
                else:
                    decoded = b64_decode(data_bytes.decode())
                try:
                    _print(f"[green]{decoded.decode()}[/green]")
                except UnicodeDecodeError:
                    _print(f"[green](binary) hex: {decoded.hex()}[/green]")
            except Exception as e:
                _print(f"[red]✗ Decode error: {e}[/red]")

    # ── main entry point ──────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Interactive menu loop.
        Called by core.terminal router.
        """
        MENU: list[tuple[str, str, Callable]] = [
            ("1",  "Hash file (single algorithm)",        self.menu_hash_file),
            ("2",  "Hash file (all algorithms)",          self.menu_hash_multi),
            ("3",  "Verify file hash",                    self.menu_verify_hash),
            ("4",  "Encrypt file",                        self.menu_encrypt_file),
            ("5",  "Decrypt file",                        self.menu_decrypt_file),
            ("6",  "RSA key pair generation",             self.menu_rsa_keygen),
            ("7",  "RSA sign / verify file",              self.menu_rsa_sign_verify),
            ("8",  "HMAC sign / verify",                  self.menu_hmac),
            ("9",  "Generate secure passwords",           self.menu_password_generator),
            ("10", "Generate secure tokens",              self.menu_token_generator),
            ("11", "Create integrity manifest",           self.menu_manifest_create),
            ("12", "Verify integrity manifest",           self.menu_manifest_verify),
            ("13", "Encode / Decode (Base64 · Hex)",      self.menu_encode_decode),
            ("0",  "← Back to main menu",                 None),
        ]

        while True:
            if _RICH_AVAILABLE:
                table = Table(
                    title       = "🔐 Crypto Tools",
                    border_style = "cyan",
                    show_header  = True,
                    header_style = "bold cyan",
                )
                table.add_column("No.",  style="bold yellow", width=4)
                table.add_column("Feature", style="white")
                for key, label, _ in MENU:
                    style = "dim" if key == "0" else ""
                    table.add_row(key, label, style=style)
                _console.print(table)
            else:
                print("\n=== Crypto Tools ===")
                for key, label, _ in MENU:
                    print(f"  {key}. {label}")

            choice = _prompt("Select").strip()

            if choice == "0":
                break

            handler = next((fn for k, _, fn in MENU if k == choice and fn), None)
            if handler:
                try:
                    handler()
                except KeyboardInterrupt:
                    _print("\n[yellow]Cancelled.[/yellow]")
            else:
                _print("[red]Invalid option.[/red]")


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level entry point (standalone execution)
# ─────────────────────────────────────────────────────────────────────────────

def run() -> None:
    """Called by core.terminal as: modules.crypto.run()"""
    CryptoModule().run()


if __name__ == "__main__":
    run()