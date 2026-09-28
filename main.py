# bot.py
import os
import io
import json
import base64
import hashlib
import secrets
import tempfile
from pathlib import Path
from threading import Lock

import telebot
from telebot import types
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BOT_TOKEN = os.environ["BOT_TOKEN"]
MASTER_KEY_B64 = os.environ["MASTER_KEY"]

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing")

try:
    MASTER_KEY = base64.urlsafe_b64decode(MASTER_KEY_B64.encode())
except Exception as exc:
    raise RuntimeError("MASTER_KEY is not valid base64") from exc

if len(MASTER_KEY) != 32:
    raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None)

MAGIC = b"ANOUAR-ENC-V1\0"
VERSION = 1

# One-shot /normaal state.
# user_id -> True
normal_mode = {}
state_lock = Lock()

EXTENSIONS = {
    ".py": "Python",
    ".pyw": "Python",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".c": "C",
    ".h": "C/C++",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rs": "Rust",
    ".go": "Go",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".php": "PHP",
    ".rb": "Ruby",
    ".pl": "Perl",
    ".pm": "Perl",
    ".lua": "Lua",
    ".dart": "Dart",
    ".r": "R",
    ".R": "R",
    ".jl": "Julia",
    ".hs": "Haskell",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".clj": "Clojure",
    ".fs": "F#",
    ".fsx": "F#",
    ".vb": "Visual Basic",
    ".f": "Fortran",
    ".f90": "Fortran",
    ".f95": "Fortran",
    ".pas": "Pascal",
    ".ada": "Ada",
    ".asm": "Assembly",
    ".s": "Assembly",
    ".sh": "Shell",
    ".bash": "Bash",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".xml": "XML",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
}

MIME_PROFILES = {
    "application/pdf": "PDF",
    "application/json": "JSON",
    "application/zip": "ZIP",
    "application/gzip": "GZIP",
    "application/x-7z-compressed": "7-Zip",
    "application/octet-stream": "Binary",
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/webp": "WEBP",
    "image/gif": "GIF",
    "audio/mpeg": "MP3",
    "audio/wav": "WAV",
    "video/mp4": "MP4",
    "video/x-matroska": "MKV",
}


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def detect_profile(filename: str, mime_type: str | None) -> str:
    suffix = Path(filename).suffix
    if suffix in EXTENSIONS:
        return EXTENSIONS[suffix]

    if mime_type and mime_type in MIME_PROFILES:
        return MIME_PROFILES[mime_type]

    return "Binary"


def safe_filename(name: str) -> str:
    name = Path(name).name
    if not name:
        name = "file.bin"

    # Avoid Telegram path tricks and control characters.
    cleaned = "".join(
        ch for ch in name
        if ch.isprintable() and ch not in "/\\\0"
    ).strip()

    return cleaned or "file.bin"


def build_envelope(filename: str, mime_type: str | None, plaintext: bytes) -> bytes:
    profile = detect_profile(filename, mime_type)

    # Random per-file data-encryption key.
    data_key = AESGCM.generate_key(bit_length=256)

    # Random nonce for the file encryption.
    data_nonce = secrets.token_bytes(12)

    # Metadata is authenticated as AAD.
    metadata = {
        "version": VERSION,
        "profile": profile,
        "filename": filename,
        "mime_type": mime_type or "application/octet-stream",
        "size": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
    }

    aad = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    ciphertext = AESGCM(data_key).encrypt(
        data_nonce,
        plaintext,
        aad,
    )

    # Wrap the random data key with the server master key.
    wrap_nonce = secrets.token_bytes(12)
    wrapped_key = AESGCM(MASTER_KEY).encrypt(
        wrap_nonce,
        data_key,
        MAGIC,
    )

    envelope = {
        "magic": MAGIC.decode("latin1"),
        "metadata": metadata,
        "data_nonce": b64e(data_nonce),
        "wrap_nonce": b64e(wrap_nonce),
        "wrapped_key": b64e(wrapped_key),
        "ciphertext": b64e(ciphertext),
    }

    raw = json.dumps(
        envelope,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return MAGIC + raw


def open_envelope(blob: bytes) -> tuple[bytes, dict]:
    if not blob.startswith(MAGIC):
        raise ValueError("Not an ANOUAR encrypted file")

    try:
        envelope = json.loads(blob[len(MAGIC):].decode("utf-8"))

        if envelope.get("magic") != MAGIC.decode("latin1"):
            raise ValueError("Invalid encryption marker")

        metadata = envelope["metadata"]

        if metadata.get("version") != VERSION:
            raise ValueError("Unsupported encryption version")

        aad = json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        wrap_nonce = b64d(envelope["wrap_nonce"])
        wrapped_key = b64d(envelope["wrapped_key"])

        data_key = AESGCM(MASTER_KEY).decrypt(
            wrap_nonce,
            wrapped_key,
            MAGIC,
        )

        data_nonce = b64d(envelope["data_nonce"])
        ciphertext = b64d(envelope["ciphertext"])

        plaintext = AESGCM(data_key).decrypt(
            data_nonce,
            ciphertext,
            aad,
        )

        expected_hash = metadata["sha256"]
        actual_hash = hashlib.sha256(plaintext).hexdigest()

        if not secrets.compare_digest(expected_hash, actual_hash):
            raise ValueError("Integrity verification failed")

        if len(plaintext) != int(metadata["size"]):
            raise ValueError("Recovered size does not match metadata")

        return plaintext, metadata

    except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid or corrupted encrypted file: {exc}") from exc


def encrypted_name(original: str) -> str:
    return f"{safe_filename(original)}.anouar.enc"


def normal_name(original: str) -> str:
    return safe_filename(original)


@bot.message_handler(commands=["start"])
def start(message: types.Message):
    bot.reply_to(
        message,
        "ANOUAR Encryption Bot\n\n"
        "/normaal = decrypt the next file once\n"
        "/encrypt = return to encryption mode immediately\n\n"
        "Send a file to encrypt it."
    )


@bot.message_handler(commands=["encrypt"])
def encrypt_mode(message: types.Message):
    user_id = message.from_user.id

    with state_lock:
        normal_mode.pop(user_id, None)

    bot.reply_to(
        message,
        "Recovery encryption mode restored. Send the file."
    )


@bot.message_handler(commands=["normaal"])
def normal_once(message: types.Message):
    user_id = message.from_user.id

    with state_lock:
        normal_mode[user_id] = True

    bot.reply_to(
        message,
        "Recovery mode armed for one file. Send the encrypted file."
    )


def get_document_info(message: types.Message):
    if not message.document:
        return None, None

    return (
        message.document.file_name or "file.bin",
        message.document.mime_type,
    )


@bot.message_handler(content_types=["document"])
def handle_document(message: types.Message):
    user_id = message.from_user.id
    filename, mime_type = get_document_info(message)

    try:
        file_info = bot.get_file(message.document.file_id)
        blob = bot.download_file(file_info.file_path)

        with state_lock:
            decrypt_once = normal_mode.pop(user_id, False)

        if decrypt_once:
            plaintext, metadata = open_envelope(blob)

            original_name = metadata["filename"]
            recovered_name = normal_name(original_name)

            document = io.BytesIO(plaintext)
            document.name = recovered_name

            bot.send_document(
                message.chat.id,
                document,
                caption=(
                    "Recovery complete.\n"
                    f"Language/profile: {metadata['profile']}\n"
                    f"Integrity: VERIFIED\n"
                    f"SHA-256: {metadata['sha256']}"
                ),
            )
            return

        encrypted = build_envelope(
            filename=safe_filename(filename),
            mime_type=mime_type,
            plaintext=blob,
        )

        output = io.BytesIO(encrypted)
        output.name = encrypted_name(filename)

        profile = detect_profile(filename, mime_type)

        bot.send_document(
            message.chat.id,
            output,
            caption=(
                "Encryption complete.\n"
                f"Detected profile: {profile}\n"
                f"Original bytes: {len(blob)}\n"
                f"Cipher: AES-256-GCM\n"
                "Integrity: authenticated"
            ),
        )

    except ValueError as exc:
        bot.reply_to(message, f"Recovery failed: {exc}")
    except Exception as exc:
        bot.reply_to(message, f"Recovery pipeline error: {type(exc).__name__}")


@bot.message_handler(
    content_types=["photo", "video", "audio", "voice", "animation", "document"]
)
def fallback_handler(message: types.Message):
    # Documents are handled by handle_document.
    if message.document:
        return

    bot.reply_to(
        message,
        "Send the file as a Telegram document so the original bytes and filename are preserved."
    )


if __name__ == "__main__":
    print("ANOUAR Encryption Bot running.")
    bot.infinity_polling(
        skip_pending=True,
        allowed_updates=["message"],
    )
