import os
import re
import html
import hashlib
from pathlib import Path

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes user-provided filename: strips directory traversal, control characters,
    and returns a clean filename while preserving extension.
    """
    cleaned = os.path.basename(filename.strip().replace("\\", "/"))
    # Remove control characters, null bytes, and path traversal sequences
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', cleaned)
    cleaned = re.sub(r'\.\.+', '.', cleaned)
    # Default to unnamed if completely empty or just dot
    if not cleaned or cleaned == '.':
        cleaned = "unnamed_upload.bin"
    return cleaned

def calculate_hashes(file_path: Path) -> dict[str, str]:
    """
    Calculates SHA-256, SHA-1, and MD5 in a single streaming pass (64 KB chunks).
    Returns hex digests for all three cryptographic hashes.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }

def strip_execute_permissions(file_path: Path) -> None:
    """
    Strips execute permissions from the file to ensure uploaded binaries
    cannot be inadvertently executed.
    """
    try:
        if os.name == 'posix':
            # 0600 = Read/Write owner only, no execute
            os.chmod(file_path, 0o600)
        else:
            # On Windows, ensure standard read/write without special execution
            os.chmod(file_path, 0o666)
    except Exception:
        pass

def sanitize_for_ui(text: str) -> str:
    """
    Sanitizes any string extracted from untrusted file content (EXIF, log lines)
    before presentation in UI or reports to prevent XSS / raw HTML injection.
    """
    if not text:
        return ""
    # Strip null bytes and non-printable control characters
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Escape HTML special characters
    return html.escape(text)
