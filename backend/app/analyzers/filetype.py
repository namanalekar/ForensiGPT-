import os
import re
from pathlib import Path
from typing import Any
import puremagic
from app.models.pydantic_models import (
    UnverifiedModalData,
    VerdictType,
    RiskFactor
)

# Known Magic Byte Signatures
MAGIC_SIGNATURES: list[tuple[bytes, int, str, str, str]] = [
    # (Magic Bytes, Offset, Extension, MIME, Category)
    (b"\xFF\xD8\xFF", 0, ".jpg", "image/jpeg", "image"),
    (b"\x89PNG\r\n\x1a\n", 0, ".png", "image/png", "image"),
    (b"GIF87a", 0, ".gif", "image/gif", "image"),
    (b"GIF89a", 0, ".gif", "image/gif", "image"),
    (b"BM", 0, ".bmp", "image/bmp", "image"),
    (b"RIFF", 0, ".webp", "image/webp", "image"),  # Also check bytes 8-12 == b"WEBP"
    (b"II*\x00", 0, ".tiff", "image/tiff", "image"),
    (b"MM\x00*", 0, ".tiff", "image/tiff", "image"),
    (b"%PDF-", 0, ".pdf", "application/pdf", "pdf"),
    (b"PK\x03\x04", 0, ".zip", "application/zip", "archive"),
    (b"Rar!\x1a\x07\x00", 0, ".rar", "application/x-rar", "archive"),
    (b"Rar!\x1a\x07\x01\x00", 0, ".rar", "application/x-rar", "archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, ".7z", "application/x-7z-compressed", "archive"),
    (b"\x1f\x8b", 0, ".gz", "application/gzip", "archive"),
    (b"MZ", 0, ".exe", "application/x-dosexec", "executable"),
    (b"\x7fELF", 0, ".elf", "application/x-executable", "executable"),
    (b"\xfe\xed\xfa\xce", 0, ".macho", "application/x-mach-binary", "executable"),
    (b"\xfe\xed\xfa\xcf", 0, ".macho", "application/x-mach-binary", "executable"),
    (b"\xce\xfa\xed\xfe", 0, ".macho", "application/x-mach-binary", "executable"),
    (b"\xcf\xfa\xed\xfe", 0, ".macho", "application/x-mach-binary", "executable"),
    (b"\xca\xfe\xba\xbe", 0, ".macho", "application/x-mach-binary", "executable"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, ".lnk", "application/x-ms-shortcut", "shortcut"),
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".elf", ".com", ".scr", ".bat",
    ".cmd", ".ps1", ".vbs", ".js", ".sh", ".bash", ".csh", ".py", ".bin"
}

SCRIPT_SHEBANGS = [
    b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env", b"#!/bin/zsh",
    b"#!/usr/bin/perl", b"#!/usr/bin/python"
]

SAFE_IMAGE_CATEGORIES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp", "image/tiff"}

class FileTypeInspector:
    """
    Forensic file type inspector that detects true file formats via magic bytes,
    flags extension/MIME mismatches, detects hidden trailing data beyond EOF markers,
    and calculates unverified/suspicious status.
    """

    @classmethod
    def inspect(cls, file_path: Path, original_filename: str) -> dict[str, Any]:
        file_size = file_path.stat().st_size
        ext = Path(original_filename).suffix.lower()

        # Read first 8 KB for magic analysis
        with open(file_path, "rb") as f:
            header_sample = f.read(8192)

        true_ext = None
        true_mime = None
        category = "misc"

        # Check WebP specifically (RIFF....WEBP)
        if header_sample.startswith(b"RIFF") and len(header_sample) >= 12 and header_sample[8:12] == b"WEBP":
            true_ext = ".webp"
            true_mime = "image/webp"
            category = "image"
        else:
            # Check primary magic signatures
            for sig, offset, sig_ext, sig_mime, sig_cat in MAGIC_SIGNATURES:
                if len(header_sample) >= offset + len(sig) and header_sample[offset:offset+len(sig)] == sig:
                    true_ext = sig_ext
                    true_mime = sig_mime
                    category = sig_cat
                    break

        # Check for scripts (shebang)
        if not true_ext:
            for shebang in SCRIPT_SHEBANGS:
                if header_sample.startswith(shebang):
                    true_ext = ".sh"
                    true_mime = "application/x-sh"
                    category = "script"
                    break

        # Check for log files / plain text
        if not true_ext:
            is_text = False
            try:
                decoded = header_sample[:1024].decode("utf-8", errors="strict")
                # Look for syslog / auth.log / web server patterns
                log_patterns = [
                    r'^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}',  # Syslog timestamp: Oct 14 09:21:00
                    r'^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',  # ISO timestamp: 2026-11-21 12:00:00
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*"(GET|POST|HEAD|PUT|DELETE)', # Web log
                    r'sshd\[\d+\]:', # Auth log SSH
                    r'sudo:\s+',     # Sudo log
                ]
                for pattern in log_patterns:
                    if re.search(pattern, decoded, re.MULTILINE):
                        true_ext = ".log"
                        true_mime = "text/x-log"
                        category = "log"
                        is_text = True
                        break
                if not is_text and ext in {".log", ".txt", ".csv", ".syslog"}:
                    true_ext = ext
                    true_mime = "text/plain"
                    category = "log"
            except UnicodeDecodeError:
                pass

        # Fallback to puremagic if not identified
        if not true_ext:
            try:
                guesses = puremagic.magic_file(str(file_path))
                if guesses:
                    best = guesses[0]
                    true_ext = best.extension if best.extension.startswith(".") else f".{best.extension}"
                    true_mime = best.mime_type
                    if "image" in true_mime:
                        category = "image"
                    elif "pdf" in true_mime:
                        category = "pdf"
                    elif "zip" in true_mime or "archive" in true_mime or "compressed" in true_mime:
                        category = "archive"
                    elif "executable" in true_mime or "dosexec" in true_mime:
                        category = "executable"
                    else:
                        category = "misc"
            except Exception:
                pass

        # Default fallback for unknown files
        if not true_ext:
            true_ext = ext if ext else ".bin"
            true_mime = "application/octet-stream"
            category = "misc"

        # Check extension match
        extension_match = True
        normalized_ext = ext.replace(".jpeg", ".jpg")
        normalized_true = true_ext.replace(".jpeg", ".jpg")
        if normalized_ext != normalized_true:
            # Special case: .txt and .log or .csv are interchangeable text formats
            if not ({normalized_ext, normalized_true}.issubset({".txt", ".log", ".csv", ".syslog"})):
                extension_match = False

        # Check for trailing data after EOF
        has_trailing, trailing_count, eof_reason = cls.check_trailing_data(file_path, true_mime)

        # Evaluate unverified popup trigger and risk score
        unverified_data, verdict, risk_score, risk_breakdown, flags = cls.evaluate_verdict_and_popup(
            file_size=file_size,
            original_filename=original_filename,
            claimed_ext=ext,
            true_ext=true_ext,
            true_mime=true_mime,
            category=category,
            extension_match=extension_match,
            has_trailing=has_trailing,
            trailing_count=trailing_count,
            eof_reason=eof_reason
        )

        return {
            "original_filename": original_filename,
            "file_size": file_size,
            "claimed_extension": ext,
            "true_file_type": true_ext,
            "mime_type": true_mime,
            "detected_category": category,
            "extension_match": extension_match,
            "has_trailing_data": has_trailing,
            "trailing_bytes_count": trailing_count,
            "eof_reason": eof_reason,
            "unverified_flags": flags,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_breakdown": risk_breakdown,
            "unverified_popup": unverified_data
        }

    @classmethod
    def check_trailing_data(cls, file_path: Path, mime_type: str) -> tuple[bool, int, str]:
        """
        Inspects if there are appended/hidden bytes past known EOF markers:
        - JPEG: EOI marker is 0xFF 0xD9
        - PNG: IEND chunk signature 0x49 0x45 0x4E 0x44 + 4 bytes CRC
        - PDF: %%EOF marker
        """
        file_size = file_path.stat().st_size
        if file_size < 16:
            return False, 0, ""

        with open(file_path, "rb") as f:
            data = f.read()

        # JPEG EOF Check
        if mime_type == "image/jpeg" or data.startswith(b"\xFF\xD8\xFF"):
            eoi_idx = data.rfind(b"\xFF\xD9")
            if eoi_idx != -1:
                trailing = file_size - (eoi_idx + 2)
                if trailing > 0:
                    return True, trailing, f"Detected {trailing:,} bytes appended after JPEG EOI marker (FFD9)"

        # PNG EOF Check
        if mime_type == "image/png" or data.startswith(b"\x89PNG\r\n\x1a\n"):
            # IEND marker is b"IEND\xae\x42\x60\x82" (length 8)
            iend_idx = data.rfind(b"IEND")
            if iend_idx != -1:
                # IEND is 4 bytes chunk name + 4 bytes CRC = 8 bytes total
                expected_end = iend_idx + 8
                if file_size > expected_end:
                    trailing = file_size - expected_end
                    return True, trailing, f"Detected {trailing:,} bytes appended after PNG IEND chunk"

        # PDF EOF Check
        if mime_type == "application/pdf" or data.startswith(b"%PDF-"):
            eof_idx = data.rfind(b"%%EOF")
            if eof_idx != -1:
                # After %%EOF usually 0-4 trailing whitespace/newlines are normal
                trailing = file_size - (eof_idx + 5)
                # Ignore trailing whitespace/newlines
                tail = data[eof_idx + 5:]
                if len(tail.strip()) > 0:
                    return True, len(tail), f"Detected {len(tail):,} bytes appended after PDF %%EOF marker"

        return False, 0, ""

    @classmethod
    def evaluate_verdict_and_popup(
        cls,
        file_size: int,
        original_filename: str,
        claimed_ext: str,
        true_ext: str,
        true_mime: str,
        category: str,
        extension_match: bool,
        has_trailing: bool,
        trailing_count: int,
        eof_reason: str
    ) -> tuple[UnverifiedModalData | None, VerdictType, int, list[RiskFactor], list[str]]:
        reasons: list[str] = []
        flags: list[str] = []
        risk_breakdown: list[RiskFactor] = []
        risk_score = 0

        # Condition 1: File type is not in supported/known-safe categories (misc/unknown)
        known_safe = category in {"image", "log", "pdf"}
        if not known_safe or category == "misc":
            reason = f"File format '{true_ext}' ({true_mime}) is an unverified / miscellaneous type outside standard forensic categories."
            reasons.append(reason)
            flags.append("UNVERIFIED_TYPE")
            risk_score += 15
            risk_breakdown.append(RiskFactor(
                factor="Miscellaneous / Unverified File Format",
                points=15,
                evidence_id="EVID-MISC-001",
                description=reason
            ))

        # Condition 2: Extension does not match magic bytes
        if not extension_match:
            reason = f"Claimed extension '{claimed_ext}' does not match detected magic bytes '{true_ext}' ({true_mime})."
            reasons.append(reason)
            flags.append("EXTENSION_MISMATCH")
            risk_score += 25
            risk_breakdown.append(RiskFactor(
                factor="File Extension / MIME Mismatch",
                points=25,
                evidence_id="EVID-MISC-002",
                description=reason
            ))

        # Condition 3: File is an executable, script, macro doc, shortcut (.lnk), or disk image
        if category in {"executable", "script", "shortcut"} or true_ext in EXECUTABLE_EXTENSIONS or claimed_ext in EXECUTABLE_EXTENSIONS:
            reason = f"File is an executable, script, or shortcut ({true_ext} / {category}). High risk of payload delivery."
            reasons.append(reason)
            flags.append("EXECUTABLE_OR_SCRIPT")
            risk_score += 35
            risk_breakdown.append(RiskFactor(
                factor="Executable / Script Detected",
                points=35,
                evidence_id="EVID-SEC-001",
                description=reason
            ))

        # Condition 4: Hidden/trailing data detected after end-of-file marker
        if has_trailing:
            reason = eof_reason if eof_reason else f"Hidden trailing data detected: {trailing_count:,} bytes after end-of-file marker."
            reasons.append(reason)
            flags.append("TRAILING_EOF_DATA")
            risk_score += 25
            risk_breakdown.append(RiskFactor(
                factor="Trailing Data Appended Beyond EOF Marker",
                points=25,
                evidence_id="EVID-STEGO-001",
                description=reason
            ))

        # Condition 5: Metadata missing or looks stripped/forged in a suspicious way
        # e.g. An image claiming to be camera original (like IMG_1234.JPG or DSC_0001.JPG) with tiny size
        is_camera_filename = bool(re.match(r'^(IMG_\d+|DSC_?\d+|PANO_\d+|PHOTO_\d+)', original_filename, re.IGNORECASE))
        if is_camera_filename and file_size < 5120:  # < 5 KB
            reason = "File name indicates a camera original, but file size is suspiciously truncated (< 5 KB)."
            reasons.append(reason)
            flags.append("SUSPICIOUS_METADATA_TRUNCATION")
            risk_score += 15
            risk_breakdown.append(RiskFactor(
                factor="Suspicious File Structure / Truncated Original",
                points=15,
                evidence_id="EVID-META-001",
                description=reason
            ))

        # Clamp risk score
        risk_score = min(risk_score, 100)

        # Verdict calculation
        if risk_score >= 60 or "EXECUTABLE_OR_SCRIPT" in flags:
            verdict: VerdictType = "Likely Malicious"
        elif risk_score >= 35 or "EXTENSION_MISMATCH" in flags or "TRAILING_EOF_DATA" in flags:
            verdict = "Suspicious"
        elif len(reasons) > 0 or category == "misc":
            verdict = "Unverified"
        else:
            verdict = "Verified-Clean-Looking"

        should_trigger_popup = len(reasons) > 0

        popup_data = None
        if should_trigger_popup:
            popup_data = UnverifiedModalData(
                should_trigger_popup=True,
                title="⚠ Miscellaneous / Unverified File Detected",
                warning_text=(
                    "ForensiGPT could not verify this file as safe. "
                    "It has NOT been scanned by antivirus. "
                    "Do not open or run it on your main system."
                ),
                reasons=reasons,
                claimed_type=claimed_ext if claimed_ext else "unknown",
                detected_true_type=f"{true_ext} ({true_mime})",
                verdict=verdict,
                persistent_badge="UNVERIFIED"
            )

        return popup_data, verdict, risk_score, risk_breakdown, flags
