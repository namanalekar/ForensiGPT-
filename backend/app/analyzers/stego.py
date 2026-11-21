import struct
import math
import re
from pathlib import Path
from typing import Any
from PIL import Image
import numpy as np
from app.models.pydantic_models import EvidenceItem

CARVE_SIGNATURES = [
    (b"PK\x03\x04", "ZIP Archive", "EVID-IMG-CARVE-001"),
    (b"Rar!\x1a\x07", "RAR Archive", "EVID-IMG-CARVE-002"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "EVID-IMG-CARVE-003"),
    (b"%PDF-", "Embedded PDF Document", "EVID-IMG-CARVE-004"),
    (b"\x7fELF", "Embedded Linux ELF Executable", "EVID-IMG-CARVE-005"),
    (b"MZ\x90\x00", "Embedded Windows PE Binary", "EVID-IMG-CARVE-006"),
]

BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{64,}={0,2}')

def calculate_chi2_1df(observed_0: int, observed_1: int) -> tuple[float, float]:
    """
    Computes Chi-Square statistic and exact p-value for 1 degree of freedom (bit 0 vs bit 1).
    Avoids heavy external OpenBLAS runtime threads.
    """
    total = observed_0 + observed_1
    if total == 0:
        return 0.0, 1.0
    expected = total / 2.0
    chi2 = ((observed_0 - expected) ** 2) / expected + ((observed_1 - expected) ** 2) / expected
    # Exact survival function (p-value) for Chi-Square distribution with 1 DF
    p_val = math.erfc(math.sqrt(chi2 / 2.0)) if chi2 >= 0 else 1.0
    return float(chi2), float(p_val)

class StegoForensicsAnalyzer:
    """
    Steganography & Hidden Data Analyzer.
    Deterministic scan for appended trailing payloads, carved file signatures,
    LSB statistical anomalies (Chi-Square & RS approximation), and anomalous PNG chunks.
    Note: All findings are forensic indicators, not definitive proof of concealed data.
    """

    @classmethod
    def analyze(cls, file_path: Path, mime_type: str) -> dict[str, Any]:
        evidence_items: list[EvidenceItem] = []
        indicators: list[str] = []
        raw_bytes = file_path.read_bytes()
        file_size = len(raw_bytes)

        # 1. Carving scan for embedded archives and executables
        carved_hits = []
        for sig, label, evid_id in CARVE_SIGNATURES:
            start_offset = 64
            while True:
                idx = raw_bytes.find(sig, start_offset)
                if idx == -1:
                    break
                carved_hits.append({"signature": label, "offset": idx, "hex_offset": hex(idx)})
                desc = (
                    f"Signature Carving: Detected embedded {label} signature at byte offset {idx:,} ({hex(idx)}). "
                    "This strongly indicates file concatenation or polyglot payload embedding."
                )
                indicators.append(desc)
                evidence_items.append(EvidenceItem(
                    evidence_id=evid_id,
                    severity="High",
                    category="Steganography / Embedded Payload",
                    title=f"Embedded {label} Signature Detected",
                    description=desc,
                    raw_data={"signature": label, "offset": idx, "hex_offset": hex(idx)}
                ))
                start_offset = idx + len(sig)

        # 2. Check for Appended Data past EOF
        eof_detected = False
        trailing_len = 0
        if mime_type == "image/jpeg" or raw_bytes.startswith(b"\xFF\xD8\xFF"):
            eoi_idx = raw_bytes.rfind(b"\xFF\xD9")
            if eoi_idx != -1 and eoi_idx + 2 < file_size:
                trailing_len = file_size - (eoi_idx + 2)
                eof_detected = True
        elif mime_type == "image/png" or raw_bytes.startswith(b"\x89PNG"):
            iend_idx = raw_bytes.rfind(b"IEND")
            if iend_idx != -1 and iend_idx + 8 < file_size:
                trailing_len = file_size - (iend_idx + 8)
                eof_detected = True

        if eof_detected and trailing_len > 0:
            desc = (
                f"Trailing Data Indicator: {trailing_len:,} bytes of unreferenced data appended beyond the official "
                "End-Of-File marker. Often used in basic steganography (overlay injection)."
            )
            indicators.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-STEGO-001",
                severity="High",
                category="Steganography / Appended Overlay",
                title="Appended Data Past EOF Marker Detected",
                description=desc,
                raw_data={"trailing_bytes": trailing_len}
            ))

        # 3. Suspicious PNG Chunks
        png_anomalies = []
        if mime_type == "image/png" or raw_bytes.startswith(b"\x89PNG"):
            offset = 8  # Skip PNG signature
            while offset + 8 <= file_size:
                chunk_len, chunk_type = struct.unpack(">I4s", raw_bytes[offset:offset+8])
                type_str = chunk_type.decode("latin1", errors="replace")

                # Oversized text chunks
                if type_str in {"tEXt", "zTXt", "iTXt"} and chunk_len > 65536:
                    desc = f"Oversized PNG {type_str} metadata chunk: {chunk_len:,} bytes (exceeds typical threshold of 64 KB)."
                    png_anomalies.append(desc)
                    evidence_items.append(EvidenceItem(
                        evidence_id="EVID-IMG-PNG-001",
                        severity="Medium",
                        category="Steganography / PNG Anomaly",
                        title=f"Oversized PNG {type_str} Chunk",
                        description=desc,
                        raw_data={"chunk_type": type_str, "size_bytes": chunk_len}
                    ))

                # Advance offset: 4 len + 4 type + data + 4 crc
                offset += 12 + chunk_len

        # 4. Base64 / Encoded Blob Scan
        base64_matches = BASE64_PATTERN.findall(raw_bytes.decode("latin1", errors="replace"))
        if base64_matches:
            longest_match = max(base64_matches, key=len)
            if len(longest_match) >= 128:
                desc = (
                    f"Encoded Blob: Found dense base64-like string sequence of length {len(longest_match)} "
                    "embedded in the file bytes."
                )
                indicators.append(desc)
                evidence_items.append(EvidenceItem(
                    evidence_id="EVID-IMG-STEGO-002",
                    severity="Medium",
                    category="Obfuscated Content",
                    title="High-Density Encoded String Detected",
                    description=desc,
                    raw_data={"sample_prefix": longest_match[:32] + "...", "length": len(longest_match)}
                ))

        # 5. LSB Statistical Chi-Square Test & RS Analysis Approximation
        lsb_results = cls.perform_lsb_statistical_analysis(file_path)
        if lsb_results.get("anomaly_detected"):
            desc = (
                f"LSB Statistical Anomaly: Chi-Square p-value ({lsb_results['p_value']:.4e}) deviates significantly "
                f"from natural distributions across bitplanes (Chi2: {lsb_results['chi2_stat']:.1f}). "
                "This is a probabilistic indicator of potential Least Significant Bit steganographic manipulation."
            )
            indicators.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-STEGO-003",
                severity="Medium",
                category="Steganography / LSB Anomaly",
                title="LSB Statistical Distribution Anomaly",
                description=desc,
                raw_data=lsb_results
            ))

        return {
            "carved_signatures": carved_hits,
            "has_trailing_data": eof_detected,
            "trailing_bytes_count": trailing_len,
            "lsb_analysis": lsb_results,
            "png_anomalies": png_anomalies,
            "indicators": indicators,
            "evidence_items": [e.model_dump() for e in evidence_items]
        }

    @classmethod
    def perform_lsb_statistical_analysis(cls, file_path: Path) -> dict[str, Any]:
        """
        Calculates Chi-Square distribution on the LSBs of pixel planes.
        Natural uncompressed images display natural bit variances; sequential or pseudo-random
        steganographic injection produces an unnaturally uniform 50/50 bit distribution or pair of values.
        """
        try:
            with Image.open(file_path) as img:
                rgb_img = img.convert("RGB")
                arr = np.array(rgb_img, dtype=np.uint8)

            # Flatten pixel channels
            pixels = arr.reshape(-1, 3)
            # Sample up to 100,000 pixels for fast deterministic evaluation
            if len(pixels) > 100000:
                sample_step = len(pixels) // 100000
                pixels = pixels[::sample_step]

            # Extract LSBs for Red, Green, Blue
            lsb_bits = pixels & 1
            total = len(pixels)

            chi2_list = []
            p_list = []
            ratios = {}
            channels = ["r", "g", "b"]

            for c_idx, ch in enumerate(channels):
                c0 = int(np.sum(lsb_bits[:, c_idx] == 0))
                c1 = int(np.sum(lsb_bits[:, c_idx] == 1))
                chi2_val, p_val = calculate_chi2_1df(c0, c1)
                chi2_list.append(chi2_val)
                p_list.append(p_val)
                ratios[ch] = round(c1 / total, 4) if total > 0 else 0.5

            mean_chi2 = float(np.mean(chi2_list))
            mean_p = float(np.mean(p_list))

            # Flag if bit ratios are artificially equalized (49.9% to 50.1%) on all 3 channels simultaneously
            is_suspiciously_uniform = (0.499 <= ratios["r"] <= 0.501) and (0.499 <= ratios["g"] <= 0.501) and (0.499 <= ratios["b"] <= 0.501)
            is_stat_anomaly = mean_p < 0.001 or is_suspiciously_uniform

            return {
                "chi2_stat": round(mean_chi2, 2),
                "p_value": mean_p,
                "lsb_one_ratios": ratios,
                "anomaly_detected": is_stat_anomaly,
                "caveat": "LSB statistics are probabilistic heuristics, not conclusive proof of hidden payloads."
            }
        except Exception:
            return {
                "chi2_stat": 0.0,
                "p_value": 1.0,
                "anomaly_detected": False,
                "error": "Unable to calculate pixel bitplanes."
            }
