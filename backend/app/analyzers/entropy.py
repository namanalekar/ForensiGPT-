import math
from pathlib import Path
from typing import Any
from PIL import Image
import numpy as np
from app.models.pydantic_models import EvidenceItem
from app.core.config import settings

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

class EntropyForensicsAnalyzer:
    """
    Entropy Forensics Analyzer.
    Calculates overall and per-block Shannon entropy, identifies dense encrypted/compressed
    injections, and produces a visual 2D entropy heatmap artifact.
    """

    @classmethod
    def analyze(cls, file_path: Path, file_id: str, mime_type: str) -> dict[str, Any]:
        evidence_items: list[EvidenceItem] = []
        raw_bytes = file_path.read_bytes()
        file_size = len(raw_bytes)
        overall_entropy = calculate_shannon_entropy(raw_bytes)

        # Compute block entropy (256-byte chunks)
        block_size = 256
        num_blocks = math.ceil(file_size / block_size)
        block_entropies: list[float] = []

        for i in range(num_blocks):
            chunk = raw_bytes[i * block_size : (i + 1) * block_size]
            block_entropies.append(calculate_shannon_entropy(chunk))

        # Check for high-entropy anomalies (> 7.85 bits/byte over consecutive blocks)
        high_entropy_blocks = [i for i, h in enumerate(block_entropies) if h >= 7.85]
        has_dense_payload = len(high_entropy_blocks) >= 4  # At least 1 KB of near-maximal randomness

        if has_dense_payload:
            first_idx = high_entropy_blocks[0]
            offset = first_idx * block_size
            desc = (
                f"High Entropy Block Anomaly: Detected continuous cluster of {len(high_entropy_blocks)} blocks "
                f"with near-maximal Shannon entropy (>= 7.85 bits/byte) starting around byte offset {offset:,} ({hex(offset)}). "
                "This is characteristic of encrypted shellcode or compressed archive embeddings."
            )
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-ENTROPY-001",
                severity="Medium" if "jpeg" in mime_type else "High",
                category="Entropy Anomaly",
                title="Dense High-Entropy Ingestion Detected",
                description=desc,
                raw_data={"overall_entropy": overall_entropy, "anomalous_blocks": len(high_entropy_blocks), "start_offset": offset}
            ))

        # Generate 2D Heatmap Image
        heatmap_rel_path = cls.generate_entropy_heatmap(block_entropies, file_id)

        return {
            "overall_entropy": overall_entropy,
            "block_count": len(block_entropies),
            "max_block_entropy": round(max(block_entropies), 4) if block_entropies else 0.0,
            "min_block_entropy": round(min(block_entropies), 4) if block_entropies else 0.0,
            "high_entropy_detected": has_dense_payload,
            "heatmap_artifact_path": heatmap_rel_path,
            "evidence_items": [e.model_dump() for e in evidence_items]
        }

    @classmethod
    def generate_entropy_heatmap(cls, block_entropies: list[float], file_id: str) -> str:
        """
        Generates a 2D raster heatmap representing file entropy from offset 0 to EOF.
        Maps 0.0 -> dark blue, 4.0 -> green, 7.0 -> yellow, 8.0 -> bright red.
        """
        settings.VISUALS_DIR.mkdir(parents=True, exist_ok=True)
        dest_filename = f"{file_id}_entropy_heatmap.png"
        dest_path = settings.VISUALS_DIR / dest_filename

        if not block_entropies:
            block_entropies = [0.0]

        # Reshape into a 2D grid (e.g. width 64 or 128)
        width = 64
        height = math.ceil(len(block_entropies) / width)
        padded = block_entropies + [0.0] * (width * height - len(block_entropies))
        grid = np.array(padded, dtype=np.float32).reshape(height, width)

        # Normalize 0.0 - 8.0 to 0 - 255
        norm = np.clip(grid / 8.0, 0.0, 1.0)

        # False color palette:
        # Red channel increases as entropy increases
        r = np.uint8(np.clip((norm - 0.5) * 2.0, 0.0, 1.0) * 255)
        # Green channel peaks in mid entropy
        g = np.uint8((1.0 - np.abs(norm - 0.5) * 2.0) * 255)
        # Blue channel dominant at low entropy
        b = np.uint8(np.clip((0.5 - norm) * 2.0, 0.0, 1.0) * 255)

        rgb_matrix = np.stack([r, g, b], axis=-1)
        # Resize to at least 256x256 with nearest neighbor for sharp block visualization
        img = Image.fromarray(rgb_matrix, "RGB")
        target_w = max(width * 4, 256)
        target_h = max(height * 4, 128)
        img_resized = img.resize((target_w, target_h), Image.Resampling.NEAREST)
        img_resized.save(dest_path, "PNG")

        return f"/api/cases/visuals/{dest_filename}"
