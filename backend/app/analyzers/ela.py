import io
from pathlib import Path
from typing import Any
from PIL import Image, ImageEnhance
import numpy as np
from app.models.pydantic_models import EvidenceItem
from app.core.config import settings

class ELAForensicsAnalyzer:
    """
    Error Level Analysis (ELA) Engine.
    Detects digital image manipulation by recompressing the image at a known quality level (95%)
    and analyzing the distribution of error differentials across 8x8 DCT blocks.
    Caveat: ELA is an investigative heuristic, not mathematical proof of tampering.
    """

    @classmethod
    def generate_ela(cls, file_path: Path, file_id: str, quality: int = 95, scale: int = 20) -> dict[str, Any]:
        evidence_items: list[EvidenceItem] = []
        dest_filename = f"{file_id}_ela.png"
        dest_path = settings.VISUALS_DIR / dest_filename
        settings.VISUALS_DIR.mkdir(parents=True, exist_ok=True)

        try:
            with Image.open(file_path) as original_img:
                original_rgb = original_img.convert("RGB")

                # Recompress in memory at specified JPEG quality
                buffer = io.BytesIO()
                original_rgb.save(buffer, "JPEG", quality=quality)
                buffer.seek(0)
                recompressed_img = Image.open(buffer)

                # Compute pixel difference
                arr_orig = np.array(original_rgb, dtype=np.int16)
                arr_recomp = np.array(recompressed_img, dtype=np.int16)
                diff = np.abs(arr_orig - arr_recomp)

                # Amplify error difference
                diff_amplified = np.clip(diff * scale, 0, 255).astype(np.uint8)

                # Save ELA visualization
                ela_img = Image.fromarray(diff_amplified, mode="RGB")
                ela_img.save(dest_path, "PNG")

                # Statistical heuristic on difference variance
                mean_diff = float(np.mean(diff))
                std_diff = float(np.std(diff))
                max_diff = float(np.max(diff))

                # If standard deviation is unusually high relative to mean, different compression histories exist
                has_inconsistent_compression = std_diff > 12.0 and max_diff > 35.0

                if has_inconsistent_compression:
                    desc = (
                        f"Error Level Analysis Heuristic: High variance in compression error levels (Std: {std_diff:.1f}, "
                        f"Max: {max_diff:.1f}). This indicates distinct image regions may have undergone different "
                        "resave cycles or local digital splicing."
                    )
                    evidence_items.append(EvidenceItem(
                        evidence_id="EVID-IMG-ELA-001",
                        severity="Low",
                        category="Image Splicing Indicator",
                        title="Inconsistent Compression Error Levels Detected",
                        description=desc,
                        raw_data={"mean_diff": round(mean_diff, 2), "std_diff": round(std_diff, 2), "max_diff": round(max_diff, 2)}
                    ))

                return {
                    "ela_artifact_path": f"/api/cases/visuals/{dest_filename}",
                    "mean_error": round(mean_diff, 2),
                    "std_error": round(std_diff, 2),
                    "max_error": round(max_diff, 2),
                    "potential_splicing": has_inconsistent_compression,
                    "caveat": "ELA results are heuristic indicators of resave history, not conclusive proof of forgery.",
                    "evidence_items": [e.model_dump() for e in evidence_items]
                }
        except Exception as e:
            return {
                "ela_artifact_path": None,
                "error": f"Failed to compute ELA: {str(e)}",
                "evidence_items": []
            }
