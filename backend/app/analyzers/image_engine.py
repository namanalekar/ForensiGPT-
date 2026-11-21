import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from app.models.db_models import get_db
from app.analyzers.exif import ExifForensicsAnalyzer
from app.analyzers.stego import StegoForensicsAnalyzer
from app.analyzers.entropy import EntropyForensicsAnalyzer
from app.analyzers.ela import ELAForensicsAnalyzer
from app.analyzers.lsb import LSBVisualizer

class ImageForensicsCoordinator:
    """
    Orchestrates deterministic image forensics: EXIF, Stego carving, Entropy,
    ELA, and LSB planes, assembling evidence items and visual artifacts.
    """

    @classmethod
    def analyze_image(cls, file_path: Path, file_id: str, original_filename: str, mime_type: str) -> dict[str, Any]:
        # 1. EXIF Analysis
        exif_res = ExifForensicsAnalyzer.analyze(file_path, original_filename)

        # 2. Steganography Analysis
        stego_res = StegoForensicsAnalyzer.analyze(file_path, mime_type)

        # 3. Entropy Analysis & Heatmap
        entropy_res = EntropyForensicsAnalyzer.analyze(file_path, file_id, mime_type)

        # 4. Error Level Analysis
        ela_res = ELAForensicsAnalyzer.generate_ela(file_path, file_id)

        # 5. LSB Plane Visualizer
        lsb_res = LSBVisualizer.generate_lsb_planes(file_path, file_id)

        # Consolidate evidence items
        all_evidence = []
        all_evidence.extend(exif_res.get("evidence_items", []))
        all_evidence.extend(stego_res.get("evidence_items", []))
        all_evidence.extend(entropy_res.get("evidence_items", []))
        all_evidence.extend(ela_res.get("evidence_items", []))

        # Consolidate visual artifacts
        visual_artifacts = {
            "original_path": f"/api/cases/vault/{Path(file_path).name}",
            "ela_path": ela_res.get("ela_artifact_path"),
            "lsb_path": lsb_res.get("lsb_artifact_path"),
            "entropy_heatmap_path": entropy_res.get("heatmap_artifact_path")
        }

        metadata_blob = {
            "exif": exif_res.get("metadata", {}),
            "stego": {
                "carved_signatures": stego_res.get("carved_signatures", []),
                "lsb_stats": stego_res.get("lsb_analysis", {}),
                "png_anomalies": stego_res.get("png_anomalies", [])
            },
            "entropy": {
                "overall": entropy_res.get("overall_entropy"),
                "max_block": entropy_res.get("max_block_entropy"),
                "min_block": entropy_res.get("min_block_entropy")
            },
            "ela": {
                "mean_error": ela_res.get("mean_error"),
                "potential_splicing": ela_res.get("potential_splicing")
            }
        }

        now_iso = datetime.now(timezone.utc).isoformat()

        # Save/Update in SQLite analysis_results
        with get_db() as db:
            # Check existing
            cur = db.execute("SELECT id FROM analysis_results WHERE file_id = ?", (file_id,))
            existing = cur.fetchone()
            if existing:
                db.execute(
                    """
                    UPDATE analysis_results
                    SET evidence_items = ?, metadata_blob = ?, visual_artifacts = ?, analyzed_at = ?
                    WHERE file_id = ?
                    """,
                    (json.dumps(all_evidence), json.dumps(metadata_blob), json.dumps(visual_artifacts), now_iso, file_id)
                )
            else:
                db.execute(
                    """
                    INSERT INTO analysis_results (id, file_id, analyzer_type, evidence_items, metadata_blob, visual_artifacts, analyzed_at)
                    VALUES (?, ?, 'image_deep', ?, ?, ?, ?)
                    """,
                    (f"analysis_{file_id}", file_id, json.dumps(all_evidence), json.dumps(metadata_blob), json.dumps(visual_artifacts), now_iso)
                )
            db.commit()

        return {
            "file_id": file_id,
            "analyzer_type": "image_deep",
            "evidence_items": all_evidence,
            "metadata_blob": metadata_blob,
            "visual_artifacts": visual_artifacts,
            "analyzed_at": now_iso
        }
