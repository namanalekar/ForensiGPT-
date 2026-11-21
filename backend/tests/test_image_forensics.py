import io
from pathlib import Path
from PIL import Image
import numpy as np
from fastapi.testclient import TestClient
from app.analyzers.exif import ExifForensicsAnalyzer
from app.analyzers.stego import StegoForensicsAnalyzer
from app.analyzers.entropy import EntropyForensicsAnalyzer
from app.analyzers.ela import ELAForensicsAnalyzer
from app.analyzers.lsb import LSBVisualizer
from app.analyzers.image_engine import ImageForensicsCoordinator

def create_synthetic_jpeg(tmp_path: Path, filename: str = "test.jpg", width: int = 100, height: int = 100, color: tuple = (120, 150, 180)) -> Path:
    """Creates a valid synthetic JPEG image programmatically."""
    p = tmp_path / filename
    img = Image.new("RGB", (width, height), color=color)
    img.save(p, "JPEG", quality=90)
    return p

def test_exif_editing_software_detected(tmp_path: Path):
    """Verifies that traces of editing software (e.g., Photoshop, Canva) are flagged with evidence ID."""
    p = tmp_path / "edited.jpg"
    img = Image.new("RGB", (100, 100), color=(120, 150, 180))
    exif = img.getexif()
    exif[0x0131] = "Adobe Photoshop 2026"  # 0x0131 is standard EXIF tag for Software
    img.save(p, "JPEG", exif=exif)

    res = ExifForensicsAnalyzer.analyze(p, "edited.jpg")
    assert any("editing" in item["title"].lower() or "photoshop" in item["description"].lower() for item in res["evidence_items"])
    assert any(item["evidence_id"] == "EVID-IMG-EXIF-001" for item in res["evidence_items"])

def test_stego_carved_signature_detection(tmp_path: Path):
    """Verifies that embedded ZIP archives carved inside the image stream are identified."""
    p = create_synthetic_jpeg(tmp_path, "carrier.jpg")
    raw_bytes = p.read_bytes()
    # Embed a mock ZIP signature in the middle of image
    zip_payload = b"PK\x03\x04\x14\x00\x00\x00\x00\x00mock_payload_inside_zip_file_header"
    mid = len(raw_bytes) // 2
    embedded_bytes = raw_bytes[:mid] + zip_payload + raw_bytes[mid:]
    p.write_bytes(embedded_bytes)

    stego_res = StegoForensicsAnalyzer.analyze(p, "image/jpeg")
    assert len(stego_res["carved_signatures"]) >= 1
    assert any(s["signature"] == "ZIP Archive" for s in stego_res["carved_signatures"])
    assert any(e["evidence_id"] == "EVID-IMG-CARVE-001" for e in stego_res["evidence_items"])

def test_entropy_analyzer_and_heatmap_generation(tmp_path: Path):
    """Verifies that block entropy calculates correctly and saves the 2D heatmap PNG."""
    p = create_synthetic_jpeg(tmp_path, "entropy_test.jpg")
    # Append high entropy random bytes
    np.random.seed(42)
    random_bytes = bytes(np.random.randint(0, 256, size=4096, dtype=np.uint8))
    p.write_bytes(p.read_bytes() + random_bytes)

    entropy_res = EntropyForensicsAnalyzer.analyze(p, "file_ent_1", "image/jpeg")
    assert entropy_res["overall_entropy"] > 6.0
    assert entropy_res["heatmap_artifact_path"] is not None

    # Verify that the generated heatmap file exists on disk
    heatmap_name = Path(entropy_res["heatmap_artifact_path"]).name
    from app.core.config import settings
    heatmap_file = settings.VISUALS_DIR / heatmap_name
    assert heatmap_file.exists()
    assert heatmap_file.stat().st_size > 0

def test_ela_error_level_analysis_generation(tmp_path: Path):
    """Verifies that ELA generates the visual diff artifact and calculates error statistics."""
    p = create_synthetic_jpeg(tmp_path, "ela_test.jpg")

    ela_res = ELAForensicsAnalyzer.generate_ela(p, "file_ela_1")
    assert ela_res["ela_artifact_path"] is not None
    assert "mean_error" in ela_res
    assert "caveat" in ela_res

    ela_filename = Path(ela_res["ela_artifact_path"]).name
    from app.core.config import settings
    ela_file = settings.VISUALS_DIR / ela_filename
    assert ela_file.exists()
    assert ela_file.stat().st_size > 0

def test_lsb_plane_visualizer_generation(tmp_path: Path):
    """Verifies that LSB planes are extracted into a visual PNG artifact."""
    p = create_synthetic_jpeg(tmp_path, "lsb_test.jpg")

    lsb_res = LSBVisualizer.generate_lsb_planes(p, "file_lsb_1")
    assert lsb_res["lsb_artifact_path"] is not None
    assert lsb_res["width"] == 100
    assert lsb_res["height"] == 100

    lsb_filename = Path(lsb_res["lsb_artifact_path"]).name
    from app.core.config import settings
    lsb_file = settings.VISUALS_DIR / lsb_filename
    assert lsb_file.exists()

def test_full_image_analysis_api_endpoint(client: TestClient, tmp_path: Path):
    """Integration test: upload image -> trigger analyze endpoint -> fetch visual artifacts."""
    # 1. Create a case
    c_res = client.post("/api/cases", json={"title": "Image Forensics Case"})
    case_id = c_res.json()["id"]

    # 2. Upload synthetic image
    p = create_synthetic_jpeg(tmp_path, "suspect.jpg")
    with open(p, "rb") as f:
        upload_res = client.post(
            f"/api/cases/{case_id}/upload",
            files=[("files", ("suspect.jpg", f.read(), "image/jpeg"))]
        )
    assert upload_res.status_code == 200
    file_id = upload_res.json()["uploaded_files"][0]["id"]

    # 3. Trigger deep analysis
    analysis_res = client.post(f"/api/cases/{case_id}/files/{file_id}/analyze")
    assert analysis_res.status_code == 200
    data = analysis_res.json()

    assert data["analyzer_type"] == "image_deep"
    assert "metadata_blob" in data
    assert "visual_artifacts" in data
    artifacts = data["visual_artifacts"]
    assert artifacts["ela_path"] is not None
    assert artifacts["lsb_path"] is not None
    assert artifacts["entropy_heatmap_path"] is not None

    # 4. Fetch the visual artifacts via the API to verify they are served safely
    ela_url = artifacts["ela_path"]
    ela_fetch = client.get(ela_url)
    assert ela_fetch.status_code == 200
    assert ela_fetch.headers["content-type"] == "image/png"

    lsb_url = artifacts["lsb_path"]
    lsb_fetch = client.get(lsb_url)
    assert lsb_fetch.status_code == 200
    assert lsb_fetch.headers["content-type"] == "image/png"

    entropy_url = artifacts["entropy_heatmap_path"]
    ent_fetch = client.get(entropy_url)
    assert ent_fetch.status_code == 200
    assert ent_fetch.headers["content-type"] == "image/png"


if __name__ == "__main__":
    import tempfile
    print("Running test_exif_editing_software_detected...", flush=True)
    with tempfile.TemporaryDirectory() as td:
        test_exif_editing_software_detected(Path(td))
    print("test_exif_editing_software_detected: PASSED", flush=True)

    print("Running test_stego_carved_signature_detection...", flush=True)
    with tempfile.TemporaryDirectory() as td:
        test_stego_carved_signature_detection(Path(td))
    print("test_stego_carved_signature_detection: PASSED", flush=True)

    print("Running test_entropy_analyzer_and_heatmap_generation...", flush=True)
    with tempfile.TemporaryDirectory() as td:
        test_entropy_analyzer_and_heatmap_generation(Path(td))
    print("test_entropy_analyzer_and_heatmap_generation: PASSED", flush=True)

    print("Running test_ela_error_level_analysis_generation...", flush=True)
    with tempfile.TemporaryDirectory() as td:
        test_ela_error_level_analysis_generation(Path(td))
    print("test_ela_error_level_analysis_generation: PASSED", flush=True)

    print("Running test_lsb_plane_visualizer_generation...", flush=True)
    with tempfile.TemporaryDirectory() as td:
        test_lsb_plane_visualizer_generation(Path(td))
    print("test_lsb_plane_visualizer_generation: PASSED", flush=True)

    print("ALL STANDALONE IMAGE FORENSICS TESTS PASSED!", flush=True)
