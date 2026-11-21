import pytest
import io
from pathlib import Path
from fastapi.testclient import TestClient
from app.analyzers.filetype import FileTypeInspector

def test_case_creation_and_health(client: TestClient):
    # Test health check
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["app"] == "ForensiGPT"

    # Test case creation
    c_resp = client.post("/api/cases", json={"title": "Test Case 1", "description": "Verification case"})
    assert c_resp.status_code == 200
    case_data = c_resp.json()
    assert case_data["title"] == "Test Case 1"
    assert "id" in case_data

def test_condition_1_unsupported_misc_file(client: TestClient, tmp_path: Path):
    """Condition 1: File type is not in supported/known-safe categories (misc/unknown)."""
    misc_file = tmp_path / "unknown_sample.xyz"
    misc_file.write_bytes(b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 32)

    inspection = FileTypeInspector.inspect(misc_file, "unknown_sample.xyz")
    popup = inspection["unverified_popup"]
    assert popup is not None
    assert popup.should_trigger_popup is True
    assert "⚠ Miscellaneous / Unverified File Detected" in popup.title
    assert any("unverified / miscellaneous type" in r for r in popup.reasons)
    assert inspection["verdict"] in {"Unverified", "Suspicious"}
    assert "UNVERIFIED_TYPE" in inspection["unverified_flags"]

def test_condition_2_extension_mismatch_jpg_is_zip(client: TestClient, tmp_path: Path):
    """Condition 2: Extension does not match magic bytes (e.g. .jpg that is really a ZIP)."""
    mismatch_file = tmp_path / "fake_photo.jpg"
    mismatch_file.write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 100)

    inspection = FileTypeInspector.inspect(mismatch_file, "fake_photo.jpg")
    popup = inspection["unverified_popup"]
    assert inspection["extension_match"] is False
    assert inspection["true_file_type"] == ".zip"
    assert popup is not None
    assert any("does not match detected magic bytes" in r for r in popup.reasons)
    assert inspection["verdict"] in {"Suspicious", "Likely Malicious"}
    assert "EXTENSION_MISMATCH" in inspection["unverified_flags"]

def test_condition_3_executable_or_script_detection(client: TestClient, tmp_path: Path):
    """Condition 3: File is an executable, script, shortcut (.lnk), or disk image."""
    pe_file = tmp_path / "payload.exe"
    pe_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 200)

    inspection = FileTypeInspector.inspect(pe_file, "payload.exe")
    popup = inspection["unverified_popup"]
    assert inspection["detected_category"] == "executable"
    assert popup is not None
    assert any("executable" in r.lower() for r in popup.reasons)
    assert inspection["verdict"] == "Likely Malicious"
    assert "EXECUTABLE_OR_SCRIPT" in inspection["unverified_flags"]

    sh_file = tmp_path / "deploy.sh"
    sh_file.write_bytes(b"#!/bin/bash\necho 'hello world'\n")
    inspection_sh = FileTypeInspector.inspect(sh_file, "deploy.sh")
    assert inspection_sh["detected_category"] == "script"
    assert inspection_sh["unverified_popup"] is not None

def test_condition_4_trailing_eof_data(client: TestClient, tmp_path: Path):
    """Condition 4: Hidden/trailing data detected after end-of-file marker (e.g. JPEG EOI FFD9)."""
    jpeg_file = tmp_path / "stego_suspicious.jpg"
    valid_jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\xFF\xD9"
    hidden_payload = b"SECRET_HIDDEN_DATA_APPENDED_PAST_EOI_MARKER_12345"
    jpeg_file.write_bytes(valid_jpeg_bytes + hidden_payload)

    inspection = FileTypeInspector.inspect(jpeg_file, "stego_suspicious.jpg")
    popup = inspection["unverified_popup"]
    assert inspection["has_trailing_data"] is True
    assert inspection["trailing_bytes_count"] == len(hidden_payload)
    assert popup is not None
    assert any("appended after JPEG EOI marker" in r for r in popup.reasons)
    assert "TRAILING_EOF_DATA" in inspection["unverified_flags"]

def test_condition_5_suspicious_truncated_metadata(client: TestClient, tmp_path: Path):
    """Condition 5: Metadata missing or looks stripped/forged in a suspicious way."""
    truncated_camera_file = tmp_path / "IMG_4920.jpg"
    truncated_camera_file.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 10)

    inspection = FileTypeInspector.inspect(truncated_camera_file, "IMG_4920.jpg")
    popup = inspection["unverified_popup"]
    assert popup is not None
    assert any("suspiciously truncated" in r for r in popup.reasons)
    assert "SUSPICIOUS_METADATA_TRUNCATION" in inspection["unverified_flags"]

def test_verified_clean_file(client: TestClient, tmp_path: Path):
    """Valid standard JPEG image with no trailing data or mismatches should be clean-looking."""
    clean_jpeg = tmp_path / "photo.jpg"
    valid_jpeg_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\xFF\xD9"
    clean_jpeg.write_bytes(valid_jpeg_bytes)

    inspection = FileTypeInspector.inspect(clean_jpeg, "photo.jpg")
    assert inspection["has_trailing_data"] is False
    assert inspection["extension_match"] is True
    assert inspection["verdict"] == "Verified-Clean-Looking"
    assert inspection["unverified_popup"] is None

def test_full_upload_pipeline_and_cancel_delete(client: TestClient):
    """Tests the full API upload endpoint, hash generation, popup response, and file cancellation."""
    # 1. Create a case
    c_res = client.post("/api/cases", json={"title": "Forensic Incident 101"})
    case_id = c_res.json()["id"]

    # 2. Upload two files: one clean-looking JPEG, one suspicious EXE disguised as JPG
    clean_content = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xD9"
    suspicious_content = b"MZ\x90\x00\x03\x00" + b"\x00" * 50

    files = [
        ("files", ("evidence_normal.jpg", clean_content, "image/jpeg")),
        ("files", ("invoice_scan.jpg", suspicious_content, "image/jpeg")),
    ]

    upload_res = client.post(f"/api/cases/{case_id}/upload", files=files)
    assert upload_res.status_code == 200
    upload_data = upload_res.json()

    uploaded_files = upload_data["uploaded_files"]
    assert len(uploaded_files) == 2

    # Check cryptographic hashes are present on both files
    for f in uploaded_files:
        assert len(f["sha256"]) == 64
        assert len(f["sha1"]) == 40
        assert len(f["md5"]) == 32

    # Verify popup list contains the suspicious file
    popups = upload_data["popup_required_files"]
    assert len(popups) == 1
    assert popups[0]["title"] == "⚠ Miscellaneous / Unverified File Detected"
    assert "ForensiGPT could not verify this file as safe" in popups[0]["warning_text"]
    assert popups[0]["persistent_badge"] == "UNVERIFIED"

    # Find the suspicious file ID
    suspicious_file = next(f for f in uploaded_files if f["original_filename"] == "invoice_scan.jpg")
    assert suspicious_file["verdict"] == "Likely Malicious"
    assert suspicious_file["extension_match"] is False

    # 3. Simulate user clicking 'Cancel and delete file' in the unverified popup
    del_res = client.delete(f"/api/cases/{case_id}/files/{suspicious_file['id']}")
    assert del_res.status_code == 204

    # 4. Verify case now only has the clean file remaining
    case_after = client.get(f"/api/cases/{case_id}")
    case_files = case_after.json()["files"]
    assert len(case_files) == 1
    assert case_files[0]["original_filename"] == "evidence_normal.jpg"
