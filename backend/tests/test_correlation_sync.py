import pytest
from datetime import datetime, timezone
from pathlib import Path
from PIL import Image
from fastapi.testclient import TestClient
from app.correlation.sync_engine import ImageLogSyncEngine
from app.correlation.anchors import AnchorExtractor

def test_image_to_log_synchronization(client: TestClient, tmp_path: Path):
    # 1. Create a case
    c_res = client.post("/api/cases", json={"title": "Image-to-Log Correlation Case"})
    case_id = c_res.json()["id"]

    # 2. Upload an image with a known EXIF DateTimeOriginal: 2026-11-21 12:00:00 UTC
    img_path = tmp_path / "camera_evidence.jpg"
    img = Image.new("RGB", (100, 100), color=(100, 120, 140))
    exif = img.getexif()
    # 0x9003 is DateTimeOriginal, 0x0132 is DateTime
    exif[0x9003] = "2026:11:21 12:00:00"
    exif[0x0132] = "2026:11:21 12:00:00"
    img.save(img_path, "JPEG", exif=exif)

    # 3. Upload a log with events around 12:00:00:
    # 11:59:19 (-41s): SSH login
    # 12:01:00 (+60s): sudo command
    # 12:15:00 (+900s): cron job (outside 300s window)
    log_content = (
        "Nov 21 11:59:19 server sshd[1050]: Accepted password for deploy from 203.0.113.5 port 45000 ssh2\n"
        "Nov 21 12:01:00 server sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash\n"
        "Nov 21 12:15:00 server CRON[1090]: (root) CMD (/usr/local/bin/backup.sh)\n"
    )

    with open(img_path, "rb") as f_img:
        up_img = client.post(
            f"/api/cases/{case_id}/upload",
            files=[("files", ("camera_evidence.jpg", f_img.read(), "image/jpeg"))]
        )
    img_file_id = up_img.json()["uploaded_files"][0]["id"]

    up_log = client.post(
        f"/api/cases/{case_id}/upload",
        files=[("files", ("auth.log", log_content.encode("utf-8"), "text/plain"))]
    )
    log_file_id = up_log.json()["uploaded_files"][0]["id"]

    # 4. Trigger log parser to populate log_events in DB
    parse_res = client.post(f"/api/cases/{case_id}/files/{log_file_id}/analyze?target_year=2026&timezone_offset_hours=0.0")
    assert parse_res.status_code == 200

    # 5. Retrieve anchors for the image
    anchors_res = client.get(f"/api/cases/{case_id}/correlation/anchors")
    assert anchors_res.status_code == 200
    files_anchors = anchors_res.json()["files"]
    img_anchor_group = next(f for f in files_anchors if f["file_id"] == img_file_id)
    assert len(img_anchor_group["anchors"]) >= 1

    # Find the EXIF DateTimeOriginal anchor
    target_anchor = next(
        (a for a in img_anchor_group["anchors"] if a["anchor_type"] == "exif_datetime_original"),
        img_anchor_group["anchors"][0]
    )
    anchor_epoch = target_anchor["epoch"]

    # 6. Run correlation with default ±300s window
    sync_res = client.post(
        f"/api/cases/{case_id}/correlation/sync",
        json={
            "anchor_file_id": img_file_id,
            "anchor_type": target_anchor["anchor_type"],
            "anchor_epoch": anchor_epoch,
            "anchor_label": target_anchor["label"],
            "window_seconds": 300,
            "manual_offset_seconds": 0
        }
    )
    assert sync_res.status_code == 200
    data = sync_res.json()

    # In default 300s window:
    # 11:59:19 (-41s) and 12:01:00 (+60s) must be present
    # 12:15:00 (+900s) must NOT be present
    in_win_events = data["correlated_events"]
    assert len(in_win_events) == 2
    delta_vals = [e["delta_seconds"] for e in in_win_events]
    assert -41.0 in delta_vals
    assert 60.0 in delta_vals

    # Check before/after pattern was flagged
    patterns = data["before_after_patterns"]
    assert len(patterns) >= 1
    assert any("41.0s BEFORE" in p["description"] for p in patterns)

    # 7. Expand window to 1200s (20 mins)
    sync_1200 = client.post(
        f"/api/cases/{case_id}/correlation/sync",
        json={
            "anchor_file_id": img_file_id,
            "anchor_type": target_anchor["anchor_type"],
            "anchor_epoch": anchor_epoch,
            "anchor_label": target_anchor["label"],
            "window_seconds": 1200,
            "manual_offset_seconds": 0
        }
    )
    assert len(sync_1200.json()["correlated_events"]) == 3  # Now includes the +900s cron job

    # 8. Test Clock Skew Warning: simulate an image timestamp from 2025 (1 year skewed)
    skewed_epoch = anchor_epoch - (365 * 86400)
    sync_skew = client.post(
        f"/api/cases/{case_id}/correlation/sync",
        json={
            "anchor_file_id": img_file_id,
            "anchor_type": "skewed_anchor",
            "anchor_epoch": skewed_epoch,
            "anchor_label": "Skewed Timestamp",
            "window_seconds": 300,
            "manual_offset_seconds": 0
        }
    )
    skew_data = sync_skew.json()
    assert skew_data["clock_skew_warning"] is not None
    assert "Timestamps don't overlap with the logs" in skew_data["clock_skew_warning"]

    # 9. Test Manual Offset Correction: shift by +365 days
    sync_corrected = client.post(
        f"/api/cases/{case_id}/correlation/sync",
        json={
            "anchor_file_id": img_file_id,
            "anchor_type": "skewed_anchor",
            "anchor_epoch": skewed_epoch,
            "anchor_label": "Skewed Timestamp",
            "window_seconds": 300,
            "manual_offset_seconds": int(365 * 86400)
        }
    )
    assert sync_corrected.json()["clock_skew_warning"] is None
    assert len(sync_corrected.json()["correlated_events"]) == 2
