import urllib.request
import json
import mimetypes
import os

BASE_URL = "http://127.0.0.1:8000/api"

# 1. Create case
req = urllib.request.Request(
    f"{BASE_URL}/cases",
    data=json.dumps({"title": "Operation Nightwatch", "description": "Test DFIR case"}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    case = json.loads(resp.read().decode())
    case_id = case["id"]
    print("Created Case:", case_id, case["title"])

# 2. Upload samples
def upload_file(case_id, file_path):
    filename = os.path.basename(file_path)
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}/cases/{case_id}/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

samples_dir = r"C:\Users\naman\.gemini\antigravity\scratch\forensigpt\samples"

# Upload suspicious file
res_suspicious = upload_file(case_id, os.path.join(samples_dir, "suspicious_payload.jpg"))
print("Uploaded suspicious_payload.jpg:", len(res_suspicious["uploaded_files"]), "files. Popup:", res_suspicious["uploaded_files"][0].get("unverified_popup", {}).get("should_trigger_popup"))
print("Popup Reasons:", res_suspicious["uploaded_files"][0].get("unverified_popup", {}).get("reasons"))

# Upload image and log
res_image = upload_file(case_id, os.path.join(samples_dir, "surveillance_capture.jpg"))
res_log = upload_file(case_id, os.path.join(samples_dir, "auth.log"))

# 3. Trigger analysis for image
img_file_id = res_image["uploaded_files"][0]["id"]
req = urllib.request.Request(f"{BASE_URL}/cases/{case_id}/files/{img_file_id}/analyze", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    img_res = json.loads(resp.read().decode())
    print("Image Analysis Done. Evidence items count:", len(img_res["evidence_items"]))
    print("Artifacts generated:", list(img_res["visual_artifacts"].keys()))

# 4. Trigger analysis for log
log_file_id = res_log["uploaded_files"][0]["id"]
req = urllib.request.Request(f"{BASE_URL}/cases/{case_id}/files/{log_file_id}/analyze?target_year=2026&timezone_offset_hours=0", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    log_res = json.loads(resp.read().decode())
    print("Log Analysis Done. Lines parsed:", log_res["total_lines_parsed"], "MITRE techniques:", [t["id"] for t in log_res["mitre_techniques"]])

# 5. Test Image-to-Log Correlation Synchronization
# Fetch anchors first
req = urllib.request.Request(f"{BASE_URL}/cases/{case_id}/correlation/anchors", method="GET")
with urllib.request.urlopen(req) as resp:
    anchors_data = json.loads(resp.read().decode())
    # Pick surveillance_capture.jpg which has the EXIF capture timestamp matching the auth.log
    target_f = next(f for f in anchors_data["files"] if "surveillance" in f["filename"])
    # Pick EXIF original capture time anchor
    anchor = next(a for a in target_f["anchors"] if a["anchor_type"] == "exif_datetime_original")
    print(f"Anchor selected from {target_f['filename']}: {anchor['label']} ({anchor['iso_timestamp']})")

sync_payload = {
    "anchor_file_id": target_f["file_id"],
    "anchor_type": anchor["anchor_type"],
    "anchor_epoch": anchor["epoch"],
    "anchor_label": anchor["label"],
    "window_seconds": 300,
    "manual_offset_seconds": 0
}
req = urllib.request.Request(f"{BASE_URL}/cases/{case_id}/correlation/sync", data=json.dumps(sync_payload).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    sync_res = json.loads(resp.read().decode())
    print("Correlation Sync Done. Correlated Events in Window:", len(sync_res["correlated_events"]))
    print("Before/After Patterns:", len(sync_res["before_after_patterns"]))
    for p in sync_res["before_after_patterns"]:
        print("  -> Pattern:", p["description"])

# 6. Test Privacy-Mode (offline local) Report Generation
req = urllib.request.Request(
    f"{BASE_URL}/cases/{case_id}/reports/generate",
    data=json.dumps({"case_id": case_id, "explanation_mode": "analyst", "privacy_mode": True}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    rep_res = json.loads(resp.read().decode())
    print("Report Generated! Executive Summary:", rep_res["report"]["executive_summary"][:120])
    print("Overall Verdict:", rep_res["report"]["verdict"], "Risk Score:", rep_res["report"]["risk_score"])

# 7. Test Exports
for fmt in ["pdf", "markdown", "json", "csv"]:
    req = urllib.request.Request(f"{BASE_URL}/cases/{case_id}/reports/export/{fmt}", method="GET")
    with urllib.request.urlopen(req) as resp:
        content = resp.read()
        print(f"Export format '{fmt}' retrieved successfully ({len(content)} bytes).")

print("\n>>> ALL API FLOWS AND EXPORTS VERIFIED 100% WORKING! <<<")
