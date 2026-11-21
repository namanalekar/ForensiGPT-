from pathlib import Path
from fastapi.testclient import TestClient

def test_full_export_suite_pdf_md_json_csv(client: TestClient):
    # 1. Create a case and upload sample file
    c_res = client.post("/api/cases", json={"title": "Export Verification Case"})
    case_id = c_res.json()["id"]

    client.post(
        f"/api/cases/{case_id}/upload",
        files=[("files", ("suspicious_doc.pdf", b"%PDF-1.4 mock content %%EOF\x00\x00extra", "application/pdf"))]
    )

    # 2. Generate report in Privacy Mode
    rep_res = client.post(
        f"/api/cases/{case_id}/reports/generate",
        json={"case_id": case_id, "explanation_mode": "expert", "privacy_mode": True}
    )
    assert rep_res.status_code == 200

    # 3. Test PDF Export
    pdf_res = client.get(f"/api/cases/{case_id}/reports/export/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000  # Non-trivial PDF binary
    assert pdf_res.content.startswith(b"%PDF")

    # 4. Test Markdown Export
    md_res = client.get(f"/api/cases/{case_id}/reports/export/markdown")
    assert md_res.status_code == 200
    assert "text/markdown" in md_res.headers["content-type"]
    assert "# ForensiGPT Incident Dossier" in md_res.text
    assert "Mandatory Forensic Disclaimer" in md_res.text

    # 5. Test JSON Export
    json_res = client.get(f"/api/cases/{case_id}/reports/export/json")
    assert json_res.status_code == 200
    pkg = json_res.json()
    assert pkg["case_id"] == case_id
    assert "chain_of_custody_files" in pkg
    assert "ai_report" in pkg

    # 6. Test CSV Export
    csv_res = client.get(f"/api/cases/{case_id}/reports/export/csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "Timestamp_UTC" in csv_res.text

def test_file_comparison_and_safe_handling(client: TestClient):
    # Create case
    c_res = client.post("/api/cases", json={"title": "Comparison Case"})
    case_id = c_res.json()["id"]

    # Upload two files
    up_res = client.post(
        f"/api/cases/{case_id}/upload",
        files=[
            ("files", ("image_a.jpg", b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xD9", "image/jpeg")),
            ("files", ("image_b.jpg", b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xD9extra_bytes", "image/jpeg"))
        ]
    )
    files = up_res.json()["uploaded_files"]
    fa_id = files[0]["id"]
    fb_id = files[1]["id"]

    # Test compare endpoint
    comp_res = client.get(f"/api/cases/{case_id}/compare?file_a_id={fa_id}&file_b_id={fb_id}")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["comparison"]["hashes"]["sha256_match"] is False
    assert comp_data["comparison"]["format"]["format_match"] is True

    # Test safe handling guide
    sh_res = client.get("/api/reputation/safe-handling-guide")
    assert sh_res.status_code == 200
    guides = sh_res.json()
    assert "Likely Malicious" in guides
    assert "Unverified" in guides
