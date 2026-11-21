import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.ai.gemini_client import GeminiForensicsClient
from app.ai.schemas import ForensicReportSchema

def test_privacy_mode_offline_report_generation():
    """Verifies that Privacy Mode generates 100% deterministic local reports without external network calls or API keys."""
    files = [
        {
            "id": "file_123",
            "original_filename": "trojan_disguised.jpg",
            "true_file_type": ".exe",
            "extension_match": False,
            "has_trailing_data": True,
            "trailing_bytes_count": 512,
            "risk_score": 50,
            "verdict": "Suspicious"
        }
    ]
    analysis_map = {
        "file_123": {
            "evidence_items": [
                {
                    "evidence_id": "EVID-IMG-EXIF-001",
                    "severity": "Medium",
                    "title": "Editing Software Traces Detected",
                    "description": "Photoshop traces detected."
                }
            ]
        }
    }

    report, model_used = GeminiForensicsClient.generate_report(
        case_title="Local Privacy Investigation",
        files=files,
        analysis_map=analysis_map,
        sync_result=None,
        risk_score=50,
        verdict="Suspicious",
        mode="analyst",
        privacy_mode=True
    )

    assert isinstance(report, ForensicReportSchema)
    assert model_used == "local_privacy_template"
    assert report.risk_score == 50
    assert report.verdict == "Suspicious"
    assert len(report.key_findings) >= 2
    # Check Evidence IDs cited
    e_ids = [f.evidence_id for f in report.key_findings]
    assert "EVID-MISC-002" in e_ids
    assert "EVID-STEGO-001" in e_ids

def test_mock_gemini_structured_call():
    """Verifies Gemini SDK invocation and schema validation handling."""
    mock_json_response = """
    {
      "executive_summary": "Suspicious executable artifact disguised as a JPEG image.",
      "verdict": "Likely Malicious",
      "risk_score": 85,
      "key_findings": [
        {
          "evidence_id": "EVID-MISC-002",
          "severity": "Critical",
          "title": "Extension Mismatch Disguised Executable",
          "plain_explanation": "File is a Windows PE executable disguised with a .jpg extension."
        }
      ],
      "timeline_narrative": [],
      "image_log_correlation_narrative": "No correlation requested.",
      "observed_facts": ["File has PE header MZ."],
      "hypotheses": [
        {
          "hypothesis": "File intended for social engineering phishing delivery.",
          "confidence": "High",
          "supporting_evidence_ids": ["EVID-MISC-002"],
          "missing_evidence": "Email headers or delivery logs."
        }
      ],
      "recommended_next_steps": ["Block SHA-256 hash across endpoint fleet."],
      "limitations_and_assumptions": ["Static analysis only."]
    }
    """

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = mock_json_response
    mock_client.models.generate_content.return_value = mock_resp

    with patch.object(GeminiForensicsClient, "get_client", return_value=mock_client):
        report, model_used = GeminiForensicsClient.generate_report(
            case_title="Mocked Case",
            files=[{"id": "1", "original_filename": "payload.jpg", "risk_score": 85, "verdict": "Likely Malicious"}],
            analysis_map={},
            sync_result=None,
            risk_score=85,
            verdict="Likely Malicious",
            mode="expert",
            privacy_mode=False
        )

        assert report.verdict == "Likely Malicious"
        assert report.risk_score == 85
        assert len(report.key_findings) == 1
        assert report.key_findings[0].evidence_id == "EVID-MISC-002"

def test_report_api_and_redaction_preview(client: TestClient):
    """Integration test: case creation -> upload -> redaction preview -> report generation."""
    c_res = client.post("/api/cases", json={"title": "Report API Integration Case"})
    case_id = c_res.json()["id"]

    # Upload mock file
    client.post(
        f"/api/cases/{case_id}/upload",
        files=[("files", ("evidence.bin", b"DATA" * 50, "application/octet-stream"))]
    )

    # 1. Test Redaction Preview Endpoint
    prev_res = client.post(f"/api/cases/{case_id}/reports/preview-redaction")
    assert prev_res.status_code == 200
    prev_data = prev_res.json()
    assert "redaction_candidates" in prev_data
    assert "sanitized_evidence_json" in prev_data

    # 2. Test Report Generation Endpoint (in Privacy Mode)
    gen_res = client.post(
        f"/api/cases/{case_id}/reports/generate",
        json={"case_id": case_id, "explanation_mode": "analyst", "privacy_mode": True}
    )
    assert gen_res.status_code == 200
    rep_data = gen_res.json()
    assert rep_data["privacy_mode_active"] is True
    assert "report" in rep_data
    assert "key_findings" in rep_data["report"]
    assert "executive_summary" in rep_data["report"]

    # 3. Test Latest Report Retrieval
    latest_res = client.get(f"/api/cases/{case_id}/reports/latest")
    assert latest_res.status_code == 200
    assert latest_res.json()["report_id"] == rep_data["report_id"]
