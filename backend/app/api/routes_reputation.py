from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, status
import httpx
from app.core.config import settings

router = APIRouter(prefix="/reputation", tags=["reputation"])

SAFE_HANDLING_GUIDES = {
    "Verified-Clean-Looking": {
        "title": "Low Risk Artifact Handling",
        "color": "emerald",
        "guidelines": [
            "File header matches its extension and contains standard structural elements.",
            "No trailing overlays, carved binaries, or prompt injection payloads detected.",
            "CAVEAT: No static analysis can guarantee safety. If acquired from an untrusted source, open only in standard sandboxed viewers."
        ]
    },
    "Unverified": {
        "title": "Unverified / Miscellaneous File Handling",
        "color": "amber",
        "guidelines": [
            "ForensiGPT could not verify this file as safe. It has NOT been scanned by antivirus.",
            "Do not execute, double-click, or open on your primary workstation.",
            "If analysis is required, transfer exclusively to an isolated sandbox VM (e.g. REMnux, FLARE VM).",
            "Maintain cryptographic chain of custody; verify file size and hashes before and after staging."
        ]
    },
    "Suspicious": {
        "title": "Suspicious Artifact Isolation Protocol",
        "color": "orange",
        "guidelines": [
            "Definite anomalies detected (e.g. extension mismatch, trailing data past EOF, or high entropy clustering).",
            "DO NOT OPEN ON BARE-METAL HOSTS. Isolate network interfaces immediately.",
            "Inspect trailing bytes and carved signatures using hex viewers in an air-gapped lab.",
            "Check endpoint logs for prior execution traces matching this file's hashes."
        ]
    },
    "Likely Malicious": {
        "title": "Critical Malicious Threat Handling",
        "color": "rose",
        "guidelines": [
            "HIGH-SEVERITY THREAT: Contains disguised executable payload, embedded exploit, or adversarial prompt injection.",
            "TREAT AS LIVE WEAPONIZED MALWARE.",
            "Quarantine immediately. Do not alter, rename, or run outside a hypervisor sandbox.",
            "Submit SHA-256 hash to enterprise SIEM/EDR blocklists to prevent execution fleet-wide."
        ]
    }
}

class HashLookupRequest(BaseModel):
    sha256: str
    api_key: str | None = None

@router.get("/safe-handling-guide")
def get_safe_handling_guide():
    return SAFE_HANDLING_GUIDES

@router.post("/lookup")
def lookup_hash_reputation(req: HashLookupRequest):
    api_key = (req.api_key or settings.VIRUSTOTAL_API_KEY).strip()
    if not api_key:
        return {
            "status": "unconfigured",
            "message": "VirusTotal API key is not provided. Enter your API key in Settings to enable hash lookups. Only the pre-calculated SHA-256 hash is sent.",
            "sha256": req.sha256,
            "reputation": None
        }

    # Query VirusTotal API v3 for hash only
    url = f"https://www.virustotal.com/api/v3/files/{req.sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = httpx.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "status": "success",
                "sha256": req.sha256,
                "reputation": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "community_score": attrs.get("reputation", 0)
                }
            }
        elif resp.status_code == 404:
            return {
                "status": "not_found",
                "message": "Hash not found in VirusTotal database (file may be novel or private).",
                "sha256": req.sha256,
                "reputation": None
            }
        else:
            return {
                "status": "error",
                "message": f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}",
                "sha256": req.sha256,
                "reputation": None
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Network error during lookup: {str(e)}",
            "sha256": req.sha256,
            "reputation": None
        }
