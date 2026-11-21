from typing import Literal, Any
from pydantic import BaseModel, Field

VerdictType = Literal[
    "Verified-Clean-Looking",
    "Unverified",
    "Suspicious",
    "Likely Malicious"
]

SeverityType = Literal["Info", "Low", "Medium", "High", "Critical"]
ExplanationModeType = Literal["eli5", "analyst", "expert"]

class UnverifiedModalData(BaseModel):
    should_trigger_popup: bool
    title: str = "⚠ Miscellaneous / Unverified File Detected"
    warning_text: str = (
        "ForensiGPT could not verify this file as safe. "
        "It has NOT been scanned by antivirus. "
        "Do not open or run it on your main system."
    )
    reasons: list[str] = Field(default_factory=list)
    claimed_type: str
    detected_true_type: str
    verdict: VerdictType
    persistent_badge: str = "UNVERIFIED"

class EvidenceItem(BaseModel):
    evidence_id: str
    severity: SeverityType
    category: str
    title: str
    description: str
    raw_data: dict[str, Any] = Field(default_factory=dict)

class RiskFactor(BaseModel):
    factor: str
    points: int
    evidence_id: str | None = None
    description: str

class FileResponse(BaseModel):
    id: str
    case_id: str
    original_filename: str
    file_size: int
    sha256: str
    sha1: str
    md5: str
    mime_type: str
    detected_category: str
    true_file_type: str
    extension_match: bool
    has_trailing_data: bool
    trailing_bytes_count: int
    unverified_flags: list[str]
    verdict: VerdictType
    risk_score: int
    risk_breakdown: list[RiskFactor] = Field(default_factory=list)
    uploaded_at: str
    unverified_popup: UnverifiedModalData | None = None

class FileUploadResponse(BaseModel):
    case_id: str
    uploaded_files: list[FileResponse]
    popup_required_files: list[UnverifiedModalData] = Field(default_factory=list)

class CaseCreate(BaseModel):
    title: str = "Investigation Case"
    description: str = ""

class CaseResponse(BaseModel):
    id: str
    title: str
    description: str
    created_at: str
    updated_at: str
    status: str
    files: list[FileResponse] = Field(default_factory=list)

class RedactionItem(BaseModel):
    field_name: str
    original_value: str
    redacted_value: str
    category: str  # "GPS", "IP", "Username", "Custom"
    applied: bool = True

class RedactionPreviewPayload(BaseModel):
    case_id: str
    redaction_candidates: list[RedactionItem]
    sanitized_evidence_json: dict[str, Any]

class ReportGenerateRequest(BaseModel):
    case_id: str
    explanation_mode: ExplanationModeType = "analyst"
    privacy_mode: bool = False
    applied_redactions: list[RedactionItem] = Field(default_factory=list)

class GroundedChatRequest(BaseModel):
    case_id: str
    message: str

class GroundedChatResponse(BaseModel):
    case_id: str
    role: str = "assistant"
    content: str
    evidence_citations: list[str] = Field(default_factory=list)
    created_at: str

class SettingsDTO(BaseModel):
    gemini_model: str
    gemini_api_key_set: bool
    privacy_mode_default: bool
    retention_hours: int
    max_upload_size_mb: int
    virustotal_configured: bool
