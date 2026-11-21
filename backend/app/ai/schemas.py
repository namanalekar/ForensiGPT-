from typing import Literal
from pydantic import BaseModel, Field

class StructuredFindingItem(BaseModel):
    evidence_id: str = Field(description="Must cite an existing evidence ID from the input evidence, e.g. EVID-IMG-001")
    severity: Literal["Info", "Low", "Medium", "High", "Critical"]
    title: str
    plain_explanation: str = Field(description="Clear explanation tailored to the requested explanation mode")

class StructuredTimelineItem(BaseModel):
    timestamp_utc: str
    event_id: str | None = None
    summary: str
    is_observed_fact: bool

class StructuredHypothesis(BaseModel):
    hypothesis: str
    confidence: Literal["Low", "Medium", "High"]
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: str

class ForensicReportSchema(BaseModel):
    executive_summary: str
    verdict: Literal["Verified-Clean-Looking", "Unverified", "Suspicious", "Likely Malicious"]
    risk_score: int = Field(ge=0, le=100)
    key_findings: list[StructuredFindingItem]
    timeline_narrative: list[StructuredTimelineItem]
    image_log_correlation_narrative: str
    observed_facts: list[str]
    hypotheses: list[StructuredHypothesis]
    recommended_next_steps: list[str]
    limitations_and_assumptions: list[str]
