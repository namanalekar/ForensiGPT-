export type VerdictType = 'Verified-Clean-Looking' | 'Unverified' | 'Suspicious' | 'Likely Malicious';

export interface RiskFactor {
  factor: string;
  points: number;
  evidence_id?: string;
  description: string;
}

export interface UnverifiedModalData {
  should_trigger_popup: boolean;
  title: string;
  warning_text: string;
  reasons: string[];
  claimed_type: string;
  detected_true_type: string;
  verdict: VerdictType;
  persistent_badge: string;
}

export interface ForensicFile {
  id: string;
  case_id: string;
  original_filename: string;
  file_size: number;
  sha256: string;
  sha1: string;
  md5: string;
  mime_type: string;
  detected_category: string;
  true_file_type: string;
  extension_match: boolean;
  has_trailing_data: boolean;
  trailing_bytes_count: number;
  unverified_flags: string[];
  verdict: VerdictType;
  risk_score: number;
  risk_breakdown: RiskFactor[];
  uploaded_at: string;
  unverified_popup?: UnverifiedModalData;
}

export interface CaseData {
  id: string;
  title: string;
  description: string;
  created_at: string;
  updated_at: string;
  status: string;
  files: ForensicFile[];
}

export interface EvidenceItem {
  evidence_id: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  category: string;
  title: string;
  description: string;
  raw_data?: Record<string, any>;
}

export interface VisualArtifacts {
  original_path?: string;
  ela_path?: string;
  lsb_path?: string;
  entropy_heatmap_path?: string;
}

export interface ImageAnalysisData {
  file_id: string;
  analyzer_type: string;
  evidence_items: EvidenceItem[];
  metadata_blob: {
    exif?: Record<string, any>;
    stego?: Record<string, any>;
    entropy?: Record<string, any>;
    ela?: Record<string, any>;
  };
  visual_artifacts: VisualArtifacts;
  analyzed_at: string;
}

export interface CorrelatedEvent {
  id: string;
  file_id: string;
  timestamp: string;
  timestamp_epoch: number;
  host: string;
  process: string;
  message: string;
  raw_line?: string;
  line_number: number;
  normalized_type: string;
  relevance_score: number;
  delta_seconds: number;
  delta_desc: string;
  iocs: Array<{ type: string; value: string; defanged: string }>;
  mitre_tags: Array<{ id: string; name: string; tactic: string; url: string }>;
}

export interface TimelineSyncData {
  case_id: string;
  anchor_file_id: string;
  anchor_epoch: number;
  effective_anchor_epoch: number;
  window_seconds: number;
  manual_offset_seconds: number;
  clock_skew_warning?: string;
  correlated_events: CorrelatedEvent[];
  before_after_patterns: Array<{
    event_id: string;
    delta_seconds: number;
    description: string;
    relevance: number;
  }>;
  swimlane: {
    window_start_iso: string;
    window_end_iso: string;
    anchor: {
      file_id: string;
      label: string;
      anchor_type: string;
      effective_iso: string;
      manual_offset_applied: number;
    };
    events_track: CorrelatedEvent[];
    total_in_window: number;
    log_range?: {
      min_iso: string;
      max_iso: string;
    };
  };
}

export interface StructuredFinding {
  evidence_id: string;
  severity: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  title: string;
  plain_explanation: string;
}

export interface StructuredHypothesis {
  hypothesis: string;
  confidence: 'Low' | 'Medium' | 'High';
  supporting_evidence_ids: string[];
  missing_evidence: string;
}

export interface ForensicReport {
  executive_summary: string;
  verdict: VerdictType;
  risk_score: number;
  key_findings: StructuredFinding[];
  timeline_narrative: Array<{
    timestamp_utc: string;
    event_id?: string;
    summary: string;
    is_observed_fact: boolean;
  }>;
  image_log_correlation_narrative: string;
  observed_facts: string[];
  hypotheses: StructuredHypothesis[];
  recommended_next_steps: string[];
  limitations_and_assumptions: string[];
}

export interface SettingsData {
  gemini_model: string;
  gemini_api_key_set: boolean;
  privacy_mode_default: boolean;
  retention_hours: number;
  max_upload_size_mb: number;
  virustotal_configured: boolean;
}
