import crypto from 'crypto';

export interface StoredFile {
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
  verdict: 'Verified-Clean-Looking' | 'Unverified' | 'Suspicious' | 'Likely Malicious';
  risk_score: number;
  risk_breakdown: Array<{ factor: string; points: number; evidence_id?: string; description: string }>;
  uploaded_at: string;
  unverified_popup?: any;
  buffer?: Buffer;
}

export interface StoredCase {
  id: string;
  title: string;
  description: string;
  created_at: string;
  updated_at: string;
  status: string;
  files: StoredFile[];
}

// In-memory global store for Vercel Serverless environment
declare global {
  var __FORENSI_CASES__: Map<string, StoredCase> | undefined;
  var __FORENSI_REPORTS__: Map<string, any> | undefined;
}

if (!global.__FORENSI_CASES__) {
  global.__FORENSI_CASES__ = new Map<string, StoredCase>();
  // Create default initial case
  const defaultCaseId = 'case-default-01';
  global.__FORENSI_CASES__.set(defaultCaseId, {
    id: defaultCaseId,
    title: 'Operation Nightwatch (Incident Investigation)',
    description: 'Active triage workspace',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    status: 'open',
    files: []
  });
}

if (!global.__FORENSI_REPORTS__) {
  global.__FORENSI_REPORTS__ = new Map<string, any>();
}

export const casesStore = global.__FORENSI_CASES__!;
export const reportsStore = global.__FORENSI_REPORTS__!;
