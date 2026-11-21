import {
  CaseData,
  ForensicFile,
  ImageAnalysisData,
  TimelineSyncData,
  ForensicReport,
  SettingsData
} from '../types/forensic';

const API_BASE = '/api';

export const api = {
  // Cases
  async listCases(): Promise<CaseData[]> {
    const res = await fetch(`${API_BASE}/cases`);
    if (!res.ok) throw new Error('Failed to load cases');
    return res.json();
  },

  async createCase(title: string, description: string = ''): Promise<CaseData> {
    const res = await fetch(`${API_BASE}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description })
    });
    if (!res.ok) throw new Error('Failed to create case');
    return res.json();
  },

  async getCase(caseId: string): Promise<CaseData> {
    const res = await fetch(`${API_BASE}/cases/${caseId}`);
    if (!res.ok) throw new Error('Failed to load case');
    return res.json();
  },

  async deleteCase(caseId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/cases/${caseId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete case');
  },

  // Upload
  async uploadFiles(caseId: string, files: File[]): Promise<{ uploaded_files: ForensicFile[]; popup_required_files: any[] }> {
    const formData = new FormData();
    files.forEach(f => formData.append('files', f));
    const res = await fetch(`${API_BASE}/cases/${caseId}/upload`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Upload failed');
    }
    return res.json();
  },

  async deleteFile(caseId: string, fileId: string): Promise<void> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/files/${fileId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete file');
  },

  // Deep Analysis
  async analyzeFile(caseId: string, fileId: string, targetYear: number = 2026, offsetHours: number = 0): Promise<any> {
    const res = await fetch(
      `${API_BASE}/cases/${caseId}/files/${fileId}/analyze?target_year=${targetYear}&timezone_offset_hours=${offsetHours}`,
      { method: 'POST' }
    );
    if (!res.ok) throw new Error('Analysis failed');
    return res.json();
  },

  async getAnalysis(caseId: string, fileId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/files/${fileId}/analysis`);
    if (!res.ok) throw new Error('Failed to fetch analysis');
    return res.json();
  },

  // Anchors & Correlation
  async getAnchors(caseId: string, offsetHours: number = 0): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/anchors?timezone_offset_hours=${offsetHours}`);
    if (!res.ok) throw new Error('Failed to get anchors');
    return res.json();
  },

  async syncTimeline(
    caseId: string,
    anchorFileId: string,
    anchorType: string,
    anchorEpoch: number,
    anchorLabel: string,
    windowSeconds: number,
    manualOffsetSeconds: number
  ): Promise<TimelineSyncData> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        anchor_file_id: anchorFileId,
        anchor_type: anchorType,
        anchor_epoch: anchorEpoch,
        anchor_label: anchorLabel,
        window_seconds: windowSeconds,
        manual_offset_seconds: manualOffsetSeconds
      })
    });
    if (!res.ok) throw new Error('Failed to sync timeline');
    return res.json();
  },

  // Reports
  async previewRedactions(caseId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/reports/preview-redaction`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to load redaction preview');
    return res.json();
  },

  async generateReport(caseId: string, mode: string = 'analyst', privacyMode: boolean = false): Promise<{ report: ForensicReport; model_used: string }> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ case_id: caseId, explanation_mode: mode, privacy_mode: privacyMode })
    });
    if (!res.ok) throw new Error('Failed to generate report');
    return res.json();
  },

  async getLatestReport(caseId: string): Promise<{ report: ForensicReport; model_used: string; privacy_mode_active: boolean }> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/reports/latest`);
    if (!res.ok) throw new Error('No reports found');
    return res.json();
  },

  // Chat
  async askChat(caseId: string, message: string): Promise<{ role: string; content: string; evidence_citations: string[] }> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ case_id: caseId, message })
    });
    if (!res.ok) throw new Error('Chat failed');
    return res.json();
  },

  async getChatHistory(caseId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/chat`);
    if (!res.ok) throw new Error('Failed to load chat');
    return res.json();
  },

  // Compare & Safe Handling
  async compareFiles(caseId: string, fileAId: string, fileBId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/compare?file_a_id=${fileAId}&file_b_id=${fileBId}`);
    if (!res.ok) throw new Error('Comparison failed');
    return res.json();
  },

  async getSafeHandling(): Promise<any> {
    const res = await fetch(`${API_BASE}/reputation/safe-handling-guide`);
    if (!res.ok) throw new Error('Failed to load guide');
    return res.json();
  },

  // Settings & Purge
  async getSettings(): Promise<SettingsData> {
    const res = await fetch(`${API_BASE}/settings`);
    if (!res.ok) throw new Error('Failed to load settings');
    return res.json();
  },

  async purgeAllData(): Promise<any> {
    const res = await fetch(`${API_BASE}/settings/purge`, { method: 'POST' });
    if (!res.ok) throw new Error('Purge failed');
    return res.json();
  }
};
