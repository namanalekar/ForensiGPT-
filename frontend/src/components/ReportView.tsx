import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Layers, 
  ListOrdered, 
  Compass, 
  HelpCircle,
  MessageSquare,
  RefreshCw,
  FileDown
} from 'lucide-react';
import { ForensicReport, VerdictType } from '../types/forensic';

interface ReportViewProps {
  caseId: string;
  report: ForensicReport | null;
  modelUsed: string;
  privacyActive: boolean;
  onSwitchMode: (mode: 'eli5' | 'analyst' | 'expert') => void;
  currentMode: string;
  onOpenChat: () => void;
  isGenerating: boolean;
}

export const ReportView: React.FC<ReportViewProps> = ({
  caseId,
  report,
  modelUsed,
  privacyActive,
  onSwitchMode,
  currentMode,
  onOpenChat,
  isGenerating
}) => {
  if (isGenerating) {
    return (
      <div className="p-12 text-center space-y-3 bg-slate-900 border border-slate-800 rounded-xl">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400 mx-auto" />
        <h3 className="text-base font-bold text-white font-mono">Synthesizing Forensic Report...</h3>
        <p className="text-xs text-slate-400">Contextualizing deterministic findings and structuring evidence citations.</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-10 text-center space-y-4 bg-slate-900 border border-slate-800 rounded-xl">
        <FileText className="w-10 h-10 text-slate-400 mx-auto" />
        <h3 className="text-base font-bold text-white font-mono">No Forensic Report Generated Yet</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Generate an AI or Local-Privacy forensic dossier to synthesize all uploaded file findings, timeline synchronization, and IOCs.
        </p>
      </div>
    );
  }

  const getVerdictColor = (v: VerdictType) => {
    switch (v) {
      case 'Likely Malicious': return 'text-rose-400 border-rose-600 bg-rose-950/40';
      case 'Suspicious': return 'text-orange-400 border-orange-600 bg-orange-950/40';
      case 'Unverified': return 'text-amber-400 border-amber-600 bg-amber-950/40';
      default: return 'text-emerald-400 border-emerald-600 bg-emerald-950/40';
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
      {/* Top Controls: Mode Switcher & Export Dropdown */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2 font-mono">
            <FileText className="w-5 h-5 text-cyan-400" />
            Incident Forensic Dossier & Executive Summary
          </h2>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mt-1">
            <span>Engine: {privacyActive ? 'Local Deterministic Template (Privacy Mode)' : `Gemini (${modelUsed})`}</span>
          </div>
        </div>

        {/* Explanation Mode Selector */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs font-mono">
            <button
              onClick={() => onSwitchMode('eli5')}
              className={`px-3 py-1.5 rounded transition ${currentMode === 'eli5' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
            >
              Beginner (ELI5)
            </button>
            <button
              onClick={() => onSwitchMode('analyst')}
              className={`px-3 py-1.5 rounded transition ${currentMode === 'analyst' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
            >
              Analyst
            </button>
            <button
              onClick={() => onSwitchMode('expert')}
              className={`px-3 py-1.5 rounded transition ${currentMode === 'expert' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
            >
              Technical / Expert
            </button>
          </div>

          {/* Ask Evidence Button */}
          <button
            onClick={onOpenChat}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <MessageSquare className="w-3.5 h-3.5" />
            Ask the Evidence
          </button>

          {/* Export Dropdown Group */}
          <div className="flex items-center gap-1.5">
            <a
              href={`/api/cases/${caseId}/reports/export/pdf`}
              download
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
              title="Download official PDF report"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              PDF
            </a>
            <a
              href={`/api/cases/${caseId}/reports/export/markdown`}
              download
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
              title="Download GitHub-flavored Markdown"
            >
              MD
            </a>
            <a
              href={`/api/cases/${caseId}/reports/export/json`}
              download
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
              title="Download raw JSON evidence package"
            >
              JSON
            </a>
            <a
              href={`/api/cases/${caseId}/reports/export/csv`}
              download
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
              title="Download timeline events CSV"
            >
              CSV
            </a>
          </div>
        </div>
      </div>

      {/* Mandatory Disclaimer Callout */}
      <div className="p-3 bg-rose-950/30 border border-rose-800/40 rounded-lg text-rose-300 text-xs font-mono flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
        <span>Generated with AI contextualization. Verify all findings independently. No static analysis can prove a file is safe.</span>
      </div>

      {/* 1. Verdict & Risk Score Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className={`p-4 rounded-xl border flex flex-col justify-between ${getVerdictColor(report.verdict)}`}>
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Assigned Verdict</span>
          <span className="text-lg font-bold font-mono mt-1">{report.verdict}</span>
          <span className="text-[10px] text-slate-400 mt-2">Static analysis evaluation</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Risk Score Meter</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono text-cyan-300">{report.risk_score}</span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-2">
            <div 
              className={`h-full ${
                report.risk_score >= 70 ? 'bg-rose-500' :
                report.risk_score >= 40 ? 'bg-orange-500' :
                report.risk_score >= 20 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${report.risk_score}%` }}
            />
          </div>
        </div>

        <div className="md:col-span-2 p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Executive Summary</span>
          <p className="text-xs text-slate-200 mt-1 leading-relaxed">
            {report.executive_summary}
          </p>
          <span className="text-[10px] text-slate-400 font-mono mt-2">Mode: {currentMode.toUpperCase()}</span>
        </div>
      </div>

      {/* 2. Key Findings Table (Citing Evidence IDs) */}
      <div className="space-y-3">
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-1.5">
          <Layers className="w-4 h-4 text-cyan-400" />
          Deterministic Findings & Explanations (Citing Evidence IDs):
        </h3>
        <div className="border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-3">Evidence ID</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Title</th>
                <th className="p-3">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 bg-slate-900/60">
              {report.key_findings.map((f, i) => (
                <tr key={i} className="hover:bg-slate-800/40 transition">
                  <td className="p-3 text-cyan-400 font-bold whitespace-nowrap">{f.evidence_id}</td>
                  <td className="p-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      f.severity === 'Critical' ? 'bg-rose-950 text-rose-300' :
                      f.severity === 'High' ? 'bg-orange-950 text-orange-300' :
                      f.severity === 'Medium' ? 'bg-amber-950 text-amber-300' : 'bg-slate-800 text-slate-300'
                    }`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="p-3 font-semibold text-slate-200">{f.title}</td>
                  <td className="p-3 text-slate-300 font-sans leading-relaxed">{f.plain_explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Observed Facts vs Hypotheses */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4" />
            Observed Verifiable Facts:
          </h3>
          <ul className="space-y-1.5 text-xs text-slate-300">
            {report.observed_facts.map((fact, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">•</span>
                <span>{fact}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-purple-400 font-bold flex items-center gap-1.5">
            <Compass className="w-4 h-4" />
            Analytical Hypotheses & Inferences:
          </h3>
          <div className="space-y-2">
            {report.hypotheses.map((h, idx) => (
              <div key={idx} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs space-y-1">
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-purple-300 font-semibold">{h.hypothesis}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
                    {h.confidence} Confidence
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 italic">Missing: {h.missing_evidence}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. Recommended Next Steps & Assumptions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 font-mono text-xs">
        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
          <span className="text-slate-400 font-bold block uppercase tracking-wider">Recommended Next Steps:</span>
          <ul className="space-y-1 text-slate-300">
            {report.recommended_next_steps.map((step, idx) => (
              <li key={idx}>→ {step}</li>
            ))}
          </ul>
        </div>

        <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
          <span className="text-slate-400 font-bold block uppercase tracking-wider">Limitations & Assumptions:</span>
          <ul className="space-y-1 text-slate-400">
            {report.limitations_and_assumptions.map((asm, idx) => (
              <li key={idx}>• {asm}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
