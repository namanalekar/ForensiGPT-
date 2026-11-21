import React, { useState } from 'react';
import { 
  FileText, 
  Image as ImageIcon, 
  FileCode, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Eye, 
  Clock, 
  Trash2, 
  ChevronDown, 
  ChevronUp,
  Fingerprint
} from 'lucide-react';
import { ForensicFile, VerdictType } from '../types/forensic';

interface FileCardProps {
  file: ForensicFile;
  onAnalyze: (file: ForensicFile) => void;
  onViewTriView?: (file: ForensicFile) => void;
  onCorrelate?: (file: ForensicFile) => void;
  onDelete: (fileId: string) => void;
}

export const FileCard: React.FC<FileCardProps> = ({
  file,
  onAnalyze,
  onViewTriView,
  onCorrelate,
  onDelete
}) => {
  const [showHashes, setShowHashes] = useState(false);
  const [showRiskBreakdown, setShowRiskBreakdown] = useState(false);

  const getVerdictBadge = (verdict: VerdictType) => {
    switch (verdict) {
      case 'Likely Malicious':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-700/60 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            LIKELY MALICIOUS
          </span>
        );
      case 'Suspicious':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-orange-950 text-orange-300 border border-orange-700/60 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-orange-400" />
            SUSPICIOUS
          </span>
        );
      case 'Unverified':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-amber-950 text-amber-300 border border-amber-600/70 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            UNVERIFIED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-700/60 flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            CLEAN-LOOKING
          </span>
        );
    }
  };

  const isImage = file.detected_category === 'image' || file.mime_type.includes('image');
  const isLog = file.detected_category === 'log' || file.mime_type.includes('text') || file.original_filename.endsWith('.log');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition shadow-sm space-y-4">
      {/* Header Line */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300">
            {isImage ? (
              <ImageIcon className="w-5 h-5 text-cyan-400" />
            ) : isLog ? (
              <FileCode className="w-5 h-5 text-emerald-400" />
            ) : (
              <FileText className="w-5 h-5 text-purple-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-100 text-sm">{file.original_filename}</span>
              {file.unverified_flags.length > 0 && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500 text-black">
                  UNVERIFIED
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-0.5">
              <span>{file.true_file_type}</span>
              <span>•</span>
              <span>{(file.file_size / 1024).toFixed(1)} KB</span>
              <span>•</span>
              <span>{file.mime_type}</span>
            </div>
          </div>
        </div>

        {/* Verdict & Risk Meter */}
        <div className="flex items-center gap-3">
          {getVerdictBadge(file.verdict)}

          {/* Risk Score Pill */}
          <button
            onClick={() => setShowRiskBreakdown(!showRiskBreakdown)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-600 transition font-mono text-xs"
            title="Click to view explainable risk score breakdown"
          >
            <span className="text-slate-400">Risk:</span>
            <span className={`font-bold ${
              file.risk_score >= 70 ? 'text-rose-400' :
              file.risk_score >= 40 ? 'text-orange-400' :
              file.risk_score >= 20 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {file.risk_score}/100
            </span>
            {showRiskBreakdown ? <ChevronUp className="w-3 h-3 text-slate-400" /> : <ChevronDown className="w-3 h-3 text-slate-400" />}
          </button>
        </div>
      </div>

      {/* Trailing data alert tag */}
      {file.has_trailing_data && (
        <div className="px-3 py-1.5 bg-amber-950/40 border border-amber-600/40 rounded-lg text-xs text-amber-300 flex items-center justify-between">
          <span className="flex items-center gap-1.5 font-medium">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            Detected {file.trailing_bytes_count.toLocaleString()} bytes appended beyond End-Of-File marker.
          </span>
          <span className="text-[10px] font-mono bg-amber-900/60 px-1.5 py-0.5 rounded">EVID-STEGO-001</span>
        </div>
      )}

      {/* Extension mismatch alert tag */}
      {!file.extension_match && (
        <div className="px-3 py-1.5 bg-rose-950/40 border border-rose-600/40 rounded-lg text-xs text-rose-300 flex items-center justify-between">
          <span className="flex items-center gap-1.5 font-medium">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            File extension does not match detected magic byte signature ({file.true_file_type}).
          </span>
          <span className="text-[10px] font-mono bg-rose-900/60 px-1.5 py-0.5 rounded">EVID-MISC-002</span>
        </div>
      )}

      {/* Expandable Risk Breakdown Meter */}
      {showRiskBreakdown && (
        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-2 text-xs animate-in fade-in duration-150">
          <div className="flex items-center justify-between text-slate-400 font-mono text-[11px] pb-1 border-b border-slate-800">
            <span>EXPLAINABLE RISK SCORE BREAKDOWN</span>
            <span>TOTAL: {file.risk_score}/100</span>
          </div>
          {file.risk_breakdown.length === 0 ? (
            <p className="text-slate-400 text-xs italic">No additive risk penalties assigned.</p>
          ) : (
            file.risk_breakdown.map((r, i) => (
              <div key={i} className="flex items-center justify-between text-slate-300 text-xs py-0.5">
                <span className="flex items-center gap-1.5">
                  <span className="text-rose-400 font-mono font-bold">+{r.points}</span>
                  <span>{r.factor}</span>
                </span>
                <span className="font-mono text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded">
                  {r.evidence_id || 'EVID-BASE'}
                </span>
              </div>
            ))
          )}
        </div>
      )}

      {/* Expandable Cryptographic Hashes (Chain of Custody) */}
      <div className="space-y-1.5">
        <button
          onClick={() => setShowHashes(!showHashes)}
          className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-mono transition"
        >
          <Fingerprint className="w-3.5 h-3.5" />
          <span>{showHashes ? 'Hide Hashes' : 'View Chain-of-Custody Hashes (SHA-256 / SHA-1 / MD5)'}</span>
        </button>

        {showHashes && (
          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg font-mono text-[11px] space-y-1 text-slate-400">
            <div className="flex justify-between items-center">
              <span className="text-slate-400">SHA-256:</span>
              <span className="text-cyan-300 select-all">{file.sha256}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">SHA-1:</span>
              <span className="text-slate-300 select-all">{file.sha1}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">MD5:</span>
              <span className="text-slate-300 select-all">{file.md5}</span>
            </div>
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
        <div className="flex items-center gap-2">
          <button
            onClick={() => onAnalyze(file)}
            className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            Analyze File
          </button>

          {isImage && onViewTriView && (
            <button
              onClick={() => onViewTriView(file)}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition"
            >
              <Eye className="w-3.5 h-3.5 text-cyan-400" />
              Tri-View (Original / ELA / LSB)
            </button>
          )}

          {isImage && onCorrelate && (
            <button
              onClick={() => onCorrelate(file)}
              className="px-3 py-1.5 rounded-lg bg-purple-950/40 hover:bg-purple-900/40 text-purple-300 border border-purple-700/50 text-xs font-medium flex items-center gap-1.5 transition"
            >
              <Clock className="w-3.5 h-3.5 text-purple-400" />
              Correlate with Logs
            </button>
          )}
        </div>

        <button
          onClick={() => onDelete(file.id)}
          className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-950/40 rounded transition"
          title="Delete file"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
