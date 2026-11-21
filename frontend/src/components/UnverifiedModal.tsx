import React from 'react';
import { AlertTriangle, Trash2, ShieldCheck, FileWarning } from 'lucide-react';
import { UnverifiedModalData } from '../types/forensic';

interface UnverifiedModalProps {
  popupData: UnverifiedModalData | null;
  onConfirm: () => void;
  onCancelDelete: () => void;
}

export const UnverifiedModal: React.FC<UnverifiedModalProps> = ({
  popupData,
  onConfirm,
  onCancelDelete
}) => {
  if (!popupData || !popupData.should_trigger_popup) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
      <div 
        className="w-full max-w-xl bg-slate-900 border-2 border-amber-500/80 rounded-xl shadow-2xl shadow-amber-950/50 overflow-hidden"
        role="alertdialog"
        aria-labelledby="unverified-modal-title"
        aria-describedby="unverified-modal-desc"
      >
        {/* Header with amber warning band */}
        <div className="bg-amber-500/10 border-b border-amber-500/30 px-6 py-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400">
            <AlertTriangle className="w-7 h-7 animate-pulse" />
          </div>
          <div>
            <h2 id="unverified-modal-title" className="text-xl font-bold text-amber-300 tracking-wide">
              {popupData.title}
            </h2>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="px-2 py-0.5 text-xs font-mono font-bold bg-amber-500 text-black rounded uppercase">
                {popupData.persistent_badge}
              </span>
              <span className="text-xs text-slate-400">Verdict: {popupData.verdict}</span>
            </div>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5">
          <div id="unverified-modal-desc" className="p-3.5 bg-rose-950/40 border border-rose-500/40 rounded-lg text-rose-200 text-sm font-medium leading-relaxed">
            {popupData.warning_text}
          </div>

          {/* Type Comparison Card */}
          <div className="grid grid-cols-2 gap-3 p-3 bg-slate-950/60 border border-slate-800 rounded-lg font-mono text-xs">
            <div>
              <span className="text-slate-400 block mb-1">Claimed File Format:</span>
              <span className="font-semibold text-slate-200 bg-slate-800 px-2 py-1 rounded inline-block">
                {popupData.claimed_type || 'Unknown'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Detected True Format:</span>
              <span className="font-semibold text-amber-300 bg-amber-950/50 border border-amber-700/50 px-2 py-1 rounded inline-block">
                {popupData.detected_true_type}
              </span>
            </div>
          </div>

          {/* Reason Breakdown */}
          <div className="space-y-2">
            <h3 className="text-xs uppercase font-mono tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
              <FileWarning className="w-4 h-4 text-amber-400" />
              Specific Forensic Anomaly Indicators:
            </h3>
            <ul className="space-y-2 pl-1">
              {popupData.reasons.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-300 leading-relaxed">
                  <span className="text-amber-400 font-bold mt-0.5">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Modal Footer Actions */}
        <div className="bg-slate-950/80 border-t border-slate-800 px-6 py-4 flex flex-col-reverse sm:flex-row items-center justify-between gap-3">
          <button
            onClick={onCancelDelete}
            className="w-full sm:w-auto px-4 py-2.5 rounded-lg border border-rose-700/60 hover:bg-rose-900/40 text-rose-300 hover:text-rose-100 text-xs font-semibold flex items-center justify-center gap-2 transition"
          >
            <Trash2 className="w-4 h-4" />
            Cancel and delete file
          </button>

          <button
            onClick={onConfirm}
            className="w-full sm:w-auto px-5 py-2.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-black text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-amber-500/20 transition"
          >
            <ShieldCheck className="w-4 h-4" />
            I understand, continue analysis
          </button>
        </div>
      </div>
    </div>
  );
};
