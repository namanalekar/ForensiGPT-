import React, { useState, useEffect } from 'react';
import { Shield, Eye, Lock, Check, X, AlertCircle } from 'lucide-react';
import { api } from '../services/api';

interface RedactionModalProps {
  caseId: string;
  isOpen: boolean;
  onClose: () => void;
  onProceed: () => void;
}

export const RedactionModal: React.FC<RedactionModalProps> = ({
  caseId,
  isOpen,
  onClose,
  onProceed
}) => {
  const [loading, setLoading] = useState(true);
  const [candidates, setCandidates] = useState<any[]>([]);
  const [previewJson, setPreviewJson] = useState<any>(null);
  const [redactedState, setRedactedState] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!isOpen || !caseId) return;
    setLoading(true);
    api.previewRedactions(caseId).then(data => {
      setCandidates(data.redaction_candidates || []);
      setPreviewJson(data.sanitized_evidence_json || {});
      const initial: Record<string, boolean> = {};
      (data.redaction_candidates || []).forEach((c: any) => {
        initial[c.field_name] = true;
      });
      setRedactedState(initial);
    }).catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, [isOpen, caseId]);

  if (!isOpen) return null;

  const toggleRedact = (fieldName: string) => {
    setRedactedState(prev => ({ ...prev, [fieldName]: !prev[fieldName] }));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in">
      <div className="w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-xl flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Pre-Flight Privacy & Redaction Review</h2>
              <p className="text-xs text-slate-400 font-mono">
                Inspect and redact sensitive fields (GPS, internal IPs, usernames) before AI transmission.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {loading ? (
            <div className="py-20 text-center text-slate-400 font-mono text-xs">
              Analyzing payload for sensitive entities...
            </div>
          ) : (
            <>
              {/* Redaction Candidate Toggles */}
              <div className="space-y-3">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                  Identified Sensitive Field Toggles:
                </h3>
                {candidates.length === 0 ? (
                  <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs text-slate-400 italic">
                    No high-sensitivity GPS coordinates or internal IP strings flagged in metadata.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {candidates.map((c) => (
                      <div
                        key={c.field_name}
                        onClick={() => toggleRedact(c.field_name)}
                        className={`p-3 rounded-lg border flex items-center justify-between transition cursor-pointer text-xs font-mono ${
                          redactedState[c.field_name]
                            ? 'bg-emerald-950/30 border-emerald-500/60 text-emerald-200'
                            : 'bg-slate-950 border-slate-800 text-slate-400'
                        }`}
                      >
                        <div>
                          <span className="font-bold text-slate-200 block">{c.field_name}</span>
                          <span className="text-[11px] text-slate-400">
                            Original: <span className="text-slate-300">{c.original_value}</span> → Masked: <span className="text-cyan-300">{c.redacted_value}</span>
                          </span>
                        </div>
                        <span className={`px-2.5 py-1 rounded text-xs font-bold ${
                          redactedState[c.field_name]
                            ? 'bg-emerald-500 text-black'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {redactedState[c.field_name] ? 'REDACTED' : 'TRANSMIT AS-IS'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Exact JSON Payload Preview */}
              <div className="space-y-2">
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                  Exact Outbound AI Payload Preview:
                </h3>
                <pre className="p-4 bg-black/80 border border-slate-800 rounded-lg text-[11px] font-mono text-cyan-300/90 max-h-[300px] overflow-y-auto leading-relaxed select-all">
                  {JSON.stringify(previewJson, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="border-t border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/80">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 transition"
          >
            Cancel
          </button>

          <button
            onClick={() => {
              onClose();
              onProceed();
            }}
            className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition"
          >
            <Check className="w-4 h-4" />
            Approve & Transmit to Gemini
          </button>
        </div>
      </div>
    </div>
  );
};
