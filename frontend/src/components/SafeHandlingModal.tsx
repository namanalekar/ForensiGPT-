import React from 'react';
import { X, HelpCircle, ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

interface SafeHandlingModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SafeHandlingModal: React.FC<SafeHandlingModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-xl flex flex-col shadow-2xl overflow-hidden max-h-[88vh]">
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/30">
              <HelpCircle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white font-mono">Forensic Artifact Safe Handling Guide</h2>
              <p className="text-xs text-slate-400 font-mono">Operational security protocols for each threat verdict</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4 overflow-y-auto font-mono text-xs">
          {/* Likely Malicious */}
          <div className="p-4 bg-rose-950/30 border border-rose-700/60 rounded-xl space-y-2">
            <span className="font-bold text-rose-300 text-sm flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              1. LIKELY MALICIOUS PROTOCOL (CRITICAL)
            </span>
            <ul className="space-y-1 text-slate-300 list-disc pl-5">
              <li>Contains disguised executable binary headers, nested shellcode, or prompt-injection attacks.</li>
              <li><strong>TREAT AS LIVE WEAPONIZED MALWARE.</strong> Never double click or run on host systems.</li>
              <li>Quarantine in an air-gapped forensic VM (e.g. REMnux, FLARE VM).</li>
              <li>Distribute SHA-256 hash immediately to enterprise SIEM/EDR blocklists.</li>
            </ul>
          </div>

          {/* Suspicious */}
          <div className="p-4 bg-orange-950/30 border border-orange-700/60 rounded-xl space-y-2">
            <span className="font-bold text-orange-300 text-sm flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              2. SUSPICIOUS ARTIFACT ISOLATION PROTOCOL
            </span>
            <ul className="space-y-1 text-slate-300 list-disc pl-5">
              <li>Definite structural anomalies detected (e.g. extension mismatch, trailing data past EOF).</li>
              <li>Isolate endpoint network adapters before continuing dynamic triage.</li>
              <li>Carve and inspect trailing bytes using hex editors inside an isolated container.</li>
            </ul>
          </div>

          {/* Unverified */}
          <div className="p-4 bg-amber-950/30 border border-amber-700/60 rounded-xl space-y-2">
            <span className="font-bold text-amber-300 text-sm flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              3. UNVERIFIED / MISCELLANEOUS FILE PROTOCOL
            </span>
            <ul className="space-y-1 text-slate-300 list-disc pl-5">
              <li>File is an unrecognized binary, script, or truncated file.</li>
              <li>It has NOT been scanned by antivirus. Do not open on your main workstation.</li>
              <li>Maintain cryptographic chain of custody hashes before performing deeper manual inspection.</li>
            </ul>
          </div>

          {/* Clean-looking */}
          <div className="p-4 bg-emerald-950/30 border border-emerald-700/60 rounded-xl space-y-2">
            <span className="font-bold text-emerald-300 text-sm flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              4. CLEAN-LOOKING ARTIFACT GUIDELINES
            </span>
            <ul className="space-y-1 text-slate-300 list-disc pl-5">
              <li>Normal structure and matching magic bytes; no steganographic markers identified.</li>
              <li><strong>REMINDER:</strong> No static analysis can prove a file is safe. Open only in standard sandboxed viewers.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
