import React from 'react';
import { Shield, Lock, EyeOff, Trash2, Cpu, HelpCircle, GitCompare, RefreshCw } from 'lucide-react';

interface HeaderProps {
  privacyMode: boolean;
  onTogglePrivacy: () => void;
  geminiModel: string;
  onOpenSettings: () => void;
  onOpenSafeGuide: () => void;
  onOpenCompare: () => void;
  onPurgeData: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  privacyMode,
  onTogglePrivacy,
  geminiModel,
  onOpenSettings,
  onOpenSafeGuide,
  onOpenCompare,
  onPurgeData
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-inner">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5 font-mono">
              FORENSI<span className="text-cyan-400">GPT</span>
            </h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              v1.0 DFIR
            </span>
          </div>
          <p className="text-xs text-slate-400">AI-Powered Image, File & Log Forensics Investigator</p>
        </div>
      </div>

      {/* Control Pills */}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        {/* Privacy Mode Toggle Pill */}
        <button
          onClick={onTogglePrivacy}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition font-mono ${
            privacyMode
              ? 'bg-emerald-950/70 border-emerald-500 text-emerald-300 shadow-sm shadow-emerald-900/50'
              : 'bg-slate-900 border-slate-700 text-slate-300 hover:border-slate-500'
          }`}
          title="Toggle Privacy Mode (100% offline local analysis, no external API calls)"
        >
          {privacyMode ? (
            <>
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>PRIVACY MODE: <strong className="text-emerald-400">ACTIVE</strong></span>
            </>
          ) : (
            <>
              <EyeOff className="w-3.5 h-3.5 text-slate-400" />
              <span>Privacy Mode: <span className="text-slate-400">Off</span></span>
            </>
          )}
        </button>

        {/* Gemini Model Pin Badge */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-700/80 text-slate-300 font-mono">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400">Model:</span>
          <span className="text-cyan-300 font-medium">{geminiModel || 'gemini-2.5-flash'}</span>
        </div>

        {/* File Compare Button */}
        <button
          onClick={onOpenCompare}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-cyan-500 text-slate-300 hover:text-white transition"
        >
          <GitCompare className="w-3.5 h-3.5 text-cyan-400" />
          <span>Compare Files</span>
        </button>

        {/* Safe Handling Guide Button */}
        <button
          onClick={onOpenSafeGuide}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-amber-500 text-slate-300 hover:text-white transition"
        >
          <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
          <span>Safe Handling Guide</span>
        </button>

        {/* Purge / Delete My Data Now Button */}
        <button
          onClick={onPurgeData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/40 border border-rose-800/80 hover:bg-rose-900/60 text-rose-300 hover:text-white transition font-mono"
          title="Immediately wipe all cases, uploaded files, and reports"
        >
          <Trash2 className="w-3.5 h-3.5 text-rose-400" />
          <span>Delete My Data Now</span>
        </button>
      </div>
    </header>
  );
};
