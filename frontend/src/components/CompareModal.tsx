import React, { useState } from 'react';
import { X, GitCompare, ArrowRight, ShieldCheck, AlertTriangle } from 'lucide-react';
import { ForensicFile } from '../types/forensic';
import { api } from '../services/api';

interface CompareModalProps {
  caseId: string;
  files: ForensicFile[];
  isOpen: boolean;
  onClose: () => void;
}

export const CompareModal: React.FC<CompareModalProps> = ({ caseId, files, isOpen, onClose }) => {
  const [fileAId, setFileAId] = useState(files[0]?.id || '');
  const [fileBId, setFileBId] = useState(files[1]?.id || files[0]?.id || '');
  const [comparison, setComparison] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const runCompare = async () => {
    if (!fileAId || !fileBId) return;
    setLoading(true);
    try {
      const data = await api.compareFiles(caseId, fileAId, fileBId);
      setComparison(data.comparison);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in">
      <div className="w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-xl flex flex-col shadow-2xl overflow-hidden max-h-[88vh]">
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white font-mono">Dual-File Comparison Mode</h2>
              <p className="text-xs text-slate-400 font-mono">Compare cryptographic digests, true formats, and entropy variance</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* File Selectors */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">Target File A:</label>
              <select
                value={fileAId}
                onChange={(e) => setFileAId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
              >
                {files.map(f => (
                  <option key={f.id} value={f.id}>{f.original_filename} ({f.true_file_type})</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs font-mono text-slate-400 block mb-1">Target File B:</label>
              <select
                value={fileBId}
                onChange={(e) => setFileBId(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
              >
                {files.map(f => (
                  <option key={f.id} value={f.id}>{f.original_filename} ({f.true_file_type})</option>
                ))}
              </select>
            </div>
          </div>

          <button
            onClick={runCompare}
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center justify-center gap-2 transition"
          >
            <GitCompare className="w-4 h-4" />
            {loading ? 'Comparing...' : 'Run Comparative Diff'}
          </button>

          {/* Diff Results */}
          {comparison && (
            <div className="space-y-4 font-mono text-xs animate-in fade-in">
              {/* Hashes */}
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="font-bold text-slate-200">Cryptographic SHA-256 Digest Match</span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${comparison.hashes.sha256_match ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}`}>
                    {comparison.hashes.sha256_match ? 'IDENTICAL MATCH' : 'DISTINCT HASHES'}
                  </span>
                </div>
                <div className="space-y-1 text-slate-400 text-[11px]">
                  <p>File A: <span className="text-slate-300">{comparison.hashes.file_a.sha256}</span></p>
                  <p>File B: <span className="text-slate-300">{comparison.hashes.file_b.sha256}</span></p>
                </div>
              </div>

              {/* Entropy & Size */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">Entropy Profile Diff:</span>
                  <p className="text-cyan-300 font-bold text-sm">
                    Δ {comparison.entropy.delta_entropy} bits/byte
                  </p>
                  <span className="text-[10px] text-slate-400">
                    A: {comparison.entropy.file_a_entropy} | B: {comparison.entropy.file_b_entropy}
                  </span>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block mb-1">File Size Variance:</span>
                  <p className="text-purple-300 font-bold text-sm">
                    {comparison.size.delta_bytes >= 0 ? `+${comparison.size.delta_bytes} B` : `${comparison.size.delta_bytes} B`}
                  </p>
                  <span className="text-[10px] text-slate-400">
                    A: {comparison.size.file_a_bytes} B | B: {comparison.size.file_b_bytes} B
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
