import React, { useState, useEffect } from 'react';
import { X, Eye, Layers, Activity, AlertCircle, Info, RefreshCw } from 'lucide-react';
import { ForensicFile, ImageAnalysisData } from '../types/forensic';
import { api } from '../services/api';

interface TriViewModalProps {
  file: ForensicFile | null;
  onClose: () => void;
}

export const TriViewModal: React.FC<TriViewModalProps> = ({ file, onClose }) => {
  const [analysis, setAnalysis] = useState<ImageAnalysisData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'triview' | 'heatmap' | 'exif'>('triview');

  useEffect(() => {
    if (!file) return;
    setLoading(true);
    api.analyzeFile(file.case_id, file.id)
      .then(res => setAnalysis(res))
      .catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, [file]);

  if (!file) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="w-full max-w-6xl max-h-[92vh] bg-slate-900 border border-slate-700 rounded-xl flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Forensic Tri-View Visualizer: {file.original_filename}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  {file.true_file_type}
                </span>
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Side-by-side inspection of Original, Error Level Analysis (ELA), LSB bitplanes, and block entropy.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* View tabs */}
            <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs font-mono">
              <button
                onClick={() => setActiveTab('triview')}
                className={`px-3 py-1 rounded transition ${activeTab === 'triview' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
              >
                Tri-View Inspector
              </button>
              <button
                onClick={() => setActiveTab('heatmap')}
                className={`px-3 py-1 rounded transition ${activeTab === 'heatmap' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
              >
                Entropy Heatmap
              </button>
              <button
                onClick={() => setActiveTab('exif')}
                className={`px-3 py-1 rounded transition ${activeTab === 'exif' ? 'bg-cyan-500 text-black font-bold' : 'text-slate-400 hover:text-white'}`}
              >
                EXIF & Stego
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Caveat alert banner */}
        <div className="bg-cyan-950/30 border-b border-cyan-900/40 px-6 py-2 text-xs text-cyan-300 flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>
            <strong>Investigative Caveat:</strong> Error Level Analysis (ELA) and LSB bitplanes are heuristic visual indicators of resave compression histories and bitplane uniformity, not conclusive mathematical proof of tampering.
          </span>
        </div>

        {/* Body content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading ? (
            <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-400">
              <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
              <p className="text-sm font-mono">Computing ELA diffs, LSB bitplanes, and block entropy...</p>
            </div>
          ) : (
            <>
              {activeTab === 'triview' && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                  {/* Panel 1: Original Image */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 text-xs font-mono font-semibold text-slate-300 flex items-center justify-between">
                      <span>1. ORIGINAL ARTIFACT</span>
                      <span className="text-[10px] text-slate-400">Untrusted Input</span>
                    </div>
                    <div className="flex-1 p-3 flex items-center justify-center bg-black/40 min-h-[260px]">
                      {analysis?.visual_artifacts.original_path ? (
                        <img
                          src={analysis.visual_artifacts.original_path}
                          alt="Original"
                          className="max-h-[300px] object-contain rounded"
                        />
                      ) : (
                        <span className="text-xs text-slate-400">Original preview unavailable</span>
                      )}
                    </div>
                    <div className="p-3 bg-slate-900/60 text-xs text-slate-400 border-t border-slate-800">
                      Dimensions: {analysis?.metadata_blob.exif?.image_dimensions || 'N/A'}
                    </div>
                  </div>

                  {/* Panel 2: ELA (Error Level Analysis) */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 text-xs font-mono font-semibold text-cyan-300 flex items-center justify-between">
                      <span>2. ERROR LEVEL ANALYSIS (ELA)</span>
                      <span className="text-[10px] bg-cyan-950 text-cyan-400 px-1.5 py-0.5 rounded">95% Resave</span>
                    </div>
                    <div className="flex-1 p-3 flex items-center justify-center bg-black/40 min-h-[260px]">
                      {analysis?.visual_artifacts.ela_path ? (
                        <img
                          src={analysis.visual_artifacts.ela_path}
                          alt="ELA"
                          className="max-h-[300px] object-contain rounded"
                        />
                      ) : (
                        <span className="text-xs text-slate-400">ELA preview unavailable</span>
                      )}
                    </div>
                    <div className="p-3 bg-slate-900/60 text-xs text-slate-400 border-t border-slate-800">
                      Bright/contrasting edges highlight areas with differing compression histories (tampered regions).
                    </div>
                  </div>

                  {/* Panel 3: LSB Plane */}
                  <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                    <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 text-xs font-mono font-semibold text-purple-300 flex items-center justify-between">
                      <span>3. LSB BITPLANE (RGB BIT 0)</span>
                      <span className="text-[10px] bg-purple-950 text-purple-400 px-1.5 py-0.5 rounded">Stego Scan</span>
                    </div>
                    <div className="flex-1 p-3 flex items-center justify-center bg-black/40 min-h-[260px]">
                      {analysis?.visual_artifacts.lsb_path ? (
                        <img
                          src={analysis.visual_artifacts.lsb_path}
                          alt="LSB Plane"
                          className="max-h-[300px] object-contain rounded"
                        />
                      ) : (
                        <span className="text-xs text-slate-400">LSB preview unavailable</span>
                      )}
                    </div>
                    <div className="p-3 bg-slate-900/60 text-xs text-slate-400 border-t border-slate-800">
                      Renders lowest bit of each pixel. Uniform static or structural shapes expose hidden steganography.
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'heatmap' && (
                <div className="space-y-4">
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl">
                    <h3 className="text-sm font-bold text-slate-200 font-mono mb-2 flex items-center gap-2">
                      <Activity className="w-4 h-4 text-cyan-400" />
                      2D Block-Level Shannon Entropy Heatmap
                    </h3>
                    <p className="text-xs text-slate-400 mb-4">
                      Entropy measures data randomness (0.0 to 8.0 bits/byte). Blue represents low entropy (uniform structures), Green/Yellow indicates typical image bytes, and Red represents dense high-entropy blocks characteristic of compressed archives or encrypted shellcode payloads.
                    </p>

                    <div className="flex items-center justify-center p-4 bg-black/50 border border-slate-800 rounded-lg">
                      {analysis?.visual_artifacts.entropy_heatmap_path ? (
                        <img
                          src={analysis.visual_artifacts.entropy_heatmap_path}
                          alt="Entropy Heatmap"
                          className="max-h-[280px] w-full object-contain rounded border border-slate-800"
                        />
                      ) : (
                        <span className="text-xs text-slate-400">Heatmap unavailable</span>
                      )}
                    </div>

                    <div className="grid grid-cols-3 gap-4 mt-4 font-mono text-xs">
                      <div className="p-3 bg-slate-900 rounded-lg">
                        <span className="text-slate-400 block">Overall File Entropy:</span>
                        <span className="text-base font-bold text-cyan-300">
                          {analysis?.metadata_blob.entropy?.overall} bits/byte
                        </span>
                      </div>
                      <div className="p-3 bg-slate-900 rounded-lg">
                        <span className="text-slate-400 block">Peak Block Entropy:</span>
                        <span className="text-base font-bold text-orange-400">
                          {analysis?.metadata_blob.entropy?.max_block} bits/byte
                        </span>
                      </div>
                      <div className="p-3 bg-slate-900 rounded-lg">
                        <span className="text-slate-400 block">Minimum Block Entropy:</span>
                        <span className="text-base font-bold text-emerald-400">
                          {analysis?.metadata_blob.entropy?.min_block} bits/byte
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'exif' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5 font-mono text-xs">
                  {/* EXIF Metadata Card */}
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2.5">
                    <h3 className="font-bold text-slate-200 border-b border-slate-800 pb-2">
                      EXIF Camera & Capture Metadata
                    </h3>
                    <div className="space-y-1.5 text-slate-300">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Camera Make:</span>
                        <span>{analysis?.metadata_blob.exif?.make || 'None / Stripped'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Camera Model:</span>
                        <span>{analysis?.metadata_blob.exif?.model || 'None / Stripped'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Software Tag:</span>
                        <span className={analysis?.metadata_blob.exif?.software ? 'text-amber-400 font-bold' : ''}>
                          {analysis?.metadata_blob.exif?.software || 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">DateTimeOriginal:</span>
                        <span className="text-cyan-300">{analysis?.metadata_blob.exif?.date_time_original || 'None'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">DateTime (Modify):</span>
                        <span>{analysis?.metadata_blob.exif?.date_time_modify || 'None'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">GPS Coordinates:</span>
                        <span>
                          {analysis?.metadata_blob.exif?.gps_latitude 
                            ? `${analysis.metadata_blob.exif.gps_latitude}, ${analysis.metadata_blob.exif.gps_longitude}`
                            : 'None'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Stego Carved Signatures Card */}
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2.5">
                    <h3 className="font-bold text-slate-200 border-b border-slate-800 pb-2">
                      Carved Signatures & Hidden Data Indicators
                    </h3>
                    {analysis?.metadata_blob.stego?.carved_signatures?.length > 0 ? (
                      <div className="space-y-2">
                        {analysis.metadata_blob.stego.carved_signatures.map((s: any, idx: number) => (
                          <div key={idx} className="p-2.5 bg-rose-950/40 border border-rose-700/60 rounded text-rose-200">
                            <span className="font-bold block">{s.signature}</span>
                            <span className="text-[11px] text-slate-400">Offset: {s.offset.toLocaleString()} ({s.hex_offset})</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-slate-400 italic">No nested archive or executable signatures carved inside byte stream.</p>
                    )}

                    <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
                      LSB Chi2 Stat: {analysis?.metadata_blob.stego?.lsb_stats?.chi2_stat ?? 0.0} (p-val: {analysis?.metadata_blob.stego?.lsb_stats?.p_value?.toExponential(2) ?? '1.0'})
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
