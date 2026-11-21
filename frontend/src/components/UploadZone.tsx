import React, { useState, useRef } from 'react';
import { Upload, FileText, Image as ImageIcon, FileCode, AlertCircle, Loader2 } from 'lucide-react';

interface UploadZoneProps {
  onUpload: (files: File[]) => Promise<void>;
  isUploading: boolean;
}

export const UploadZone: React.FC<UploadZoneProps> = ({ onUpload, isUploading }) => {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length > 0) {
      await onUpload(droppedFiles);
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selected = Array.from(e.target.files);
      await onUpload(selected);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
        isDragging
          ? 'border-cyan-400 bg-cyan-950/20 scale-[1.01]'
          : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'
      }`}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={handleFileSelect}
        className="hidden"
        id="forensic-file-input"
      />

      <div className="flex flex-col items-center justify-center space-y-3">
        <div className="p-3.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
          {isUploading ? (
            <Loader2 className="w-8 h-8 animate-spin" />
          ) : (
            <Upload className="w-8 h-8" />
          )}
        </div>

        <div>
          <h2 className="text-base font-semibold text-slate-100">
            {isUploading ? 'Ingesting & Hashing Files...' : 'Drag and drop suspicious files for forensic triage'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic magic byte verification, cryptographic chain of custody, and unverified threat detection.
          </p>
        </div>

        <button
          disabled={isUploading}
          onClick={() => fileInputRef.current?.click()}
          className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-semibold text-xs tracking-wide shadow-md shadow-cyan-500/20 transition disabled:opacity-50"
        >
          Select Files (Multi-Select)
        </button>

        {/* Supported badges */}
        <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
            <ImageIcon className="w-3 h-3 text-cyan-400" />
            Images (JPG, PNG, GIF, BMP, WebP, TIFF)
          </span>
          <span className="flex items-center gap-1 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
            <FileCode className="w-3 h-3 text-emerald-400" />
            Logs (auth.log, syslog, web access, WinEvent)
          </span>
          <span className="flex items-center gap-1 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
            <FileText className="w-3 h-3 text-purple-400" />
            PDFs & Misc Files
          </span>
          <span className="flex items-center gap-1 text-slate-400">
            Max 25 MB per file
          </span>
        </div>
      </div>
    </div>
  );
};
