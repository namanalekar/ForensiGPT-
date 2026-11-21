import React, { useState, useEffect } from 'react';
import { 
  Clock, 
  Sliders, 
  AlertTriangle, 
  ShieldAlert, 
  ChevronRight, 
  ExternalLink, 
  FileText, 
  RefreshCw,
  Terminal,
  ArrowRightLeft
} from 'lucide-react';
import { TimelineSyncData, CorrelatedEvent } from '../types/forensic';
import { api } from '../services/api';

interface TimelineSwimlaneProps {
  caseId: string;
  files: any[];
}

export const TimelineSwimlane: React.FC<TimelineSwimlaneProps> = ({ caseId, files }) => {
  const [anchorsList, setAnchorsList] = useState<any[]>([]);
  const [selectedAnchorFileId, setSelectedAnchorFileId] = useState<string>('');
  const [selectedAnchor, setSelectedAnchor] = useState<any>(null);
  const [windowSeconds, setWindowSeconds] = useState<number>(300);
  const [manualOffsetSeconds, setManualOffsetSeconds] = useState<number>(0);
  const [syncData, setSyncData] = useState<TimelineSyncData | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<CorrelatedEvent | null>(null);

  // Load anchors
  useEffect(() => {
    if (!caseId) return;
    api.getAnchors(caseId).then(res => {
      const filesWithAnchors = res.files || [];
      setAnchorsList(filesWithAnchors);
      // Pick first image or file with anchors by default
      const defaultFile = filesWithAnchors.find((f: any) => f.anchors && f.anchors.length > 0);
      if (defaultFile) {
        setSelectedAnchorFileId(defaultFile.file_id);
        setSelectedAnchor(defaultFile.anchors[0]);
      }
    }).catch(err => console.error(err));
  }, [caseId]);

  // Execute sync
  const triggerSync = (
    fileId: string = selectedAnchorFileId,
    anchor: any = selectedAnchor,
    winSec: number = windowSeconds,
    offsetSec: number = manualOffsetSeconds
  ) => {
    if (!fileId || !anchor) return;
    setLoading(true);
    api.syncTimeline(
      caseId,
      fileId,
      anchor.anchor_type,
      anchor.epoch,
      anchor.label,
      winSec,
      offsetSec
    ).then(data => {
      setSyncData(data);
      if (data.correlated_events.length > 0) {
        setSelectedEvent(data.correlated_events[0]);
      } else {
        setSelectedEvent(null);
      }
    }).catch(err => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (selectedAnchorFileId && selectedAnchor) {
      triggerSync(selectedAnchorFileId, selectedAnchor, windowSeconds, manualOffsetSeconds);
    }
  }, [selectedAnchorFileId, selectedAnchor]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
      {/* Header and Anchor Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2 font-mono">
            <Clock className="w-5 h-5 text-cyan-400" />
            ⭐ Image-to-Log Temporal Synchronization Engine
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-correlates file creation/modification anchors with system, auth, and network log streams.
          </p>
        </div>

        {/* Anchor selector */}
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs font-mono text-slate-400">Anchor Timestamp:</label>
          <select
            value={selectedAnchor ? `${selectedAnchorFileId}::${selectedAnchor.anchor_type}` : ''}
            onChange={(e) => {
              const [fId, aType] = e.target.value.split('::');
              const fGroup = anchorsList.find(f => f.file_id === fId);
              if (fGroup) {
                const aObj = fGroup.anchors.find((a: any) => a.anchor_type === aType);
                setSelectedAnchorFileId(fId);
                setSelectedAnchor(aObj);
              }
            }}
            className="bg-slate-950 border border-slate-700 text-xs text-cyan-300 font-mono rounded-lg px-3 py-1.5 focus:border-cyan-500 outline-none"
          >
            {anchorsList.map(f => (
              <optgroup key={f.file_id} label={f.filename}>
                {f.anchors.map((a: any) => (
                  <option key={a.anchor_type} value={`${f.file_id}::${a.anchor_type}`}>
                    {a.label} ({a.iso_timestamp})
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        </div>
      </div>

      {/* Sliders: Correlation Window & Manual Offset */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 p-4 bg-slate-950/60 border border-slate-800/80 rounded-xl">
        {/* Window Slider */}
        <div className="space-y-2">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-slate-300 flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              Correlation Window:
            </span>
            <span className="text-cyan-400 font-bold">
              ±{windowSeconds >= 60 ? `${(windowSeconds / 60).toFixed(1)} min` : `${windowSeconds}s`}
            </span>
          </div>
          <input
            type="range"
            min={30}
            max={7200}
            step={30}
            value={windowSeconds}
            onChange={(e) => {
              const val = Number(e.target.value);
              setWindowSeconds(val);
              triggerSync(selectedAnchorFileId, selectedAnchor, val, manualOffsetSeconds);
            }}
            className="w-full accent-cyan-400 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono text-slate-400">
            <span>30s</span>
            <span>5 min (default)</span>
            <span>30 min</span>
            <span>2 hours</span>
          </div>
        </div>

        {/* Manual Clock-Skew Offset Slider */}
        <div className="space-y-2">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-slate-300 flex items-center gap-1.5">
              <ArrowRightLeft className="w-3.5 h-3.5 text-amber-400" />
              Manual Time Offset (Clock Skew Adjust):
            </span>
            <span className="text-amber-400 font-bold">
              {manualOffsetSeconds >= 0 ? `+${manualOffsetSeconds}s` : `${manualOffsetSeconds}s`}
            </span>
          </div>
          <input
            type="range"
            min={-86400}
            max={86400}
            step={60}
            value={manualOffsetSeconds}
            onChange={(e) => {
              const val = Number(e.target.value);
              setManualOffsetSeconds(val);
              triggerSync(selectedAnchorFileId, selectedAnchor, windowSeconds, val);
            }}
            className="w-full accent-amber-400 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono text-slate-400">
            <span>-24h</span>
            <span>0s (synced)</span>
            <span>+24h</span>
          </div>
        </div>
      </div>

      {/* Clock Skew Warning Alert */}
      {syncData?.clock_skew_warning && (
        <div className="p-4 bg-amber-950/40 border border-amber-600/60 rounded-xl text-amber-200 text-xs flex items-start gap-3 animate-in fade-in">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-bold text-amber-300">Clock Skew / Desynchronization Alert</h4>
            <p className="leading-relaxed">{syncData.clock_skew_warning}</p>
            <p className="text-slate-400 text-[11px] pt-1">
              Tip: Use the Manual Time Offset slider above to align desynchronized system clocks.
            </p>
          </div>
        </div>
      )}

      {/* Before / After Highlighted Deltas */}
      {syncData && syncData.before_after_patterns.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-1.5">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            Detected Forensic Before / After Patterns:
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {syncData.before_after_patterns.map((p, idx) => (
              <div 
                key={idx} 
                className="p-3 bg-slate-950 border border-cyan-800/40 rounded-lg text-xs space-y-1 shadow-sm"
              >
                <div className="flex items-center justify-between font-mono text-[11px]">
                  <span className="text-cyan-400 font-bold">
                    {p.delta_seconds < 0 ? `${Math.abs(p.delta_seconds)}s BEFORE ANCHOR` : `${p.delta_seconds}s AFTER ANCHOR`}
                  </span>
                  <span className="text-slate-400">Relevance: {p.relevance}/100</span>
                </div>
                <p className="text-slate-200 leading-snug">{p.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Visual Swimlane Track */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <span>SYNCHRONIZATION TIMELINE SWIMLANE ({syncData?.correlated_events.length ?? 0} events in window)</span>
          <span>Window: {syncData?.swimlane?.window_start_iso?.slice(11, 19)} → {syncData?.swimlane?.window_end_iso?.slice(11, 19)} UTC</span>
        </div>

        {/* Anchor Card Indicator */}
        <div className="p-3 bg-cyan-950/20 border-2 border-cyan-500/50 rounded-lg flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-white font-bold">FILE ANCHOR:</span>
            <span className="text-cyan-300">{syncData?.swimlane?.anchor?.label}</span>
          </div>
          <span className="text-slate-400">{syncData?.swimlane?.anchor?.effective_iso}</span>
        </div>

        {/* Event List / Swimlane items */}
        {loading ? (
          <div className="py-12 flex justify-center text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
          </div>
        ) : syncData?.correlated_events.length === 0 ? (
          <div className="p-8 text-center text-slate-400 border border-slate-800 rounded-xl bg-slate-950/30 text-xs font-mono">
            No log events fall inside this correlation window (±{windowSeconds}s).
            <br />Expand the slider above or adjust the clock skew offset.
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Left 2 Cols: Events Swimlane list */}
            <div className="lg:col-span-2 space-y-2 max-h-[420px] overflow-y-auto pr-1">
              {syncData?.correlated_events.map((ev) => (
                <div
                  key={ev.id}
                  onClick={() => setSelectedEvent(ev)}
                  className={`p-3 rounded-lg border transition cursor-pointer font-mono text-xs ${
                    selectedEvent?.id === ev.id
                      ? 'bg-cyan-950/40 border-cyan-500 shadow-md'
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-cyan-400 font-semibold">{ev.delta_desc}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      ev.normalized_type.includes('brute') || ev.normalized_type.includes('privilege')
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : ev.normalized_type.includes('success')
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : 'bg-slate-900 text-slate-400'
                    }`}>
                      {ev.normalized_type.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-slate-200 truncate">{ev.process}: {ev.message}</p>
                </div>
              ))}
            </div>

            {/* Right 1 Col: Raw Line Inspector */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-4 font-mono text-xs">
              {selectedEvent ? (
                <div className="space-y-3 overflow-y-auto">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-slate-200 flex items-center gap-1.5">
                      <Terminal className="w-4 h-4 text-cyan-400" />
                      Raw Event Inspector
                    </span>
                    <span className="text-slate-400">Line #{selectedEvent.line_number}</span>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Raw Log Entry:</span>
                    <div className="p-2.5 bg-black/60 rounded border border-slate-800 text-slate-300 break-all leading-relaxed text-[11px]">
                      {selectedEvent.raw_line}
                    </div>
                  </div>

                  {selectedEvent.iocs.length > 0 && (
                    <div>
                      <span className="text-slate-400 block text-[11px] mb-1">Extracted IOCs (Defanged):</span>
                      <div className="space-y-1">
                        {selectedEvent.iocs.map((ioc, i) => (
                          <span key={i} className="inline-block mr-1.5 mb-1 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px]">
                            {ioc.type.toUpperCase()}: {ioc.defanged}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedEvent.mitre_tags.length > 0 && (
                    <div>
                      <span className="text-slate-400 block text-[11px] mb-1">MITRE ATT&CK Mapping:</span>
                      <div className="space-y-1">
                        {selectedEvent.mitre_tags.map((m, i) => (
                          <a
                            key={i}
                            href={m.url}
                            target="_blank"
                            rel="noreferrer"
                            className="flex items-center justify-between p-1.5 rounded bg-purple-950/40 border border-purple-800/60 text-purple-200 hover:text-white transition text-[11px]"
                          >
                            <span>{m.id}: {m.name}</span>
                            <ExternalLink className="w-3 h-3 text-purple-400" />
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="py-20 text-center text-slate-400 italic">
                  Click any event in the swimlane to inspect its raw log line and extracted IOCs.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
