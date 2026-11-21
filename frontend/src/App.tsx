import React, { useState, useEffect } from 'react';
import { 
  FolderPlus, 
  Layers, 
  Clock, 
  FileText, 
  AlertTriangle, 
  ShieldCheck, 
  RefreshCw, 
  Trash2,
  FolderOpen
} from 'lucide-react';
import { 
  CaseData, 
  ForensicFile, 
  UnverifiedModalData, 
  ForensicReport 
} from './types/forensic';
import { api } from './services/api';
import { Header } from './components/Header';
import { UploadZone } from './components/UploadZone';
import { FileCard } from './components/FileCard';
import { UnverifiedModal } from './components/UnverifiedModal';
import { TriViewModal } from './components/TriViewModal';
import { TimelineSwimlane } from './components/TimelineSwimlane';
import { RedactionModal } from './components/RedactionModal';
import { ReportView } from './components/ReportView';
import { ChatDrawer } from './components/ChatDrawer';
import { CompareModal } from './components/CompareModal';
import { SafeHandlingModal } from './components/SafeHandlingModal';

export const App: React.FC = () => {
  const [cases, setCases] = useState<CaseData[]>([]);
  const [activeCase, setActiveCase] = useState<CaseData | null>(null);
  const [loadingCases, setLoadingCases] = useState<boolean>(true);
  const [privacyMode, setPrivacyMode] = useState<boolean>(false);
  const [geminiModel, setGeminiModel] = useState<string>('gemini-2.5-flash');

  // Active view tab: 'files' | 'timeline' | 'report'
  const [activeTab, setActiveTab] = useState<'files' | 'timeline' | 'report'>('files');

  // Uploading state
  const [isUploading, setIsUploading] = useState<boolean>(false);

  // Unverified Popup state
  const [pendingPopup, setPendingPopup] = useState<UnverifiedModalData | null>(null);
  const [unverifiedFileId, setUnverifiedFileId] = useState<string | null>(null);

  // Modals state
  const [triViewFile, setTriViewFile] = useState<ForensicFile | null>(null);
  const [isRedactionOpen, setIsRedactionOpen] = useState<boolean>(false);
  const [isChatOpen, setIsChatOpen] = useState<boolean>(false);
  const [isCompareOpen, setIsCompareOpen] = useState<boolean>(false);
  const [isSafeGuideOpen, setIsSafeGuideOpen] = useState<boolean>(false);

  // Report state
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [reportModel, setReportModel] = useState<string>('');
  const [reportPrivacy, setReportPrivacy] = useState<boolean>(false);
  const [explanationMode, setExplanationMode] = useState<'eli5' | 'analyst' | 'expert'>('analyst');
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);

  // Load cases and settings
  const loadInitialData = async () => {
    try {
      const settings = await api.getSettings();
      setGeminiModel(settings.gemini_model);
      setPrivacyMode(settings.privacy_mode_default);

      const caseList = await api.listCases();
      setCases(caseList);

      if (caseList.length > 0) {
        const fullCase = await api.getCase(caseList[0].id);
        setActiveCase(fullCase);
      } else {
        // Create initial default case
        const newCase = await api.createCase("Incident Alpha-01", "Primary DFIR triage workspace");
        setActiveCase(newCase);
        setCases([newCase]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingCases(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // Refresh active case files
  const refreshActiveCase = async () => {
    if (!activeCase) return;
    try {
      const updated = await api.getCase(activeCase.id);
      setActiveCase(updated);
    } catch (err) {
      console.error(err);
    }
  };

  // Upload handler
  const handleUpload = async (files: File[]) => {
    if (!activeCase) return;
    setIsUploading(true);
    try {
      const res = await api.uploadFiles(activeCase.id, files);
      await refreshActiveCase();

      // Check if any file triggered unverified/miscellaneous popup
      if (res.popup_required_files && res.popup_required_files.length > 0) {
        setPendingPopup(res.popup_required_files[0]);
        const matched = res.uploaded_files.find(f => f.unverified_popup !== null);
        if (matched) setUnverifiedFileId(matched.id);
      }
    } catch (err: any) {
      alert(`Upload error: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  // Unverified popup actions
  const handleConfirmUnverified = () => {
    setPendingPopup(null);
    setUnverifiedFileId(null);
  };

  const handleCancelDeleteUnverified = async () => {
    if (activeCase && unverifiedFileId) {
      await api.deleteFile(activeCase.id, unverifiedFileId);
      await refreshActiveCase();
    }
    setPendingPopup(null);
    setUnverifiedFileId(null);
  };

  // Delete file
  const handleDeleteFile = async (fileId: string) => {
    if (!activeCase) return;
    await api.deleteFile(activeCase.id, fileId);
    await refreshActiveCase();
  };

  // Create new case
  const handleCreateCase = async () => {
    const title = prompt("Enter Case Name / Reference:", `Incident-${Date.now().toString().slice(-4)}`);
    if (!title) return;
    const created = await api.createCase(title);
    setCases(prev => [created, ...prev]);
    setActiveCase(created);
    setReport(null);
  };

  // Purge all data handler
  const handlePurgeAll = async () => {
    if (!confirm("WARNING: This will permanently delete all uploaded files, reports, and database records. Proceed?")) return;
    await api.purgeAllData();
    window.location.reload();
  };

  // Generate report
  const handleGenerateReport = async () => {
    if (!activeCase) return;
    setIsGeneratingReport(true);
    try {
      const res = await api.generateReport(activeCase.id, explanationMode, privacyMode);
      setReport(res.report);
      setReportModel(res.model_used);
      setReportPrivacy(privacyMode);
      setActiveTab('report');
    } catch (err: any) {
      alert(`Report Generation Error: ${err.message}`);
    } finally {
      setIsGeneratingReport(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#090D16] text-slate-100 font-sans">
      {/* Header */}
      <Header
        privacyMode={privacyMode}
        onTogglePrivacy={() => setPrivacyMode(!privacyMode)}
        geminiModel={geminiModel}
        onOpenSettings={() => {}}
        onOpenSafeGuide={() => setIsSafeGuideOpen(true)}
        onOpenCompare={() => setIsCompareOpen(true)}
        onPurgeData={handlePurgeAll}
      />

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Case Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400">
              <FolderOpen className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400 font-mono uppercase tracking-wider">Active Workspace:</span>
                <select
                  value={activeCase?.id || ''}
                  onChange={(e) => {
                    const c = cases.find(item => item.id === e.target.value);
                    if (c) {
                      api.getCase(c.id).then(full => {
                        setActiveCase(full);
                        setReport(null);
                      });
                    }
                  }}
                  className="bg-slate-950 border border-slate-700 text-xs font-mono font-bold text-slate-200 px-3 py-1 rounded outline-none focus:border-cyan-500"
                >
                  {cases.map(c => (
                    <option key={c.id} value={c.id}>{c.title}</option>
                  ))}
                </select>
              </div>
              <span className="text-xs text-slate-400 font-mono block mt-0.5">
                {activeCase?.files.length ?? 0} files ingested | Chain of Custody active
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleCreateCase}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs flex items-center gap-1.5 transition font-mono"
            >
              <FolderPlus className="w-3.5 h-3.5 text-cyan-400" />
              New Case
            </button>

            {/* Synthesize Report Button */}
            <button
              onClick={() => {
                if (privacyMode) {
                  handleGenerateReport();
                } else {
                  setIsRedactionOpen(true);
                }
              }}
              disabled={isGeneratingReport || !activeCase || activeCase.files.length === 0}
              className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition disabled:opacity-40"
            >
              <FileText className="w-3.5 h-3.5" />
              {isGeneratingReport ? 'Generating...' : 'Synthesize Forensic Dossier'}
            </button>
          </div>
        </div>

        {/* View Navigation Tabs */}
        <div className="flex border-b border-slate-800 space-x-6 text-xs font-mono">
          <button
            onClick={() => setActiveTab('files')}
            className={`pb-3 flex items-center gap-2 font-semibold transition border-b-2 ${
              activeTab === 'files'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            Case Artifacts & Triage ({activeCase?.files.length ?? 0})
          </button>

          <button
            onClick={() => setActiveTab('timeline')}
            className={`pb-3 flex items-center gap-2 font-semibold transition border-b-2 ${
              activeTab === 'timeline'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-4 h-4" />
            ⭐ Image-to-Log Synchronization
          </button>

          <button
            onClick={() => setActiveTab('report')}
            className={`pb-3 flex items-center gap-2 font-semibold transition border-b-2 ${
              activeTab === 'report'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            Incident Report & Exports
          </button>
        </div>

        {/* Tab 1: Files & Triage */}
        {activeTab === 'files' && (
          <div className="space-y-6">
            <UploadZone onUpload={handleUpload} isUploading={isUploading} />

            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>INGESTED EVIDENCE ARTIFACTS</span>
                <span>Sorted by upload timestamp</span>
              </div>

              {activeCase?.files.length === 0 ? (
                <div className="p-12 text-center text-slate-400 border border-slate-800 rounded-xl bg-slate-950/20 text-xs font-mono">
                  No files ingested yet. Drag and drop suspicious images, auth.log, syslog, or PDFs above.
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-4">
                  {activeCase?.files.map(f => (
                    <FileCard
                      key={f.id}
                      file={f}
                      onAnalyze={async (file) => {
                        await api.analyzeFile(activeCase.id, file.id);
                        await refreshActiveCase();
                        if (file.detected_category === 'image') {
                          setTriViewFile(file);
                        } else {
                          alert(`Completed deep parsing for ${file.original_filename}. Inspect results in timeline or report.`);
                        }
                      }}
                      onViewTriView={(file) => setTriViewFile(file)}
                      onCorrelate={(file) => setActiveTab('timeline')}
                      onDelete={handleDeleteFile}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Timeline Swimlane */}
        {activeTab === 'timeline' && activeCase && (
          <TimelineSwimlane caseId={activeCase.id} files={activeCase.files} />
        )}

        {/* Tab 3: Report & Exports */}
        {activeTab === 'report' && activeCase && (
          <ReportView
            caseId={activeCase.id}
            report={report}
            modelUsed={reportModel}
            privacyActive={reportPrivacy}
            onSwitchMode={async (mode) => {
              setExplanationMode(mode);
              setIsGeneratingReport(true);
              try {
                const res = await api.generateReport(activeCase.id, mode, privacyMode);
                setReport(res.report);
                setReportModel(res.model_used);
              } catch (err: any) {
                alert(`Error: ${err.message}`);
              } finally {
                setIsGeneratingReport(false);
              }
            }}
            currentMode={explanationMode}
            onOpenChat={() => setIsChatOpen(true)}
            isGenerating={isGeneratingReport}
          />
        )}
      </main>

      {/* Required Unverified / Misc File Modal */}
      <UnverifiedModal
        popupData={pendingPopup}
        onConfirm={handleConfirmUnverified}
        onCancelDelete={handleCancelDeleteUnverified}
      />

      {/* Tri-View Modal */}
      <TriViewModal
        file={triViewFile}
        onClose={() => setTriViewFile(null)}
      />

      {/* Pre-Flight Redaction Modal */}
      {activeCase && (
        <RedactionModal
          caseId={activeCase.id}
          isOpen={isRedactionOpen}
          onClose={() => setIsRedactionOpen(false)}
          onProceed={handleGenerateReport}
        />
      )}

      {/* Chat Drawer */}
      {activeCase && (
        <ChatDrawer
          caseId={activeCase.id}
          isOpen={isChatOpen}
          onClose={() => setIsChatOpen(false)}
        />
      )}

      {/* Compare Modal */}
      {activeCase && (
        <CompareModal
          caseId={activeCase.id}
          files={activeCase.files}
          isOpen={isCompareOpen}
          onClose={() => setIsCompareOpen(false)}
        />
      )}

      {/* Safe Handling Guide Modal */}
      <SafeHandlingModal
        isOpen={isSafeGuideOpen}
        onClose={() => setIsSafeGuideOpen(false)}
      />
    </div>
  );
};

export default App;
