import React, { useState, useEffect, useRef } from 'react';
import { X, Send, MessageSquare, Bot, User, RefreshCw, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';

interface ChatDrawerProps {
  caseId: string;
  isOpen: boolean;
  onClose: () => void;
}

export const ChatDrawer: React.FC<ChatDrawerProps> = ({ caseId, isOpen, onClose }) => {
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen || !caseId) return;
    api.getChatHistory(caseId).then(res => {
      setMessages(res.messages || []);
    }).catch(err => console.error(err));
  }, [isOpen, caseId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userText = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userText, created_at: new Date().toISOString() }]);
    setLoading(true);

    try {
      const resp = await api.askChat(caseId, userText);
      setMessages(prev => [...prev, resp]);
    } catch (err: any) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Error querying evidence: ${err.message || 'Server error'}`,
        evidence_citations: []
      }]);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-md bg-slate-900 border-l border-slate-800 shadow-2xl z-50 flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <MessageSquare className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white font-mono">Ask the Evidence</h3>
            <p className="text-[11px] text-slate-400 font-mono">Strictly grounded in case findings</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white transition">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Grounding directive banner */}
      <div className="px-4 py-2 bg-cyan-950/30 border-b border-cyan-900/30 text-[11px] text-cyan-300 font-mono flex items-center gap-2">
        <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
        <span>Answers are strictly restricted to stored evidence JSON.</span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
        {messages.length === 0 ? (
          <div className="py-20 text-center text-slate-400 italic">
            Ask any question about hashes, EXIF anomalies, log correlation windows, or attack indicators.
          </div>
        ) : (
          messages.map((m, idx) => (
            <div
              key={idx}
              className={`flex gap-2.5 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {m.role !== 'user' && (
                <div className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center shrink-0 mt-0.5">
                  <Bot className="w-3.5 h-3.5" />
                </div>
              )}
              <div
                className={`p-3 rounded-xl max-w-[85%] leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-cyan-500 text-black font-semibold'
                    : 'bg-slate-950 border border-slate-800 text-slate-200'
                }`}
              >
                <p className="whitespace-pre-wrap">{m.content}</p>
                {m.evidence_citations && m.evidence_citations.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-slate-800 flex flex-wrap gap-1">
                    {m.evidence_citations.map((c: string, ci: number) => (
                      <span key={ci} className="px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-700 text-cyan-300 text-[10px]">
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))
        )}
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 text-xs py-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Consulting evidence store...</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input Form */}
      <form onSubmit={handleSend} className="p-3 border-t border-slate-800 bg-slate-950/80 flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about timestamps, SSH IPs, or EXIF..."
          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 outline-none font-mono"
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="px-3 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs disabled:opacity-40 transition"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
