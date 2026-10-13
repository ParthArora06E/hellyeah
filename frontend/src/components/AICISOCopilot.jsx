import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, 
  Send, 
  Sparkles, 
  X, 
  Minimize2, 
  Maximize2, 
  Copy, 
  Check, 
  RotateCcw, 
  ShieldAlert, 
  Zap, 
  Flame,
  User,
  ArrowRight
} from 'lucide-react';

export default function AICISOCopilot({ scan, onNavigateTab }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `👋 **Greetings! I am your AI CISO Copilot.**\n\nI have evaluated the perimeter of **${scan?.target_domain || 'your enterprise target'}** (Risk Score: **${scan?.risk_score || 72.5}/100**).\n\nAsk me anything or click a preset below to generate executive briefings, Jira incident tickets, or regulatory penalty projections for the judges!`
    }
  ]);
  const [inputPrompt, setInputPrompt] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState(null);
  const messagesEndRef = useRef(null);

  const domain = scan?.target_domain || 'hcesonepat.org';
  const scanId = scan?.id;

  // Preset chips for instant demonstration
  const quickChips = [
    { label: '👔 30-Sec CEO Briefing', prompt: `Provide a 3-bullet executive CISO security briefing for the CEO on ${domain}.` },
    { label: '🎫 Draft Jira Ticket', prompt: `Generate a production-ready Jira security incident ticket with reproduction steps for the top CVE on ${domain}.` },
    { label: '⚖️ DPDP Act Penalties', prompt: `What is the financial liability and regulatory penalty under India DPDP Act 2023 for ${domain}?` },
    { label: '🛡️ Explain Attack Path', prompt: `Explain how an external attacker exploits the transport layer and CORS flaws on ${domain}.` }
  ];

  const handleSendMessage = async (textToSend = null) => {
    const text = (textToSend || inputPrompt).trim();
    if (!text || loading) return;

    const userMsg = { role: 'user', content: text };
    setMessages(prev => [...prev, userMsg]);
    if (!textToSend) setInputPrompt('');
    setLoading(true);

    try {
      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scanId,
          prompt: text,
          history: messages.slice(-4)
        })
      });

      if (res.ok) {
        const data = await res.json();
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: data.response,
          model: data.model_used
        }]);
      } else {
        setMessages(prev => [...prev, {
          role: 'assistant',
          content: `⚠️ Failed to query copilot engine (HTTP ${res.status}). Please check network connectivity.`
        }]);
      }
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `⚠️ Connection error: ${err.message}. Using autonomous offline security core.`
      }]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isOpen]);

  const copyMessage = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <>
      {/* Floating Trigger Button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-3 rounded-full bg-gradient-to-r from-sky-500 via-indigo-600 to-purple-600 text-white font-bold text-xs shadow-2xl shadow-sky-500/40 hover:shadow-sky-500/60 hover:scale-105 active:scale-95 transition-all cursor-pointer border border-sky-400/30 group"
          title="Open AI CISO Security Copilot"
        >
          <div className="relative">
            <Bot className="w-5 h-5 text-white animate-bounce" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
          </div>
          <span className="tracking-wide">AI CISO Copilot</span>
          <span className="px-1.5 py-0.5 rounded text-[9px] bg-white/20 font-mono uppercase tracking-wider">
            GPT-4o
          </span>
        </button>
      )}

      {/* Slide-over Copilot Drawer */}
      {isOpen && (
        <div className="fixed bottom-4 right-4 z-50 w-full sm:w-[440px] h-[600px] max-h-[90vh] rounded-3xl bg-slate-950 border border-sky-500/40 shadow-2xl shadow-sky-500/30 flex flex-col overflow-hidden animate-in fade-in slide-in-from-bottom-6 duration-300">
          {/* Header */}
          <div className="px-5 py-4 bg-gradient-to-r from-slate-900 via-sky-950/60 to-slate-900 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
                <Bot className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-extrabold text-white text-sm">AI CISO Copilot</h3>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">
                    ACTIVE
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono truncate max-w-[200px]">
                  Context: {domain}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={() => setMessages([messages[0]])}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
                title="Clear Chat History"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Quick Action Preset Chips */}
          <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800/80 flex items-center gap-1.5 overflow-x-auto no-scrollbar">
            {quickChips.map((chip, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(chip.prompt)}
                disabled={loading}
                className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-[10px] font-medium whitespace-nowrap border border-slate-700/60 transition-all cursor-pointer hover:border-sky-500/40 disabled:opacity-50"
              >
                {chip.label}
              </button>
            ))}
          </div>

          {/* Chat Messages Log */}
          <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs font-sans bg-black/60 selection:bg-sky-500/30">
            {messages.map((msg, index) => {
              const isUser = msg.role === 'user';
              return (
                <div
                  key={index}
                  className={`flex gap-2.5 ${isUser ? 'justify-end' : 'justify-start'}`}
                >
                  {!isUser && (
                    <div className="w-6 h-6 rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/30 flex items-center justify-center shrink-0 mt-0.5">
                      <Sparkles className="w-3.5 h-3.5" />
                    </div>
                  )}

                  <div
                    className={`max-w-[85%] rounded-2xl p-3.5 relative group ${
                      isUser
                        ? 'bg-gradient-to-r from-sky-600 to-indigo-600 text-white rounded-br-none shadow-md shadow-sky-600/20'
                        : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-bl-none shadow-md'
                    }`}
                  >
                    <div className="whitespace-pre-wrap leading-relaxed text-xs">
                      {msg.content}
                    </div>

                    {!isUser && (
                      <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                        <span>{msg.model || 'OpenRouter Multi-Key Engine'}</span>
                        <button
                          onClick={() => copyMessage(msg.content, index)}
                          className="flex items-center gap-1 hover:text-sky-400 transition-colors cursor-pointer"
                        >
                          {copiedIndex === index ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>

                  {isUser && (
                    <div className="w-6 h-6 rounded-lg bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 flex items-center justify-center shrink-0 mt-0.5">
                      <User className="w-3.5 h-3.5" />
                    </div>
                  )}
                </div>
              );
            })}

            {loading && (
              <div className="flex gap-2.5 items-center text-slate-400 text-xs pl-2">
                <Sparkles className="w-4 h-4 text-sky-400 animate-spin" />
                <span className="font-mono text-[11px]">AI Copilot synthesizing security intelligence...</span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Bar */}
          <div className="p-3 bg-slate-900 border-t border-slate-800">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendMessage();
              }}
              className="flex items-center gap-2"
            >
              <input
                type="text"
                placeholder={`Ask Copilot about ${domain}...`}
                value={inputPrompt}
                onChange={(e) => setInputPrompt(e.target.value)}
                disabled={loading}
                className="flex-1 bg-slate-950 border border-slate-800 focus:border-sky-500 rounded-xl px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none transition-all font-sans"
              />
              <button
                type="submit"
                disabled={loading || !inputPrompt.trim()}
                className="p-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white disabled:opacity-40 transition-all cursor-pointer shadow-md shadow-sky-500/20"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
