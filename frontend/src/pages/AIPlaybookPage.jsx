import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  Crown, 
  FileDown, 
  Copy, 
  Check, 
  Lock, 
  ShieldAlert, 
  Terminal, 
  Code, 
  RotateCcw, 
  Search, 
  Filter, 
  CheckCircle2, 
  ExternalLink,
  Zap,
  Clock,
  ArrowRight
} from 'lucide-react';

export default function AIPlaybookPage({ scan, user, token, onSwitchToPro, onUpgradeToPro }) {
  const [playbookData, setPlaybookData] = useState(null);
  const [previewData, setPreviewData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isProLocked, setIsProLocked] = useState(user?.role !== 'pro');

  const scanId = scan?.id;

  useEffect(() => {
    setIsProLocked(user?.role !== 'pro');
  }, [user?.role]);

  const fetchPlaybook = async () => {
    if (!scanId) return;
    setLoading(true);
    try {
      const headers = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const params = new URLSearchParams();
      if (user?.role) params.set('role', user.role);
      if (token) params.set('token', token);

      const res = await fetch(`/api/scans/${scanId}/ai-playbook?${params.toString()}`, { headers });
      if (res.status === 403) {
        setIsProLocked(true);
        // Fetch public preview teaser
        const prevRes = await fetch(`/api/scans/${scanId}/ai-playbook/preview`);
        if (prevRes.ok) {
          const prevJson = await prevRes.json();
          setPreviewData(prevJson);
        }
      } else if (res.ok) {
        const data = await res.json();
        setPlaybookData(data);
        setIsProLocked(false);
      }
    } catch (err) {
      console.error('Error fetching AI Playbook:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPlaybook();
  }, [scanId, user?.role, token]);

  const handleDownloadPdf = async () => {
    if (!scanId) return;
    setDownloadingPdf(true);
    try {
      const headers = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const params = new URLSearchParams();
      if (user?.role) params.set('role', user.role);
      if (token) params.set('token', token);

      const res = await fetch(`/api/scans/${scanId}/ai-playbook/pdf?${params.toString()}`, { headers });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `AI_Patch_Playbook_${scan?.target_domain || 'target'}_${scanId.slice(0, 8)}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else if (res.status === 403) {
        alert('Pro Subscription required to download the AI Patch Playbook PDF.');
      }
    } catch (err) {
      console.error('Download error:', err);
    } finally {
      setDownloadingPdf(false);
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Severity color maps
  const getSevBadge = (sev) => {
    switch (sev) {
      case 'Critical':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
      case 'High':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'Medium':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      default:
        return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
    }
  };

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8 bg-slate-900/40 border border-slate-800 rounded-2xl">
        <Sparkles className="w-12 h-12 text-slate-600 mb-3" />
        <h3 className="text-lg font-semibold text-slate-300">No Target Scan Selected</h3>
        <p className="text-sm text-slate-500 max-w-md mt-1">
          Select or launch a scan from the top navbar to view or generate autonomous AI remediation playbooks.
        </p>
      </div>
    );
  }

  // --- STANDARD USER: PAYWALL & TEASER VIEW ---
  if (isProLocked || user?.role !== 'pro') {
    return (
      <div className="space-y-6">
        {/* Paywall Hero Banner */}
        <div className="relative overflow-hidden rounded-2xl border border-amber-500/30 bg-gradient-to-br from-slate-900 via-amber-950/20 to-slate-900 p-8 shadow-2xl">
          <div className="absolute top-0 right-0 w-96 h-96 bg-amber-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 relative z-10">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 mb-3">
                <Crown className="w-3.5 h-3.5 text-amber-400" />
                <span>PRO TIER SUBSCRIPTION REQUIRED</span>
              </div>
              <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
                Autonomous AI Remediation Playbook
              </h1>
              <p className="text-sm text-slate-400 mt-2 max-w-2xl leading-relaxed">
                You are currently signed in as a <span className="text-slate-200 font-semibold">Standard User</span> ({user?.email || 'user@hackingly.io'}).
                Autonomous unified git diffs, shell execution scripts, verification curl tests, and publication-grade analytical PDF playbooks are exclusively unlocked for <span className="text-amber-400 font-semibold">Pro Subscribers</span>.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
              <button
                onClick={onSwitchToPro}
                className="px-5 py-3 rounded-xl bg-gradient-to-r from-amber-500 via-orange-500 to-amber-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 font-bold text-sm shadow-lg shadow-amber-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <Crown className="w-4 h-4" />
                <span>Switch to Pro Account</span>
              </button>
              <button
                onClick={onUpgradeToPro}
                className="px-5 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-sm border border-slate-700 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Upgrade Current Account</span>
              </button>
            </div>
          </div>

          {/* Quick Demo Credentials Info */}
          <div className="mt-6 pt-6 border-t border-slate-800/80 flex flex-wrap items-center gap-4 text-xs text-slate-400">
            <span className="font-semibold text-slate-300">Default Demo Credentials:</span>
            <div className="flex items-center gap-2 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 font-mono text-[11px]">
              <span className="text-amber-400 font-bold">Pro:</span> pro@hackingly.io / Pro@123456
            </div>
            <div className="flex items-center gap-2 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 font-mono text-[11px]">
              <span className="text-sky-400 font-bold">Standard:</span> user@hackingly.io / User@123456
            </div>
          </div>
        </div>

        {/* Feature Comparison Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-slate-200">Standard Plan (Current)</h3>
              <span className="text-xs px-2.5 py-1 rounded-md bg-slate-800 text-slate-400 font-medium">Free / Standard</span>
            </div>
            <ul className="space-y-3 text-xs text-slate-400">
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>External Attack Surface Discovery & CVE scanning</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Financial Cost-of-Risk & Breach Modeling</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Standard Executive CSV and XLSX Exports</span>
              </li>
              <li className="flex items-center gap-2.5 text-slate-600 line-through">
                <Lock className="w-4 h-4 text-slate-600 shrink-0" />
                <span>Unified Git Diffs for Nginx, Apache & Applications</span>
              </li>
              <li className="flex items-center gap-2.5 text-slate-600 line-through">
                <Lock className="w-4 h-4 text-slate-600 shrink-0" />
                <span>Automated Bash Terminal CLI Execution Scripts</span>
              </li>
              <li className="flex items-center gap-2.5 text-slate-600 line-through">
                <Lock className="w-4 h-4 text-slate-600 shrink-0" />
                <span>Analytical AI Patch Playbook PDF Blueprint</span>
              </li>
            </ul>
          </div>

          <div className="p-6 rounded-2xl bg-gradient-to-b from-sky-950/30 to-indigo-950/20 border border-sky-500/30 space-y-4 relative">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-sky-200 flex items-center gap-2">
                <Crown className="w-4 h-4 text-amber-400" />
                <span>Pro Tier (Recommended)</span>
              </h3>
              <span className="text-xs px-2.5 py-1 rounded-md bg-sky-500/20 text-sky-300 font-bold border border-sky-500/30">
                Full Access
              </span>
            </div>
            <ul className="space-y-3 text-xs text-slate-300">
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
                <span><b>100% Executable Code Patches:</b> Unified git diffs for web servers and apps</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
                <span><b>Copy-Paste Terminal Commands:</b> Safe Linux CLI deployment scripts</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
                <span><b>Automated Verification:</b> Zero-trust curl validation test suites</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
                <span><b>Rollback Safeguards:</b> Immediate emergency reversal instructions</span>
              </li>
              <li className="flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0" />
                <span><b>Publication-Grade Analytical PDF:</b> Formal signed remediation blueprint</span>
              </li>
            </ul>
            <button
              onClick={onSwitchToPro}
              className="w-full mt-2 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-xs transition-all flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-sky-500/20"
            >
              <span>Unlock Pro Features Instantly</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Locked Sample Teaser */}
        <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-200">
                {previewData?.total_available_patches || scan.total_findings || 5} Patches Ready for {scan.target_domain}
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Sample preview of autonomous patch blueprint waiting to be unlocked.
              </p>
            </div>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30">
              {previewData?.critical_patches || 1} Critical Patches
            </span>
          </div>

          <div className="relative rounded-xl border border-slate-800 bg-slate-950 p-5 overflow-hidden">
            <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-[3px] flex flex-col items-center justify-center z-20">
              <Lock className="w-8 h-8 text-amber-400 mb-2" />
              <p className="text-sm font-semibold text-white">Full Playbook Diff Locked</p>
              <p className="text-xs text-slate-400 mt-1 mb-3">Switch to Pro account to inspect unified diff and terminal commands</p>
              <button
                onClick={onSwitchToPro}
                className="px-4 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-all"
              >
                Switch to Pro Account
              </button>
            </div>

            <div className="filter blur-sm select-none font-mono text-xs text-slate-400 space-y-2">
              <p className="text-sky-400 font-bold">--- /etc/nginx/conf.d/ssl_security.conf.orig</p>
              <p className="text-emerald-400 font-bold">+++ /etc/nginx/conf.d/ssl_security.conf</p>
              <p className="text-slate-500">@@ -12,4 +12,10 @@</p>
              <p className="text-emerald-400">+ add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;</p>
              <p className="text-emerald-400">+ add_header X-Frame-Options "SAMEORIGIN" always;</p>
              <p className="text-emerald-400">+ add_header X-Content-Type-Options "nosniff" always;</p>
              <p className="text-slate-400">sudo nginx -t && sudo systemctl reload nginx</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --- PRO USER: UNLOCKED INTERACTIVE WORKSPACE ---
  const playbookItems = playbookData?.playbook || [];

  // Filter items
  const filteredItems = playbookItems.filter(item => {
    const sev = item.finding.severity;
    const matchesSev = severityFilter === 'all' || sev === severityFilter;
    const matchesSearch = 
      item.finding.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.finding.cve_ids || []).some(c => c.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (item.remediation.affected_component || '').toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-sky-950/40 to-slate-900 border border-sky-500/30">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-sky-500/20 text-sky-300 border border-sky-500/40 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            <span>PRO EDITION // AUTONOMOUS AI REMEDIATION PLAYBOOK</span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Executable Patch Blueprint: {scan.target_domain}
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real configuration diffs, CLI terminal deployment scripts, and verification tests synthesized via OpenRouter Multi-Key AI.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchPlaybook}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 flex items-center gap-2 cursor-pointer transition-all disabled:opacity-50"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Synthesizing...' : 'Refresh'}</span>
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={downloadingPdf || loading}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white text-xs font-bold shadow-lg shadow-sky-500/25 flex items-center gap-2 cursor-pointer transition-all disabled:opacity-50"
          >
            <FileDown className={`w-4 h-4 ${downloadingPdf ? 'animate-bounce' : ''}`} />
            <span>{downloadingPdf ? 'Generating PDF...' : 'Download Patch Playbook PDF'}</span>
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Patches Ready</div>
          <div className="text-2xl font-extrabold text-sky-400 mt-1">{playbookData?.total_patches || playbookItems.length}</div>
          <div className="text-[10px] text-slate-500 mt-1">100% executable config diffs</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Critical Hotfixes</div>
          <div className="text-2xl font-extrabold text-rose-400 mt-1">{playbookData?.critical_patches || 0}</div>
          <div className="text-[10px] text-rose-400/80 mt-1">Immediate priority</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">High Priority Diffs</div>
          <div className="text-2xl font-extrabold text-orange-400 mt-1">{playbookData?.high_patches || 0}</div>
          <div className="text-[10px] text-slate-500 mt-1">Sprint schedule</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">AI Intelligence Engine</div>
          <div className="text-xs font-bold text-emerald-400 mt-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>OpenRouter Multi-Key</span>
          </div>
          <div className="text-[10px] text-slate-500 mt-1">17 API Keys in Active Pool</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/40 border border-slate-800">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {['all', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                severityFilter === sev
                  ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {sev === 'all' ? 'All Patches' : sev}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search CVE, component..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Remediation Cards List */}
      {loading ? (
        <div className="flex flex-col items-center justify-center p-12 text-slate-500 space-y-3">
          <Sparkles className="w-8 h-8 text-sky-400 animate-spin" />
          <p className="text-xs">Synthesizing autonomous AI code patches and verification commands...</p>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="p-8 text-center text-slate-500 bg-slate-900/20 border border-slate-800/80 rounded-xl">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
          <p className="text-xs">No patches match the active filter.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {filteredItems.map((item, idx) => {
            const f = item.finding;
            const r = item.remediation;
            const diffKey = `diff_${idx}`;
            const cliKey = `cli_${idx}`;

            return (
              <div
                key={f.id || idx}
                className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-lg hover:border-slate-700 transition-all"
              >
                {/* Finding Header */}
                <div className="p-5 border-b border-slate-800/80 bg-slate-950/40 flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSevBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      {(f.cve_ids || []).map(cve => (
                        <span key={cve} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-sky-300 border border-slate-700">
                          {cve}
                        </span>
                      ))}
                      {f.cvss_score > 0 && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/60 text-rose-300 border border-rose-800/50">
                          CVSS {f.cvss_score}
                        </span>
                      )}
                      <span className="text-[11px] text-slate-400">
                        Component: <b className="text-slate-300">{r.affected_component || 'Server / API'}</b>
                      </span>
                    </div>

                    <h3 className="text-base font-bold text-white tracking-tight">
                      {f.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-slate-400 self-start md:self-auto shrink-0">
                    <span className="px-2 py-1 rounded bg-slate-800/80 text-emerald-400 font-mono text-[10px] border border-slate-700">
                      {r.generated_by || 'AI Synthesized'}
                    </span>
                    <span className="flex items-center gap-1 text-slate-400">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {r.estimated_time || '20m'}
                    </span>
                  </div>
                </div>

                {/* Body Content */}
                <div className="p-5 space-y-4 text-xs">
                  {/* 1. Root Cause */}
                  <div>
                    <div className="font-semibold text-slate-300 mb-1 flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                      <span>1. Root Cause Analysis & Exploit Vector</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed bg-slate-950/50 p-3 rounded-lg border border-slate-800/60">
                      {r.root_cause_analysis}
                    </p>
                  </div>

                  {/* 2. Unified Git Diff */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                        <Code className="w-3.5 h-3.5 text-sky-400" />
                        <span>2. Unified Configuration Patch (Git Diff)</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(r.patch_code_diff, diffKey)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center gap-1 cursor-pointer transition-all border border-slate-700"
                      >
                        {copiedKey === diffKey ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Copied Diff</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Diff</span>
                          </>
                        )}
                      </button>
                    </div>

                    <pre className="p-3.5 rounded-xl bg-slate-950 font-mono text-[11px] leading-relaxed border border-slate-800 overflow-x-auto max-h-56">
                      {r.patch_code_diff.split('\n').map((line, lIdx) => {
                        let color = 'text-slate-400';
                        if (line.startsWith('+') && !line.startsWith('+++')) color = 'text-emerald-400 font-semibold bg-emerald-950/20';
                        if (line.startsWith('-') && !line.startsWith('---')) color = 'text-rose-400 font-semibold bg-rose-950/20';
                        if (line.startsWith('@@')) color = 'text-sky-400 italic';
                        return (
                          <div key={lIdx} className={`${color} px-1 rounded`}>
                            {line}
                          </div>
                        );
                      })}
                    </pre>
                  </div>

                  {/* 3. Terminal CLI Commands */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                        <span>3. Terminal Execution Script (Copy & Run)</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(r.terminal_commands, cliKey)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center gap-1 cursor-pointer transition-all border border-slate-700"
                      >
                        {copiedKey === cliKey ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Copied CLI</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Commands</span>
                          </>
                        )}
                      </button>
                    </div>

                    <pre className="p-3.5 rounded-xl bg-slate-950 font-mono text-[11px] leading-relaxed text-sky-300 border border-slate-800 overflow-x-auto max-h-44">
                      {r.terminal_commands}
                    </pre>
                  </div>

                  {/* 4. Verification and Rollback */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                      <div className="font-semibold text-sky-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Verification Test Suite</span>
                      </div>
                      <p className="font-mono text-[11px] text-slate-300 leading-snug">
                        {r.verification_test}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-1">
                      <div className="font-semibold text-amber-400 flex items-center gap-1">
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Emergency Rollback Procedure</span>
                      </div>
                      <p className="font-mono text-[11px] text-slate-400 leading-snug">
                        {r.rollback_procedure}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
