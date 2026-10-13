import React, { useState, useEffect } from 'react';
import {
  X,
  Code,
  CheckCircle2,
  Copy,
  Download,
  Terminal,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  GitBranch,
  Check,
  Award,
  Layers,
  FileCode
} from 'lucide-react';

export default function RemediationDrawer({ finding, onClose, onFindingUpdated }) {
  const [patchData, setPatchData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('nginx'); // 'nginx', 'apache', 'diff'
  const [copied, setCopied] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);

  useEffect(() => {
    if (!finding?.id) return;
    setLoading(true);
    fetch(`/api/findings/${finding.id}/remediation-patch`)
      .then((r) => r.json())
      .then((d) => setPatchData(d))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [finding?.id]);

  const handleCopyCode = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleDownloadDiff = () => {
    if (!patchData?.diff_patch) return;
    const blob = new Blob([patchData.diff_patch], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `remediation_patch_finding_${finding?.id}.diff`;
    a.click();
  };

  const handleVerifyFix = async () => {
    if (!finding?.id) return;
    setVerifying(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/verify-fix`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setVerificationResult(data);
        if (onFindingUpdated) onFindingUpdated({ ...finding, status: 'Remediated' });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setVerifying(false);
    }
  };

  const handleSyncIssue = async (provider) => {
    if (!finding?.id) return;
    setSyncing(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/sync-issue?provider=${provider}&target_repo=corp/security-remediations`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setSyncResult(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSyncing(false);
    }
  };

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex justify-end">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-5 shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                  finding.severity === 'Critical'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                }`}
              >
                {finding.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">Finding ID #{finding.id}</span>
              {finding.status === 'Remediated' && (
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Remediated
                </span>
              )}
            </div>
            <h2 className="text-base font-bold text-slate-100 mt-1">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Effort & Cost Metrics */}
        <div className="grid grid-cols-3 gap-3 text-center text-xs">
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Dev Fix Effort</span>
            <div className="font-bold text-slate-200 font-mono mt-0.5">{finding.fix_hours_dev || 4.0} hours</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">QA Verification</span>
            <div className="font-bold text-slate-200 font-mono mt-0.5">{finding.fix_hours_tester || 2.0} hours</div>
          </div>
          <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Remediation Cost</span>
            <div className="font-bold text-sky-400 font-mono mt-0.5">${finding.estimated_fix_cost || 340}</div>
          </div>
        </div>

        {/* Verification Success Certificate Card */}
        {verificationResult?.certificate && (
          <div className="bg-emerald-950/20 border border-emerald-500/40 rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                <Award className="w-4 h-4 text-emerald-400" />
                Certificate of Remediation Issued
              </span>
              <span className="text-[10px] font-mono text-emerald-300/80">
                {verificationResult.certificate.certificate_id}
              </span>
            </div>
            <p className="text-[11px] text-slate-300">
              Auditor targeted probe confirmed this vulnerability is no longer exploitable on target endpoint.
            </p>
            <div className="text-[10px] text-slate-400 font-mono pt-1 border-t border-emerald-900/40 flex justify-between">
              <span>Timestamp: {verificationResult.certificate.verified_at}</span>
              <span>SHA256: {verificationResult.certificate.verification_hash}</span>
            </div>
          </div>
        )}

        {/* Synced Issue Card */}
        {syncResult && (
          <div className="bg-sky-950/20 border border-sky-500/40 rounded-xl p-3 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-sky-400" />
              <span className="text-slate-200 font-medium">Issue created: <strong className="text-sky-400">{syncResult.issue_id}</strong></span>
            </div>
            <a
              href={syncResult.issue_url}
              target="_blank"
              rel="noreferrer"
              className="text-[11px] text-sky-400 hover:text-sky-300 flex items-center gap-1 underline font-mono"
            >
              <span>View Issue</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}

        {/* Action Buttons: Verify Fix & Issue Sync */}
        <div className="flex flex-wrap items-center gap-2.5 pt-1">
          <button
            onClick={handleVerifyFix}
            disabled={verifying}
            className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-medium text-xs px-3.5 py-2 rounded-lg transition-all shadow-md shadow-emerald-600/20 active:scale-95 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
            <span>{verifying ? 'Running Targeted Probe…' : 'Verify Fix (Targeted Probe)'}</span>
          </button>

          <button
            onClick={() => handleSyncIssue('github')}
            disabled={syncing}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs px-3 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>Push to GitHub Issues</span>
          </button>

          <button
            onClick={() => handleSyncIssue('jira')}
            disabled={syncing}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-xs px-3 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <Layers className="w-3.5 h-3.5 text-indigo-400" />
            <span>Sync to Jira</span>
          </button>
        </div>

        {/* Patch Code Tabs */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab('nginx')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all ${
                  activeTab === 'nginx' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
                }`}
              >
                Nginx Configuration
              </button>
              <button
                onClick={() => setActiveTab('apache')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all ${
                  activeTab === 'apache' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
                }`}
              >
                Apache / Firewall / Terraform
              </button>
              <button
                onClick={() => setActiveTab('diff')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition-all ${
                  activeTab === 'diff' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
                }`}
              >
                Unified .diff
              </button>
            </div>

            <div className="flex items-center gap-2">
              {activeTab === 'diff' && (
                <button
                  onClick={handleDownloadDiff}
                  className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>Download .diff</span>
                </button>
              )}
              <button
                onClick={() => {
                  const content =
                    activeTab === 'nginx'
                      ? patchData?.nginx_config
                      : activeTab === 'apache'
                      ? patchData?.apache_or_cli_config
                      : patchData?.diff_patch;
                  handleCopyCode(content);
                }}
                className="flex items-center gap-1 text-[11px] text-slate-300 hover:text-white bg-slate-800 px-2.5 py-1 rounded-md border border-slate-700 cursor-pointer"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          {/* Code Viewer */}
          <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] text-slate-200 font-mono overflow-x-auto max-h-72 leading-relaxed">
            {activeTab === 'nginx' && patchData?.nginx_config}
            {activeTab === 'apache' && patchData?.apache_or_cli_config}
            {activeTab === 'diff' && patchData?.diff_patch}
          </pre>

          {/* Implementation Guidance */}
          {patchData?.implementation_guidance && (
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80 text-xs space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Terminal className="w-3.5 h-3.5" /> Implementation Guidance
              </span>
              <p className="text-[11px] text-slate-300 leading-relaxed font-mono">
                {patchData.implementation_guidance}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
