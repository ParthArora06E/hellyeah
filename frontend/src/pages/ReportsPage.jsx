import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  FileSpreadsheet, 
  Code, 
  ShieldCheck, 
  ExternalLink,
  Sparkles,
  Crown,
  Lock
} from 'lucide-react';
import AuditFeasibilityDecisionCard from '../components/AuditFeasibilityDecisionCard';

export default function ReportsPage({ scan, user, token }) {
  const [summaryText, setSummaryText] = useState('');
  const [costData, setCostData] = useState(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [copied, setCopied] = useState(false);
  const [downloadingPlaybook, setDownloadingPlaybook] = useState(false);

  const isPro = user?.role === 'pro';

  useEffect(() => {
    if (!scan?.id) return;
    setLoadingSummary(true);

    fetch(`/api/scans/${scan.id}/report/summary`)
      .then(r => r.json())
      .then(d => setSummaryText(d.summary || ''))
      .catch(() => setSummaryText('Unable to load executive summary.'))
      .finally(() => setLoadingSummary(false));

    fetch(`/api/scans/${scan.id}/cost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'both' })
    })
      .then(r => r.json())
      .then(d => setCostData(d))
      .catch(() => {});
  }, [scan?.id]);

  // Executive Decision computation for reports
  const riskScore = scan?.risk_score || 0;
  const totalLoss = costData?.total_potential_breach_loss ?? scan?.potential_breach_loss ?? 0;
  const totalFixCost = costData?.total_fix_cost_both ?? costData?.active_fix_cost ?? scan?.total_fix_cost ?? 0;
  const roi = costData?.active_roi ?? scan?.roi_percentage ?? (totalFixCost > 0 ? Math.round(((totalLoss - totalFixCost) / totalFixCost) * 100) : 0);
  const totalAssets = scan?.total_assets || 1;
  const severityBreakdown = costData?.severity_breakdown || {};
  const criticalCount = severityBreakdown?.Critical?.count || 0;
  const highCount = severityBreakdown?.High?.count || 0;
  const riskAssetsCount = Math.max(1, Math.min(totalAssets, Math.ceil((criticalCount * 1.0 + highCount * 0.7))));

  let decisionVerdict = 'PROCEED';
  if (riskScore < 35 && criticalCount === 0 && (highCount === 0 || totalLoss < 20000 || roi <= 80)) {
    decisionVerdict = 'SKIP';
  } else if ((criticalCount > 0 || highCount > 0) && (totalAssets >= 3 || (riskScore >= 35 && riskScore <= 75))) {
    decisionVerdict = 'SCOPE_DOWN';
  } else {
    decisionVerdict = 'PROCEED';
  }

  const handleCopySummary = () => {
    let fullTextToCopy = summaryText;
    if (scan) {
      const advisoryHeader = [
        '======================================================================',
        'EXECUTIVE AUDIT FEASIBILITY & BUDGET ROI ADVISORY',
        '======================================================================',
        `Target Domain: ${scan.target_domain}`,
        `Risk Engine Score: ${riskScore}/100`,
        `Potential Breach Loss: $${totalLoss.toLocaleString()}`,
        `Estimated Fix Cost: $${totalFixCost.toLocaleString()}`,
        `Projected Remediation ROI: ${roi}%`,
        `High-Risk Asset Concentration: ${riskAssetsCount} of ${totalAssets} assets`,
        '',
        `EXECUTIVE VERDICT: ${
          decisionVerdict === 'PROCEED'
            ? 'PROCEED WITH FULL AUDIT (High-value audit; critical exposure warrants complete budget commitment)'
            : decisionVerdict === 'SCOPE_DOWN'
            ? `SCOPE DOWN BUDGET (Target ${riskAssetsCount} high-risk assets; save 60%+ capital while neutralizing 88%+ breach loss)`
            : 'SAFE TO SKIP / DEFER AUDIT (Perimeter risk is low; preserve capital and maintain automated monitoring)'
        }`,
        '======================================================================',
        '',
        ''
      ].join('\n');
      fullTextToCopy = advisoryHeader + summaryText;
    }
    navigator.clipboard.writeText(fullTextToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };


  const handleDownloadPlaybookPdf = async () => {
    if (!scan?.id) return;
    if (!isPro) {
      alert('Pro Subscription Required! Please switch to the Pro User account (pro@hackingly.io) in the top-right navbar to download the Analytical AI Patch Playbook PDF.');
      return;
    }
    setDownloadingPlaybook(true);
    try {
      const res = await fetch(`/api/scans/${scan.id}/ai-playbook/pdf`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `AI_Patch_Playbook_${scan.target_domain}_${scan.id.slice(0, 8)}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      } else {
        alert('Could not download AI Playbook PDF. Ensure Pro tier is active.');
      }
    } catch (e) {
      console.error(e);
    } finally {
      setDownloadingPlaybook(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
          <FileText className="w-5 h-5 text-sky-400" />
          Audit Reports & Compliance Exports
        </h1>
        <p className="text-xs text-slate-400">
          Export full audit documentation in PDF, Excel XLSX, CSV, JSON, and Pro AI Patch Playbook formats.
        </p>
      </div>

      {/* Featured Pro Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-amber-950/20 to-indigo-950/30 border border-amber-500/30 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
            <Crown className="w-3 h-3 text-amber-400" />
            <span>PRO EXCLUSIVE // PUBLICATION-GRADE PLAYBOOK</span>
          </div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>Autonomous AI Patch Playbook PDF</span>
            <Sparkles className="w-4 h-4 text-sky-400" />
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
            Contains executable unified git diffs, shell execution scripts, zero-trust verification curl tests, and emergency rollback procedures for all detected vulnerabilities.
          </p>
        </div>

        <button
          onClick={handleDownloadPlaybookPdf}
          disabled={downloadingPlaybook}
          className={`px-5 py-3 rounded-xl font-bold text-xs flex items-center gap-2 transition-all shadow-lg cursor-pointer shrink-0 ${
            isPro
              ? 'bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-slate-950 shadow-amber-500/20'
              : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
          }`}
        >
          {isPro ? (
            <Download className={`w-4 h-4 ${downloadingPlaybook ? 'animate-bounce' : ''}`} />
          ) : (
            <Lock className="w-4 h-4 text-amber-400" />
          )}
          <span>{downloadingPlaybook ? 'Generating Playbook...' : isPro ? 'Download AI Playbook PDF' : 'Unlock with Pro (Switch Account)'}</span>
        </button>
      </div>

      {/* Executive Audit Feasibility & Budget ROI Advisory */}
      <AuditFeasibilityDecisionCard scan={scan} costData={costData} variant="report" />

      {/* Export Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* PDF Export */}
        <div className="glass-panel rounded-2xl p-5 border-slate-800 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-sm">Executive PDF Report</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Formatted multi-page briefing with posture metrics, statutory DPDP/GDPR penalty exposures, and ROI breakdown.
            </p>
          </div>
          <a
            href={`/api/scans/${scan?.id}/report/pdf`}
            download
            className="flex items-center justify-center gap-2 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs transition shadow-md shadow-rose-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </a>
        </div>

        {/* Excel XLSX Export */}
        <div className="glass-panel rounded-2xl p-5 border-slate-800 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center">
              <FileSpreadsheet className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-sm">Excel Spreadsheet (.xlsx)</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Formatted workbook with color-coded severities, hours, fix costs, OWASP, and ISO 27001 mappings.
            </p>
          </div>
          <a
            href={`/api/scans/${scan?.id}/report/xlsx`}
            download
            className="flex items-center justify-center gap-2 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition shadow-md shadow-emerald-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download XLSX</span>
          </a>
        </div>

        {/* CSV Export */}
        <div className="glass-panel rounded-2xl p-5 border-slate-800 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 text-sky-400 flex items-center justify-center">
              <Download className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-sm">Normalized CSV</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Raw tabular dataset compatible with Jira, ServiceNow, Linear, or enterprise GRC registers.
            </p>
          </div>
          <a
            href={`/api/scans/${scan?.id}/report/csv`}
            download
            className="flex items-center justify-center gap-2 py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs transition shadow-md shadow-sky-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download CSV</span>
          </a>
        </div>

        {/* JSON Export */}
        <div className="glass-panel rounded-2xl p-5 border-slate-800 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400 flex items-center justify-center">
              <Code className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-sm">Full Audit JSON</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Complete machine-readable JSON structure including forensic banners and financial aggregates.
            </p>
          </div>
          <a
            href={`/api/scans/${scan?.id}/report/json`}
            download
            className="flex items-center justify-center gap-2 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs transition shadow-md shadow-purple-600/20"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download JSON</span>
          </a>
        </div>
      </div>

      {/* Executive Security Briefing */}
      <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Executive Briefing & Remediation Strategy
            </h3>
          </div>
          <button
            onClick={handleCopySummary}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Text'}</span>
          </button>
        </div>

        <div className="bg-slate-950/80 p-5 rounded-xl border border-slate-800 text-xs text-slate-200 leading-relaxed font-sans space-y-4">
          {/* Executive Strategic Verdict Callout */}
          <div className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
            decisionVerdict === 'PROCEED'
              ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
              : decisionVerdict === 'SCOPE_DOWN'
              ? 'bg-amber-950/30 border-amber-500/40 text-amber-200'
              : 'bg-sky-950/30 border-sky-500/40 text-sky-200'
          }`}>
            <div>
              <div className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-80">
                AUDIT FEASIBILITY VERDICT &bull; RISK &amp; COST ENGINE
              </div>
              <div className="text-sm font-black mt-0.5">
                {decisionVerdict === 'PROCEED'
                  ? 'PROCEED: Full Audit Highly Worth It (Compelling ROI)'
                  : decisionVerdict === 'SCOPE_DOWN'
                  ? `SCOPE DOWN: Target ${riskAssetsCount} High-Risk Assets (Save 60%+ Capital)`
                  : 'SAFE TO SKIP / DEFER: Low Residual Risk (Capital Preservation)'}
              </div>
            </div>
            <div className="text-right text-[11px] font-mono shrink-0">
              <div>Risk Score: <b>{riskScore}/100</b></div>
              <div>Projected ROI: <b className="text-white">+{roi}%</b></div>
            </div>
          </div>

          <div className="whitespace-pre-wrap">
            {loadingSummary ? 'Generating executive briefing...' : summaryText}
          </div>
        </div>

      </div>
    </div>
  );
}
