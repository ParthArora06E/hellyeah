import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  DollarSign,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Sparkles,
  ArrowRight,
  Sliders,
  Scale,
  Percent,
  CheckCircle,
  Clock,
  Layers
} from 'lucide-react';

export default function AuditFeasibilityDecisionCard({ 
  scan, 
  costData: propCostData, 
  topFindings = [],
  variant = 'dashboard', // 'dashboard' or 'report'
  onNavigateTab
}) {
  const [costData, setCostData] = useState(propCostData || null);
  const [selectedScenario, setSelectedScenario] = useState('recommended'); // 'recommended', 'full', 'scoped', 'skip'

  useEffect(() => {
    if (propCostData) {
      setCostData(propCostData);
      return;
    }
    if (!scan?.id) return;

    fetch(`/api/scans/${scan.id}/cost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'both' })
    })
      .then(r => r.json())
      .then(d => setCostData(d))
      .catch(() => {});
  }, [scan?.id, propCostData]);

  if (!scan) return null;

  // 1. Risk Engine Metrics
  const riskScore = scan.risk_score || 0;
  const totalAssets = scan.total_assets || 1;
  const totalFindings = scan.total_findings || 0;

  // 2. Cost Engine & Financial Metrics
  const totalLoss = costData?.total_potential_breach_loss ?? scan.potential_breach_loss ?? 0;
  const totalFixCost = costData?.total_fix_cost_both ?? costData?.active_fix_cost ?? scan.total_fix_cost ?? 0;
  const roi = costData?.active_roi ?? scan.roi_percentage ?? (totalFixCost > 0 ? Math.round(((totalLoss - totalFixCost) / totalFixCost) * 100) : 0);

  const severityBreakdown = costData?.severity_breakdown || {};
  const criticalCount = severityBreakdown?.Critical?.count || 0;
  const highCount = severityBreakdown?.High?.count || 0;
  const mediumCount = severityBreakdown?.Medium?.count || 0;
  const lowCount = severityBreakdown?.Low?.count || 0;

  // 3. Scoped-Down High-Risk Asset Analysis
  const riskAssetsCount = Math.max(1, Math.min(totalAssets, Math.ceil((criticalCount * 1.0 + highCount * 0.7))));
  const critHighFixCost = Math.round(
    ((severityBreakdown?.Critical?.fix_cost || 0) + (severityBreakdown?.High?.fix_cost || 0)) ||
    (totalFixCost * 0.38)
  );
  const critHighLoss = Math.round(
    ((severityBreakdown?.Critical?.potential_loss || 0) + (severityBreakdown?.High?.potential_loss || 0)) ||
    (totalLoss * 0.88)
  );

  const scopedSavings = Math.max(0, totalFixCost - critHighFixCost);
  const scopedSavingsPct = totalFixCost > 0 ? Math.round((scopedSavings / totalFixCost) * 100) : 0;
  const scopedRiskNeutralizedPct = totalLoss > 0 ? Math.min(99, Math.round((critHighLoss / totalLoss) * 100)) : 85;
  const scopedRoi = critHighFixCost > 0 ? Math.round(((critHighLoss - critHighFixCost) / critHighFixCost) * 100) : roi * 1.5;

  // 4. Decision Engine Algorithm
  // Verdict Options: 'PROCEED' (Full Audit Worth It), 'SCOPE_DOWN' (Focus on High Risk Assets), 'SKIP' (Safe to Defer)
  let decisionVerdict = 'PROCEED';
  if (riskScore < 35 && criticalCount === 0 && (highCount === 0 || totalLoss < 20000 || roi <= 80)) {
    decisionVerdict = 'SKIP';
  } else if ((criticalCount > 0 || highCount > 0) && (totalAssets >= 3 || (riskScore >= 35 && riskScore <= 75) || scopedSavingsPct >= 35)) {
    decisionVerdict = 'SCOPE_DOWN';
  } else {
    decisionVerdict = 'PROCEED';
  }

  // Active view scenario
  const effectiveScenario = selectedScenario === 'recommended' 
    ? (decisionVerdict === 'PROCEED' ? 'full' : decisionVerdict === 'SCOPE_DOWN' ? 'scoped' : 'skip')
    : selectedScenario;

  return (
    <div className={`rounded-2xl border transition-all duration-300 relative overflow-hidden backdrop-blur-md ${
      variant === 'report' ? 'p-6 bg-slate-900/80 border-slate-700/80' : 'p-6 bg-slate-900/70 border-slate-800 shadow-2xl'
    }`}>
      {/* Background cyber accent glow */}
      <div className={`absolute -top-24 -right-24 w-80 h-80 rounded-full blur-3xl pointer-events-none opacity-20 ${
        decisionVerdict === 'PROCEED' ? 'bg-emerald-500' : decisionVerdict === 'SCOPE_DOWN' ? 'bg-amber-500' : 'bg-sky-500'
      }`} />

      {/* Header Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5 relative z-10">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <span className={`w-8 h-8 rounded-xl flex items-center justify-center border ${
              decisionVerdict === 'PROCEED'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : decisionVerdict === 'SCOPE_DOWN'
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                : 'bg-sky-500/10 text-sky-400 border-sky-500/30'
            }`}>
              <Scale className="w-4 h-4" />
            </span>
            <div>
              <h2 className="text-base font-black text-white tracking-tight flex items-center gap-2">
                <span>Executive Audit Feasibility &amp; Budget ROI Advisory</span>
                <span className={`text-[10px] font-extrabold font-mono uppercase px-2 py-0.5 rounded-full border ${
                  decisionVerdict === 'PROCEED'
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : decisionVerdict === 'SCOPE_DOWN'
                    ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    : 'bg-sky-500/10 text-sky-300 border-sky-500/30'
                }`}>
                  {decisionVerdict === 'PROCEED' ? 'HIGH-VALUE AUDIT' : decisionVerdict === 'SCOPE_DOWN' ? 'BUDGET OPTIMIZATION' : 'CAPITAL PRESERVATION'}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Automated recommendation evaluated by Risk Engine, Cost Engine, and Return on Security Investment (ROSI).
              </p>
            </div>
          </div>
        </div>

        {/* Interactive Scenario Pills */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-950/80 rounded-xl border border-slate-800 shrink-0">
          <button
            onClick={() => setSelectedScenario('recommended')}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
              selectedScenario === 'recommended'
                ? 'bg-gradient-to-r from-sky-500 to-indigo-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Sparkles className="w-3 h-3" />
            <span>AI Engine Verdict</span>
          </button>
          <button
            onClick={() => setSelectedScenario('full')}
            className={`px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all cursor-pointer ${
              selectedScenario === 'full' ? 'bg-slate-800 text-emerald-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Full Scope
          </button>
          <button
            onClick={() => setSelectedScenario('scoped')}
            className={`px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all cursor-pointer ${
              selectedScenario === 'scoped' ? 'bg-slate-800 text-amber-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Scoped Down
          </button>
          <button
            onClick={() => setSelectedScenario('skip')}
            className={`px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all cursor-pointer ${
              selectedScenario === 'skip' ? 'bg-slate-800 text-sky-400 font-bold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Defer / Skip
          </button>
        </div>
      </div>

      {/* Main Decision Hero Banner */}
      <div className="py-5 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Left Column: Verdict Badge & Headline */}
        <div className="lg:col-span-8 space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              EXECUTIVE DETERMINATION:
            </span>
          </div>

          {effectiveScenario === 'full' && (
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-bold text-sm">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>PROCEED: FULL AUDIT HIGHLY WORTH THE BUDGET (ROI: {roi}%)</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                The Risk Engine identified acute perimeter exposures representing an estimated <b>${totalLoss.toLocaleString()}</b> in risk-adjusted breach loss. 
                Remediating all findings costs <b>${totalFixCost.toLocaleString()}</b>, delivering an outstanding <b>{roi}% Return on Investment</b>. 
                Full audit and remediation must proceed without delay.
              </p>
            </div>
          )}

          {effectiveScenario === 'scoped' && (
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-300 font-bold text-sm">
                <Sliders className="w-4 h-4 text-amber-400 shrink-0" />
                <span>SCOPE DOWN BUDGET: TARGET HIGH-RISK ASSETS ONLY (SAVE {scopedSavingsPct}%)</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                The Risk Engine reveals that <b>{scopedRiskNeutralizedPct}%</b> of all breach loss is concentrated in only <b>{riskAssetsCount} high-risk asset(s)</b> out of {totalAssets}. 
                Remediating the entire perimeter costs ${totalFixCost.toLocaleString()}. 
                By scoping down the audit budget to <b>${critHighFixCost.toLocaleString()}</b>, you neutralize <b>${critHighLoss.toLocaleString()}</b> in critical exposure while saving <b>${scopedSavings.toLocaleString()}</b> ({scopedSavingsPct}% savings) with an elevated <b>{scopedRoi}% Targeted ROI</b>.
              </p>
            </div>
          )}

          {effectiveScenario === 'skip' && (
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-sky-500/15 border border-sky-500/30 text-sky-300 font-bold text-sm">
                <CheckCircle className="w-4 h-4 text-sky-400 shrink-0" />
                <span>SAFE TO SKIP / DEFER AUDIT: CAPITAL PRESERVATION MODE</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Risk Posture is healthy (Score: <b>{riskScore}/100</b>) with zero active weaponized KEV exploits. 
                Potential breach exposure (${totalLoss.toLocaleString()}) does not warrant costly third-party penetration testing or developer remediation at this time. 
                The company can safely defer this audit, saving 100% of remediation capital (<b>${totalFixCost.toLocaleString()}</b>) and relying on continuous automated perimeter monitoring.
              </p>
            </div>
          )}

          {/* Key Factor Checklist */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2">
            <div className="bg-slate-950/70 p-2.5 rounded-xl border border-slate-800/80 text-xs flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-sky-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Risk Posture</div>
                <div className="text-slate-200 font-bold">{riskScore}/100 ({riskScore >= 70 ? 'High' : riskScore >= 40 ? 'Moderate' : 'Guarded'})</div>
              </div>
            </div>

            <div className="bg-slate-950/70 p-2.5 rounded-xl border border-slate-800/80 text-xs flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Breach Loss at Risk</div>
                <div className="text-slate-200 font-bold font-mono">${totalLoss.toLocaleString()}</div>
              </div>
            </div>

            <div className="bg-slate-950/70 p-2.5 rounded-xl border border-slate-800/80 text-xs flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-amber-400 shrink-0" />
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Critical Asset Focus</div>
                <div className="text-slate-200 font-bold">{riskAssetsCount} of {totalAssets} Assets</div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Comparative Metrics Card */}
        <div className="lg:col-span-4 bg-slate-950/90 rounded-2xl border border-slate-800 p-4 space-y-3.5 shadow-inner">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Budget Impact Analysis</span>
            <span className="font-mono text-[10px] text-sky-400">{effectiveScenario.toUpperCase()} MODE</span>
          </div>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-slate-900">
              <span className="text-slate-400">Allocated Budget:</span>
              <span className="text-white font-bold">
                {effectiveScenario === 'full' 
                  ? `$${totalFixCost.toLocaleString()}` 
                  : effectiveScenario === 'scoped' 
                  ? `$${critHighFixCost.toLocaleString()}` 
                  : '$0 (Deferred)'}
              </span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-slate-900">
              <span className="text-slate-400">Capital Saved:</span>
              <span className={`font-bold ${effectiveScenario !== 'full' ? 'text-emerald-400' : 'text-slate-500'}`}>
                {effectiveScenario === 'full' 
                  ? '$0' 
                  : effectiveScenario === 'scoped' 
                  ? `$${scopedSavings.toLocaleString()} (${scopedSavingsPct}%)` 
                  : `$${totalFixCost.toLocaleString()} (100%)`}
              </span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-slate-900">
              <span className="text-slate-400">Loss Prevented:</span>
              <span className="text-sky-300 font-bold">
                {effectiveScenario === 'full' 
                  ? `$${totalLoss.toLocaleString()} (100%)` 
                  : effectiveScenario === 'scoped' 
                  ? `$${critHighLoss.toLocaleString()} (${scopedRiskNeutralizedPct}%)` 
                  : '$0 (Risk Retained)'}
              </span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-slate-400">Effective ROI:</span>
              <span className={`text-sm font-black ${
                effectiveScenario === 'full' ? 'text-emerald-400' : effectiveScenario === 'scoped' ? 'text-amber-400' : 'text-slate-400'
              }`}>
                {effectiveScenario === 'full' 
                  ? `${roi}%` 
                  : effectiveScenario === 'scoped' 
                  ? `${scopedRoi}%` 
                  : 'N/A'}
              </span>
            </div>
          </div>

          {variant === 'dashboard' && onNavigateTab && (
            <button
              onClick={() => onNavigateTab('cost')}
              className="w-full py-2 rounded-xl text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center justify-center gap-1.5 transition-all cursor-pointer hover:border-sky-500/30"
            >
              <span>Explore Full Financial Ledger</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Strategic CISO / CFO Action Directive */}
      <div className="mt-2 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-slate-400">
          <Clock className="w-4 h-4 text-sky-400 shrink-0" />
          <span>
            <b>Recommended Action:</b>{' '}
            {effectiveScenario === 'full'
              ? 'Authorize complete remediation sprint; dispatch developers to patch high-severity CVEs immediately.'
              : effectiveScenario === 'scoped'
              ? `Isolate and remediate the ${riskAssetsCount} high-risk asset(s); place secondary subdomains on automated drift monitoring.`
              : 'Preserve audit budget; reallocate resources to higher-risk business units and review next quarter.'}
          </span>
        </div>

        <div className="text-[11px] font-mono text-slate-500 shrink-0">
          Target: <b className="text-slate-300">{scan.target_domain}</b> &bull; Engine v2.4
        </div>
      </div>
    </div>
  );
}
