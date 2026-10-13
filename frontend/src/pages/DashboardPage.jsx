import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  DollarSign, 
  TrendingUp, 
  Layers, 
  AlertTriangle, 
  ExternalLink,
  Flame,
  Info,
  ArrowUpRight,
  Clock,
  Sparkles,
  Scale,
  RefreshCw,
  GitCompare,
  Check
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import AuditFeasibilityDecisionCard from '../components/AuditFeasibilityDecisionCard';


export default function DashboardPage({ scan, onNavigateTab, onSelectScan, onScanStarted }) {
  const [costData, setCostData] = useState(null);
  const [dpdpData, setDpdpData] = useState(null);
  const [driftData, setDriftData] = useState(null);
  const [topFindings, setTopFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [rescanSuccess, setRescanSuccess] = useState(false);

  const handleDashboardRescan = async () => {
    if (!scan?.id) return;
    setRescanLoading(true);
    try {
      const res = await fetch(`/api/scans/${scan.id}/rescan`, { method: 'POST' });
      if (res.ok) {
        setRescanSuccess(true);
        if (onScanStarted) onScanStarted();
        setTimeout(() => setRescanSuccess(false), 4000);
      }
    } catch (e) {
    } finally {
      setRescanLoading(false);
    }
  };

  useEffect(() => {
    if (!scan?.id) return;
    setLoading(true);

    // Fetch Cost summary
    fetch(`/api/scans/${scan.id}/cost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'both' })
    })
      .then(r => r.json())
      .then(d => setCostData(d))
      .catch(() => {});

    // Fetch DPDP compliance
    fetch(`/api/scans/${scan.id}/compliance/dpdp`)
      .then(r => r.json())
      .then(d => setDpdpData(d))
      .catch(() => {});

    // Fetch Drift
    fetch(`/api/scans/${scan.id}/diff`)
      .then(r => r.json())
      .then(d => setDriftData(d))
      .catch(() => {});

    // Fetch Findings
    fetch(`/api/scans/${scan.id}/findings`)
      .then(r => r.json())
      .then(d => setTopFindings(d.slice(0, 5)))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [scan?.id]);

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center h-[70vh] text-center p-6 space-y-4">
        <div className="w-16 h-16 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
          <Layers className="w-8 h-8 text-sky-400" />
        </div>
        <h2 className="text-xl font-bold text-slate-200">No Active Audit Selected</h2>
        <p className="text-sm text-slate-400 max-w-md">
          Launch a new attack-surface scan in passive or active mode to inspect perimeter assets, vulnerabilities, and financial risk metrics.
        </p>
        <button
          onClick={() => onNavigateTab('runner')}
          className="px-5 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-medium text-xs transition cursor-pointer"
        >
          Launch Audit Runner
        </button>
      </div>
    );
  }

  const riskScore = scan.risk_score || 0;
  const isHighRisk = riskScore >= 70;

  const totalLoss = costData?.total_potential_breach_loss ?? scan.potential_breach_loss ?? 0;
  const damageBreakdown = costData?.damage_breakdown || {
    incident_response_forensics: Math.round(totalLoss * 0.30),
    business_downtime_disruption: Math.round(totalLoss * 0.35),
    regulatory_penalties_fines: Math.round(totalLoss * 0.20),
    customer_notification_pr: Math.round(totalLoss * 0.15),
  };
  const dpdpExposureInr = dpdpData?.penalty_exposure_inr_formatted || '₹0.00';
  const dpdpScore = dpdpData?.compliance_score ?? 100;
  const dpdpVerdict = dpdpData?.compliance_verdict || 'COMPLIANT';

  // Chart data
  const severityChartData = costData ? Object.entries(costData.severity_breakdown || {}).map(([sev, val]) => ({
    severity: sev,
    fixCost: val.fix_cost,
    loss: val.potential_loss,
    count: val.count
  })) : [];

  const COLORS = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#3b82f6',
    Info: '#64748b'
  };

  return (
    <div className="space-y-6">
      {/* Target Banner */}
      <div className="glass-panel rounded-2xl p-6 relative overflow-hidden flex flex-col md:flex-row md:items-center justify-between gap-6 border-slate-800">
        <div className="space-y-1.5 z-10">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-black text-white tracking-tight">{scan.target_domain}</h1>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wider bg-slate-800 border border-slate-700 text-slate-300">
              Mode: {scan.mode}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold ${
              scan.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400'
            }`}>
              {scan.status}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            {scan.company_name} &bull; Perimeter posture evaluation &bull; Updated: {new Date(scan.created_at).toLocaleString()}
          </p>

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={handleDashboardRescan}
              disabled={rescanLoading || scan.status === 'running' || scan.status === 'queued'}
              title="Launch fresh re-scan of this perimeter in the background"
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 text-xs font-semibold transition cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${rescanLoading ? 'animate-spin' : ''}`} />
              <span>{rescanSuccess ? 'Re-Scan Queued!' : rescanLoading ? 'Starting...' : 'Re-Scan Target'}</span>
            </button>

            <button
              onClick={() => onNavigateTab && onNavigateTab('diff')}
              title="View differential drift and posture changes"
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 text-xs font-medium transition cursor-pointer"
            >
              <GitCompare className="w-3.5 h-3.5 text-purple-400" />
              <span>
                {driftData?.has_previous_scan
                  ? `Posture: ${driftData?.deltas?.posture_status || 'Diff'}`
                  : 'Scan Diff & Drift'}
              </span>
            </button>
          </div>
        </div>

        {/* 0-100 Risk Score Badge */}
        <div className="flex items-center gap-4 bg-slate-900/90 border border-slate-800 p-3.5 rounded-xl z-10 shrink-0">
          <div className="text-right">
            <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Risk Posture Score</div>
            <div className="text-[11px] text-slate-500">
              {riskScore >= 85 ? 'Critical Danger' : riskScore >= 70 ? 'High Exposure' : 'Guarded Posture'}
            </div>
          </div>
          <div className={`w-14 h-14 rounded-xl flex items-center justify-center font-black text-xl shadow-lg ${
            riskScore >= 85
              ? 'bg-gradient-to-br from-rose-600 to-red-800 text-white shadow-rose-600/30 glow-badge-red'
              : riskScore >= 70
              ? 'bg-gradient-to-br from-amber-500 to-orange-600 text-white shadow-orange-500/30'
              : 'bg-gradient-to-br from-emerald-500 to-teal-600 text-white'
          }`}>
            {riskScore}
          </div>
        </div>
      </div>

      {/* Cyber Threat Radar & Visual Kill-Chain Command Card */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-sky-950/40 to-slate-900 border border-sky-500/30 p-5 shadow-2xl">
        <div className="absolute top-0 right-0 w-80 h-full bg-cyber-grid opacity-30 pointer-events-none" />
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5 relative z-10">
          <div className="flex items-center gap-4">
            {/* Animated Threat Radar Compass */}
            <div className="relative w-14 h-14 rounded-2xl bg-slate-950 border border-sky-500/40 flex items-center justify-center shrink-0 overflow-hidden shadow-lg shadow-sky-500/20">
              <div className="absolute inset-0 border border-sky-500/20 rounded-full m-1" />
              <div className="absolute inset-0 border border-sky-500/30 rounded-full m-3" />
              {/* Radar sweep hand */}
              <div className="absolute inset-0 animate-radar origin-center">
                <div className="w-1/2 h-0.5 bg-gradient-to-r from-transparent to-sky-400 absolute top-1/2 right-1/2" />
              </div>
              <Flame className="w-5 h-5 text-rose-400 z-10 animate-pulse" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-extrabold font-mono uppercase px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  LIVE THREAT RADAR
                </span>
                <span className="text-xs text-slate-400">
                  Target: <b className="text-sky-300 font-mono">{scan.target_domain}</b>
                </span>
              </div>
              <h2 className="text-base font-extrabold text-white mt-1">
                Visual Exploit Path & Blast-Radius Engine
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Interactive mapping of external entrypoints, exploitable CVE kill-chains, and zero-trust remediation playbooks.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto shrink-0">
            <button
              onClick={() => onNavigateTab && onNavigateTab('graph')}
              className="flex-1 md:flex-none px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-500 via-orange-500 to-amber-500 hover:from-rose-400 hover:to-amber-400 text-slate-950 font-bold text-xs shadow-lg shadow-rose-500/20 flex items-center justify-center gap-2 cursor-pointer transition-all"
            >
              <Flame className="w-4 h-4 fill-current" />
              <span>Inspect Attack Graph</span>
            </button>

            <button
              onClick={() => onNavigateTab && onNavigateTab('playbook')}
              className="flex-1 md:flex-none px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs border border-slate-700 flex items-center justify-center gap-2 cursor-pointer transition-all hover:border-sky-500/40"
            >
              <Sparkles className="w-4 h-4 text-sky-400" />
              <span>View AI Patch Playbook</span>
            </button>
          </div>
        </div>
      </div>

      {/* Top Hero Financial Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Expected Breach Loss */}
        <div className="glass-panel glass-panel-hover rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Potential Breach Loss</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-black text-rose-400 font-mono tracking-tight">
              ${(costData?.total_potential_breach_loss || scan.potential_breach_loss || 0).toLocaleString()}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">Annualized risk-weighted exposure based on EPSS/KEV</p>
          </div>
        </div>

        {/* Metric 2: Fix Cost */}
        <div className="glass-panel glass-panel-hover rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Estimated Cost to Fix</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <DollarSign className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-black text-emerald-400 font-mono tracking-tight">
              ${(costData?.total_fix_cost_both || scan.total_fix_cost || 0).toLocaleString()}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              {costData?.total_dev_hours || 0} dev hrs + {costData?.total_tester_hours || 0} QA test hrs
            </p>
          </div>
        </div>

        {/* Metric 3: ROSI / ROI */}
        <div className="glass-panel glass-panel-hover rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Remediation ROI</span>
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-black text-sky-400 font-mono tracking-tight">
              +{(costData?.roi_both || scan.roi_percentage || 0).toLocaleString()}%
            </div>
            <p className="text-[11px] text-slate-500 mt-1">ROI of proactive patching vs breach loss</p>
          </div>
        </div>

        {/* Metric 4: Perimeter Assets */}
        <div className="glass-panel glass-panel-hover rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Perimeter Assets</span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div>
            <div className="text-2xl font-black text-purple-400 font-mono tracking-tight">
              {scan.total_assets || 0}
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Across subdomains, IPs, cloud buckets, services
            </p>
          </div>
        </div>
      </div>

      {/* Executive Audit Feasibility & Budget ROI Advisory Card */}
      <AuditFeasibilityDecisionCard 
        scan={scan} 
        costData={costData} 
        topFindings={topFindings} 
        variant="dashboard" 
        onNavigateTab={onNavigateTab} 
      />

      {/* Quantified Breach Damage Breakdown & DPDP Statutory Exposure Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Breach Damage Cost Center Breakdown (2 cols) */}
        <div className="lg:col-span-2 glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Quantified Breach Damage Breakdown
              </h3>
              <p className="text-xs text-slate-400">Actuarial loss distribution across standard breach incident cost centers</p>
            </div>
            <div className="text-right">
              <span className="text-xs font-mono font-bold text-rose-400 bg-rose-500/10 px-3 py-1 rounded-lg border border-rose-500/20">
                Total Risk: ${totalLoss.toLocaleString()}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
            {/* 1. Business Downtime & Disruption */}
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Business Downtime & Disruption</span>
                <span className="text-rose-400 font-mono font-bold">35%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(damageBreakdown.business_downtime_disruption || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-rose-500 h-full rounded-full transition-all duration-500" style={{ width: totalLoss > 0 ? '35%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Service outages, operational SLA penalties, and customer churn</p>
            </div>

            {/* 2. Incident Response & Forensics */}
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Incident Response & DFIR</span>
                <span className="text-orange-400 font-mono font-bold">30%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(damageBreakdown.incident_response_forensics || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-orange-500 h-full rounded-full transition-all duration-500" style={{ width: totalLoss > 0 ? '30%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Digital forensics investigation, reverse engineering, perimeter containment</p>
            </div>

            {/* 3. Regulatory Penalties & Fines */}
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Regulatory Penalties & Fines</span>
                <span className="text-amber-400 font-mono font-bold">20%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(damageBreakdown.regulatory_penalties_fines || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-amber-500 h-full rounded-full transition-all duration-500" style={{ width: totalLoss > 0 ? '20%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">DPDP Act, GDPR, PCI-DSS statutory sanctions and compliance audits</p>
            </div>

            {/* 4. Customer Notification & PR */}
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Customer Notification & Legal PR</span>
                <span className="text-sky-400 font-mono font-bold">15%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(damageBreakdown.customer_notification_pr || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-sky-500 h-full rounded-full transition-all duration-500" style={{ width: totalLoss > 0 ? '15%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Principal disclosures, identity monitoring support, legal defense retainers</p>
            </div>
          </div>
        </div>

        {/* DPDP Act 2023 Live Statutory Posture Badge Card */}
        <div className="glass-panel rounded-2xl p-6 border-indigo-500/30 bg-gradient-to-br from-slate-900/90 via-slate-900/80 to-indigo-950/40 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 flex items-center gap-1.5">
                <Scale className="w-3.5 h-3.5 text-indigo-400" />
                DPDP Act 2023 Statutory
              </span>
              <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${
                dpdpScore >= 80 
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                  : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}>
                {dpdpScore}% Compliance
              </span>
            </div>

            <div>
              <div className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Estimated Penalty Exposure</div>
              <div className="text-2xl font-black text-rose-400 font-mono mt-0.5">
                {dpdpExposureInr}
              </div>
              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                {dpdpData?.penalty_exposure_usd_formatted || '$0.00'} &bull; Max cap: ₹250 Cr
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] space-y-1.5">
              <div className="text-slate-300 font-semibold flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${dpdpData?.controls_summary?.failed === 0 ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                <span>Section 8(5) Safeguards: {dpdpData?.controls_summary?.failed === 0 ? 'Passed' : `${dpdpData?.controls_summary?.failed || 0} Action Items`}</span>
              </div>
              <p className="text-[10px] text-slate-400 line-clamp-2">
                {dpdpVerdict}
              </p>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('compliance')}
            className="w-full py-2.5 px-3.5 rounded-xl bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-xs font-semibold transition flex items-center justify-center gap-1.5 cursor-pointer shadow-sm"
          >
            <span>View Complete Statutory Matrix</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Grid: Cost Analysis Charts + Drift Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Cost vs Loss Comparison Bar Chart */}
        <div className="glass-panel rounded-2xl p-6 lg:col-span-2 space-y-4 border-slate-800">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Financial Risk Model: Fix Cost vs Potential Breach Loss
              </h3>
              <p className="text-xs text-slate-400">Broken down by vulnerability severity classification</p>
            </div>
            <button
              onClick={() => onNavigateTab('cost')}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-medium cursor-pointer"
            >
              Interactive Simulator <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="h-64 w-full pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: 10, bottom: 20 }}>
                <XAxis dataKey="severity" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} tickFormatter={(val) => `$${val >= 1000 ? `${(val/1000).toFixed(0)}k` : val}`} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                  formatter={(val, name) => [`$${val.toLocaleString()}`, name === 'loss' ? 'Potential Loss' : 'Fix Cost']}
                />
                <Bar dataKey="loss" fill="#ef4444" radius={[4, 4, 0, 0]} name="Potential Loss" />
                <Bar dataKey="fixCost" fill="#10b981" radius={[4, 4, 0, 0]} name="Cost to Fix" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Surface Drift & Diff */}
        <div className="glass-panel rounded-2xl p-6 space-y-4 border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-sky-400" />
                Attack-Surface Drift
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-mono">
                APScheduler
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Changes detected since previous scheduled scan</p>

            <div className="space-y-3 mt-4">
              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                <div className="text-[11px] text-slate-400">New Assets Discovered</div>
                <div className="text-lg font-bold text-white font-mono">
                  {driftData?.new_assets?.length || 0} nodes
                </div>
                {driftData?.new_assets?.length > 0 && (
                  <p className="text-[10px] text-slate-500 truncate mt-1">
                    {driftData.new_assets.join(', ')}
                  </p>
                )}
              </div>

              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                <div className="text-[11px] text-slate-400">Newly Emerged Vulnerabilities</div>
                <div className={`text-lg font-bold font-mono ${driftData?.new_findings?.length > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
                  {driftData?.new_findings?.length || 0} issues
                </div>
              </div>

              <div className="bg-slate-900/80 p-3 rounded-xl border border-slate-800">
                <div className="text-[11px] text-slate-400">Resolved / Patched</div>
                <div className="text-lg font-bold text-emerald-400 font-mono">
                  {driftData?.resolved_findings?.length || 0} closed
                </div>
              </div>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 bg-slate-900/40 p-2.5 rounded-lg border border-slate-800/60">
            {driftData?.previous_scan_date ? `Previous scan: ${new Date(driftData.previous_scan_date).toLocaleDateString()}` : 'Initial baseline scan recorded.'}
          </div>
        </div>
      </div>

      {/* Top 5 Prioritized Issues (with rank explanation) */}
      <div className="glass-panel rounded-2xl p-6 space-y-4 border-slate-800">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-500" />
              Top 5 Prioritized Security Issues
            </h3>
            <p className="text-xs text-slate-400">
              Ranked dynamically by CISA KEV active weaponization, EPSS exploit likelihood, and CVSS
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium cursor-pointer"
          >
            View all {scan.total_findings} findings &rarr;
          </button>
        </div>

        <div className="space-y-3">
          {topFindings.length === 0 ? (
            <p className="text-xs text-slate-500 py-4">No findings recorded for this target.</p>
          ) : (
            topFindings.map((f, idx) => (
              <div
                key={f.id || idx}
                className="bg-slate-900/70 border border-slate-800/80 hover:border-slate-700 p-4 rounded-xl transition flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-xs font-mono font-bold text-slate-500">#{idx + 1}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      f.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-orange-500/20 text-orange-400'
                    }`}>
                      {f.severity}
                    </span>
                    {f.is_kev && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-black tracking-wide bg-red-600 text-white flex items-center gap-1 glow-badge-red">
                        <Flame className="w-3 h-3 fill-current" /> CISA KEV
                      </span>
                    )}
                    <h4 className="text-xs font-bold text-white hover:text-sky-400 transition cursor-pointer" onClick={() => onNavigateTab('findings')}>
                      {f.title}
                    </h4>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-1">{f.description}</p>
                  
                  {/* Why ranked explanation */}
                  <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono">
                    <Info className="w-3 h-3 text-sky-400" />
                    <span>
                      {f.is_kev ? 'Ranked #1: Confirmed actively weaponized in CISA KEV' : `Ranked #${idx + 1}: EPSS ${(f.epss_score * 100).toFixed(1)}% likelihood`} &bull; CVSS {f.cvss_score || 'N/A'} &bull; Risk Score: {f.risk_score}/100
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-4 shrink-0 text-right">
                  <div>
                    <div className="text-[10px] text-slate-400">Est. Fix Cost</div>
                    <div className="text-xs font-mono font-bold text-emerald-400">
                      ${f.estimated_fix_cost || (f.fix_hours_dev * 85 + f.fix_hours_tester * 65)}
                    </div>
                  </div>
                  <button
                    onClick={() => onNavigateTab('findings')}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition cursor-pointer"
                  >
                    Details
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
