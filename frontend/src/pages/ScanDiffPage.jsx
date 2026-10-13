import React, { useState, useEffect } from 'react';
import { 
  GitCompare, 
  TrendingDown, 
  TrendingUp, 
  Minus, 
  ShieldCheck, 
  AlertCircle, 
  CheckCircle2, 
  Layers, 
  Calendar, 
  DollarSign, 
  ArrowRight,
  RefreshCw,
  Clock,
  Sparkles,
  Zap,
  Activity,
  Info
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  CartesianGrid 
} from 'recharts';

export default function ScanDiffPage({ scan, onSelectScan, onScanStarted, onNavigateTab }) {
  const [diffData, setDiffData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [compareToId, setCompareToId] = useState('');
  const [activeTab, setActiveTab] = useState('resolved'); // 'resolved', 'new', 'persistent', 'assets'
  const [actionLoading, setActionLoading] = useState(null); // 'rescan' | 'simulate' | null
  const [actionMessage, setActionMessage] = useState(null);

  const fetchDiff = (selectedCompareId = '') => {
    if (!scan?.id) return;
    setLoading(true);
    setError(null);
    const query = selectedCompareId ? `?compare_to=${selectedCompareId}` : '';
    fetch(`/api/scans/${scan.id}/diff${query}`)
      .then(r => {
        if (!r.ok) throw new Error("Failed to load differential scan analytics");
        return r.json();
      })
      .then(data => {
        setDiffData(data);
        if (data.previous_scan?.id && !selectedCompareId) {
          setCompareToId(data.previous_scan.id);
        }
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchDiff(compareToId);
  }, [scan?.id, compareToId]);

  const handleRescan = async () => {
    if (!scan?.id) return;
    setActionLoading('rescan');
    setActionMessage(null);
    try {
      const res = await fetch(`/api/scans/${scan.id}/rescan`, { method: 'POST' });
      if (!res.ok) throw new Error("Failed to dispatch live re-scan");
      const data = await res.json();
      setActionMessage({
        type: 'info',
        text: `Live re-scan queued (#${data.id ? data.id.slice(0, 8) : 'new'}). Reconnaissance pipeline running in background.`
      });
      if (onScanStarted) onScanStarted();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setActionLoading(null);
    }
  };

  const handleSimulateDrift = async () => {
    if (!scan?.id) return;
    setActionLoading('simulate');
    setActionMessage(null);
    try {
      const res = await fetch(`/api/scans/${scan.id}/simulate-drift`, { method: 'POST' });
      if (!res.ok) throw new Error("Failed to simulate remediation drift");
      const data = await res.json();
      setActionMessage({
        type: 'success',
        text: `Remediation verification created! Patched ${data.resolved_findings_count} configuration findings, introduced staging asset, and reduced risk to ${data.risk_score}.`
      });
      if (onScanStarted) onScanStarted();
      if (onSelectScan) {
        onSelectScan(data);
      } else {
        fetchDiff(scan.id);
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setActionLoading(null);
    }
  };

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center bg-slate-900/40 rounded-xl border border-slate-800">
        <GitCompare className="w-12 h-12 text-slate-500 mb-3" />
        <h3 className="text-lg font-semibold text-slate-200">No Active Scan Selected</h3>
        <p className="text-sm text-slate-400 mt-1 max-w-md">
          Please run or select a completed scan to inspect differential asset drift and remediation trajectory.
        </p>
      </div>
    );
  }

  if (loading && !diffData) {
    return (
      <div className="flex flex-col items-center justify-center p-16 space-y-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <p className="text-xs text-slate-400">Computing differential audit deltas and asset drift...</p>
      </div>
    );
  }

  const hasPrev = diffData?.has_previous_scan;
  const deltas = diffData?.deltas || {};
  const current = diffData?.current_scan || {};
  const previous = diffData?.previous_scan || {};
  const assetDrift = diffData?.asset_drift || {};
  const findingDrift = diffData?.finding_drift || {};
  const timeline = diffData?.timeline || [];
  const candidateScans = diffData?.available_scans_for_target || [];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <GitCompare className="w-5 h-5" />
            </span>
            <div>
              <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Scan Differential & Asset Drift Engine
              </h1>
              <p className="text-xs text-slate-400">
                Tracking target <span className="font-mono text-sky-400">{scan.target_domain}</span> remediation progress and perimeter changes
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls & Comparison Selector */}
        <div className="flex items-center flex-wrap gap-2.5">
          {candidateScans.length > 1 && (
            <div className="flex items-center gap-2 bg-slate-900/80 p-1.5 rounded-lg border border-slate-800">
              <span className="text-xs text-slate-400 font-medium flex items-center gap-1.5 pl-1">
                <Calendar className="w-3.5 h-3.5 text-slate-500" /> Compare:
              </span>
              <select
                value={compareToId}
                onChange={(e) => {
                  setCompareToId(e.target.value);
                  fetchDiff(e.target.value);
                }}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
              >
                {candidateScans
                  .filter(s => s.id !== scan.id)
                  .map(s => (
                    <option key={s.id} value={s.id}>
                      {s.created_at} &bull; Risk {s.risk_score} &bull; {s.findings_count} Vulns
                    </option>
                  ))}
              </select>
            </div>
          )}

          {/* Quick Action: Re-Scan Target */}
          <button
            onClick={handleRescan}
            disabled={actionLoading !== null}
            title="Dispatch a live background scan against this domain"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-200 text-xs font-medium transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${actionLoading === 'rescan' ? 'animate-spin' : ''}`} />
            <span>{actionLoading === 'rescan' ? 'Queuing Re-scan...' : 'Re-Scan Target'}</span>
          </button>

          {/* Quick Action: Demo Remediation Drift */}
          <button
            onClick={handleSimulateDrift}
            disabled={actionLoading !== null}
            title="Instant 1-click verification audit demonstrating improved security posture & resolved findings"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600/30 via-indigo-600/30 to-emerald-600/30 hover:from-purple-600/50 hover:to-emerald-600/50 border border-purple-500/40 text-purple-200 text-xs font-semibold transition cursor-pointer disabled:opacity-50 shadow-sm"
          >
            <Zap className={`w-3.5 h-3.5 text-emerald-400 ${actionLoading === 'simulate' ? 'animate-spin' : ''}`} />
            <span>{actionLoading === 'simulate' ? 'Generating...' : 'Demo Drift (1-Click)'}</span>
          </button>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div className={`p-3.5 rounded-xl border flex items-center justify-between gap-3 text-xs ${
          actionMessage.type === 'success'
            ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
            : actionMessage.type === 'error'
            ? 'bg-rose-950/40 border-rose-500/30 text-rose-300'
            : 'bg-sky-950/40 border-sky-500/30 text-sky-300'
        }`}>
          <div className="flex items-center gap-2">
            {actionMessage.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            ) : actionMessage.type === 'error' ? (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            ) : (
              <Info className="w-4 h-4 shrink-0 text-sky-400" />
            )}
            <span>{actionMessage.text}</span>
          </div>
          <button
            onClick={() => setActionMessage(null)}
            className="text-slate-400 hover:text-slate-200 cursor-pointer text-xs"
          >
            &times;
          </button>
        </div>
      )}

      {!hasPrev ? (
        <div className="space-y-6">
          <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/60 to-slate-950 border border-slate-800 p-8 shadow-2xl">
            <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl pointer-events-none" />
            
            <div className="max-w-2xl mx-auto text-center space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center mx-auto text-sky-400 shadow-lg shadow-sky-500/10">
                <ShieldCheck className="w-8 h-8" />
              </div>
              <div className="space-y-2">
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-sky-500/10 text-sky-300 border border-sky-500/20">
                  <Clock className="w-3.5 h-3.5" /> Inaugural Baseline Established
                </div>
                <h3 className="text-xl font-bold text-white tracking-tight">
                  First Security Baseline for <span className="font-mono text-sky-400">{scan.target_domain}</span>
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed max-w-xl mx-auto">
                  Differential analytics require at least two completed scans to compute vulnerability remediation velocity, averted breach loss, and perimeter asset drift. Choose an action below to compare against this baseline:
                </p>
              </div>

              {/* Dual Action Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 text-left">
                {/* Action 1: Live Re-scan */}
                <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-sky-400 font-bold text-sm">
                      <RefreshCw className="w-4 h-4" />
                      <span>Live Re-Scan Target</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      Dispatches the full active/passive reconnaissance and vulnerability testing suite in the background. Discovers live updates, new subdomains, or freshly applied fixes.
                    </p>
                  </div>
                  <div>
                    <button
                      onClick={handleRescan}
                      disabled={actionLoading !== null}
                      className="w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-medium text-xs flex items-center justify-center gap-2 transition cursor-pointer shadow-md shadow-sky-600/20"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${actionLoading === 'rescan' ? 'animate-spin' : ''}`} />
                      <span>{actionLoading === 'rescan' ? 'Dispatching Live Re-scan...' : 'Launch Live Re-Scan'}</span>
                    </button>
                    <span className="block text-[10px] text-slate-500 text-center mt-1.5 font-mono">
                      Runs asynchronously (~30-60s)
                    </span>
                  </div>
                </div>

                {/* Action 2: Instant Demo Drift */}
                <div className="p-5 rounded-xl bg-gradient-to-br from-indigo-950/40 via-purple-950/20 to-slate-950 border border-purple-500/30 hover:border-purple-500/50 transition flex flex-col justify-between space-y-4 relative overflow-hidden">
                  <div className="absolute top-2 right-2 px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    Instant Demo
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 text-purple-300 font-bold text-sm">
                      <Sparkles className="w-4 h-4 text-purple-400" />
                      <span>Demo Remediation Drift</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Instantly generates a verified post-remediation audit for <span className="font-mono text-white">{scan.target_domain}</span>. Resolves 2-3 configuration findings, discovers a staging asset, and drops risk score by ~28 pts.
                    </p>
                  </div>
                  <div>
                    <button
                      onClick={handleSimulateDrift}
                      disabled={actionLoading !== null}
                      className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-emerald-600 hover:from-purple-500 hover:to-emerald-500 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer shadow-lg shadow-purple-600/25"
                    >
                      <Zap className={`w-3.5 h-3.5 ${actionLoading === 'simulate' ? 'animate-spin' : ''}`} />
                      <span>{actionLoading === 'simulate' ? 'Simulating Drift...' : '⚡ Generate Demo Drift (Instant)'}</span>
                    </button>
                    <span className="block text-[10px] text-emerald-400/90 text-center mt-1.5 font-mono font-medium">
                      0s wait time &bull; Instant green posture verification
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <>
          {/* Posture Verdict Banner */}
          <div className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
            deltas.posture_status === 'Improved'
              ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
              : deltas.posture_status === 'Degraded'
              ? 'bg-rose-950/30 border-rose-500/30 text-rose-300'
              : 'bg-slate-900/60 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center gap-3">
              {deltas.posture_status === 'Improved' ? (
                <div className="p-2.5 rounded-lg bg-emerald-500/20 text-emerald-400">
                  <TrendingDown className="w-5 h-5" />
                </div>
              ) : deltas.posture_status === 'Degraded' ? (
                <div className="p-2.5 rounded-lg bg-rose-500/20 text-rose-400">
                  <TrendingUp className="w-5 h-5" />
                </div>
              ) : (
                <div className="p-2.5 rounded-lg bg-slate-800 text-slate-400">
                  <Minus className="w-5 h-5" />
                </div>
              )}
              <div>
                <h4 className="text-sm font-bold flex items-center gap-2">
                  <span>{deltas.posture_status} Posture</span>
                  <span className="text-[11px] font-normal opacity-80">&bull; {deltas.posture_verdict}</span>
                </h4>
                <p className="text-xs opacity-70">
                  Comparing current scan ({current.created_at?.slice(0, 16)}) vs baseline ({previous.created_at?.slice(0, 16)})
                </p>
              </div>
            </div>

            {deltas.resolved_potential_loss_saved > 0 && (
              <div className="hidden md:flex flex-col items-end">
                <span className="text-[10px] uppercase font-semibold text-emerald-400/80 tracking-wider">Breach Loss Averted</span>
                <span className="text-base font-mono font-bold text-emerald-400">
                  +${deltas.resolved_potential_loss_saved.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                </span>
              </div>
            )}
          </div>

          {/* Delta KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {/* Risk Score Delta */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-medium text-slate-400">Risk Score Change</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-2xl font-bold font-mono text-slate-100">{current.risk_score}</span>
                <span className={`text-xs font-mono font-bold flex items-center ${
                  deltas.risk_score_delta < 0 ? 'text-emerald-400' : deltas.risk_score_delta > 0 ? 'text-rose-400' : 'text-slate-400'
                }`}>
                  {deltas.risk_score_delta > 0 ? `+${deltas.risk_score_delta}` : deltas.risk_score_delta} pts
                </span>
              </div>
              <div className="text-[10px] text-slate-500 mt-1 font-mono">
                Previous: {previous.risk_score}
              </div>
            </div>

            {/* Breach Loss Delta */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-medium text-slate-400">Potential Breach Loss Delta</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold font-mono text-slate-100">
                  ${current.potential_breach_loss?.toLocaleString(undefined, { maximumFractionDigits: 0 })}
                </span>
              </div>
              <div className={`text-xs font-mono font-bold mt-1 ${
                deltas.loss_delta < 0 ? 'text-emerald-400' : deltas.loss_delta > 0 ? 'text-rose-400' : 'text-slate-400'
              }`}>
                {deltas.loss_delta > 0 ? `+$${deltas.loss_delta?.toLocaleString()}` : `-$${Math.abs(deltas.loss_delta || 0)?.toLocaleString()}`}
              </div>
            </div>

            {/* Resolved Vulnerabilities */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-medium text-slate-400">Resolved Vulnerabilities</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {findingDrift.resolved_count || 0}
                </span>
                <span className="text-xs text-slate-400">fixed</span>
              </div>
              <div className="text-[10px] text-slate-500 mt-1">
                {findingDrift.new_count > 0 ? `+${findingDrift.new_count} new findings discovered` : 'No new vulnerabilities introduced'}
              </div>
            </div>

            {/* Asset Drift */}
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-4">
              <span className="text-[11px] font-medium text-slate-400">Asset Drift</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-2xl font-bold font-mono text-slate-100">
                  {current.total_assets}
                </span>
                <span className={`text-xs font-mono font-bold ${
                  deltas.assets_delta > 0 ? 'text-sky-400' : deltas.assets_delta < 0 ? 'text-amber-400' : 'text-slate-400'
                }`}>
                  {deltas.assets_delta > 0 ? `+${deltas.assets_delta}` : deltas.assets_delta} assets
                </span>
              </div>
              <div className="text-[10px] text-slate-500 mt-1">
                +{assetDrift.new_count || 0} new &bull; -{assetDrift.decommissioned_count || 0} retired
              </div>
            </div>
          </div>

          {/* Historical Trend Chart */}
          {timeline.length > 1 && (
            <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Activity className="w-4 h-4 text-sky-400" /> Historical Risk Score Trajectory
                </h3>
                <span className="text-[11px] font-mono text-slate-400">{timeline.length} Scans on Record</span>
              </div>
              <div className="h-44 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 10 }} domain={[0, 100]} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                      formatter={(val) => [`${val} / 100`, 'Risk Score']}
                    />
                    <Line type="monotone" dataKey="risk_score" stroke="#38bdf8" strokeWidth={2.5} dot={{ r: 4, fill: '#38bdf8' }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Detailed Drift Tabs */}
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl overflow-hidden">
            <div className="flex border-b border-slate-800 bg-slate-950/40 text-xs">
              <button
                onClick={() => setActiveTab('resolved')}
                className={`px-4 py-3 font-medium flex items-center gap-2 border-b-2 transition-all cursor-pointer ${
                  activeTab === 'resolved'
                    ? 'border-emerald-500 text-emerald-400 bg-emerald-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Resolved Vulnerabilities</span>
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-emerald-500/20 text-emerald-300 font-mono">
                  {findingDrift.resolved_count || 0}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('new')}
                className={`px-4 py-3 font-medium flex items-center gap-2 border-b-2 transition-all cursor-pointer ${
                  activeTab === 'new'
                    ? 'border-rose-500 text-rose-400 bg-rose-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertCircle className="w-4 h-4 text-rose-400" />
                <span>Newly Discovered</span>
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-rose-500/20 text-rose-300 font-mono">
                  {findingDrift.new_count || 0}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('persistent')}
                className={`px-4 py-3 font-medium flex items-center gap-2 border-b-2 transition-all cursor-pointer ${
                  activeTab === 'persistent'
                    ? 'border-amber-500 text-amber-400 bg-amber-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Clock className="w-4 h-4 text-amber-400" />
                <span>Persistent / Unpatched</span>
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-amber-500/20 text-amber-300 font-mono">
                  {findingDrift.persistent_count || 0}
                </span>
              </button>

              <button
                onClick={() => setActiveTab('assets')}
                className={`px-4 py-3 font-medium flex items-center gap-2 border-b-2 transition-all cursor-pointer ${
                  activeTab === 'assets'
                    ? 'border-sky-500 text-sky-400 bg-sky-500/5'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-4 h-4 text-sky-400" />
                <span>Perimeter Asset Drift</span>
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-sky-500/20 text-sky-300 font-mono">
                  +{assetDrift.new_count || 0} / -{assetDrift.decommissioned_count || 0}
                </span>
              </button>
            </div>

            <div className="p-5">
              {/* Tab 1: Resolved Findings */}
              {activeTab === 'resolved' && (
                <div className="space-y-3">
                  {(!findingDrift.resolved_findings || findingDrift.resolved_findings.length === 0) ? (
                    <div className="text-center py-8 text-xs text-slate-500">
                      No resolved vulnerabilities between these two scans.
                    </div>
                  ) : (
                    findingDrift.resolved_findings.map((f, i) => (
                      <div key={i} className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 flex items-start justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                              PATCHED
                            </span>
                            <span className="text-xs font-bold text-slate-200">{f.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 leading-relaxed">{f.remediation_text || "Remediated in web server / host configuration."}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono font-bold text-slate-300">CVSS {f.cvss_score}</span>
                          <div className="text-[10px] text-emerald-400 font-mono">-$12,500 Risk Averted</div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 2: New Findings */}
              {activeTab === 'new' && (
                <div className="space-y-3">
                  {(!findingDrift.new_findings || findingDrift.new_findings.length === 0) ? (
                    <div className="text-center py-8 text-xs text-slate-500">
                      Great news! No new vulnerabilities were introduced in this scan.
                    </div>
                  ) : (
                    findingDrift.new_findings.map((f, i) => (
                      <div key={i} className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-500/20 flex items-start justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                              NEW REGRESSION
                            </span>
                            <span className="text-xs font-bold text-slate-200">{f.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 leading-relaxed">{f.remediation_text}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono font-bold text-rose-400">CVSS {f.cvss_score}</span>
                          <div className="text-[10px] text-slate-500 font-mono">Est. Fix: ${f.estimated_fix_cost}</div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 3: Persistent Findings */}
              {activeTab === 'persistent' && (
                <div className="space-y-3">
                  {(!findingDrift.persistent_findings || findingDrift.persistent_findings.length === 0) ? (
                    <div className="text-center py-8 text-xs text-slate-500">
                      No persistent vulnerabilities found.
                    </div>
                  ) : (
                    findingDrift.persistent_findings.map((f, i) => (
                      <div key={i} className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800 flex items-start justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-amber-400">
                              UNRESOLVED
                            </span>
                            <span className="text-xs font-semibold text-slate-200">{f.title}</span>
                          </div>
                          <p className="text-[11px] text-slate-400 leading-relaxed">{f.remediation_text}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono text-slate-400">CVSS {f.cvss_score}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Tab 4: Perimeter Asset Drift */}
              {activeTab === 'assets' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Newly Discovered */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Sparkles className="w-3.5 h-3.5" /> Newly Discovered Assets (+{assetDrift.new_count || 0})
                    </h4>
                    {(!assetDrift.new_assets || assetDrift.new_assets.length === 0) ? (
                      <p className="text-xs text-slate-500 py-3">No new assets detected in this scan.</p>
                    ) : (
                      assetDrift.new_assets.map((a, i) => (
                        <div key={i} className="p-2.5 rounded bg-slate-950 border border-emerald-500/20 text-xs font-mono text-slate-300 flex items-center justify-between">
                          <span className="truncate">{a.value}</span>
                          <span className="text-[10px] uppercase text-emerald-400">{a.type}</span>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Decommissioned */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5" /> Decommissioned Assets (-{assetDrift.decommissioned_count || 0})
                    </h4>
                    {(!assetDrift.decommissioned_assets || assetDrift.decommissioned_assets.length === 0) ? (
                      <p className="text-xs text-slate-500 py-3">No assets decommissioned since baseline.</p>
                    ) : (
                      assetDrift.decommissioned_assets.map((a, i) => (
                        <div key={i} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-400 line-through flex items-center justify-between">
                          <span className="truncate">{a.value}</span>
                          <span className="text-[10px] uppercase text-slate-500">{a.type}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
