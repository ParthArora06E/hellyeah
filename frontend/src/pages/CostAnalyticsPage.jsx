import React, { useState, useEffect } from 'react';
import { 
  DollarSign, 
  TrendingUp, 
  ShieldAlert, 
  Calculator, 
  HelpCircle, 
  Sliders, 
  Layers, 
  ArrowRight,
  Info
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  Legend 
} from 'recharts';
import CyberInsuranceCard from '../components/CyberInsuranceCard';

export default function CostAnalyticsPage({ scan }) {
  const [devRate, setDevRate] = useState(85);
  const [testerRate, setTesterRate] = useState(65);
  const [currency, setCurrency] = useState('USD');
  const [assetValue, setAssetValue] = useState(250000);
  const [recordsCount, setRecordsCount] = useState(50000);
  const [scenario, setScenario] = useState('both'); // 'dev_only' or 'both'

  const [costData, setCostData] = useState(null);
  const [loading, setLoading] = useState(false);

  const recalculateCosts = () => {
    if (!scan?.id) return;
    setLoading(true);

    fetch(`/api/scans/${scan.id}/cost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dev_rate: Number(devRate),
        tester_rate: Number(testerRate),
        currency: currency,
        asset_value: Number(assetValue),
        records_count: Number(recordsCount),
        scenario: scenario
      })
    })
      .then(r => r.json())
      .then(d => setCostData(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    recalculateCosts();
  }, [scan?.id, devRate, testerRate, currency, assetValue, recordsCount, scenario]);

  const severityChartData = costData ? Object.entries(costData.severity_breakdown || {}).map(([sev, val]) => ({
    severity: sev,
    fixCost: val.fix_cost,
    breachLoss: val.potential_loss,
    count: val.count
  })) : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
          <DollarSign className="w-5 h-5 text-emerald-400" />
          Quantified Cost-of-Risk & ROI Analyzer
        </h1>
        <p className="text-xs text-slate-400">
          Financial risk simulator: Compare realistic engineering remediation costs against actuarial breach losses.
        </p>
      </div>

      {/* Hero Financial Summary Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Fix Cost Card */}
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase">
            <span>Total Cost to Remediate</span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono">
              {scenario === 'both' ? 'Dev + QA Tester' : 'Developer Only'}
            </span>
          </div>
          <div className="text-3xl font-black text-emerald-400 font-mono tracking-tight">
            ${(costData?.active_fix_cost || 0).toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-400">
            {costData?.total_dev_hours || 0} dev hours @ ${devRate}/hr {scenario === 'both' ? `+ ${costData?.total_tester_hours || 0} QA hours @ $${testerRate}/hr` : ''}
          </p>
        </div>

        {/* Breach Loss Card */}
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase">
            <span>Potential Breach Loss</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-black text-rose-400 font-mono tracking-tight">
            ${(costData?.total_potential_breach_loss || 0).toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-400">
            Risk-adjusted exposure: Asset Value &times; Exploitation Likelihood (EPSS/KEV) &times; Severity Impact
          </p>
        </div>

        {/* ROI Payoff Card */}
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase">
            <span>Remediation ROI (ROSI)</span>
            <TrendingUp className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-3xl font-black text-sky-400 font-mono tracking-tight">
            +{(costData?.active_roi || 0).toLocaleString()}%
          </div>
          <p className="text-[11px] text-slate-400">
            Every $1 invested in remediation preserves ${(costData?.active_fix_cost ? (costData.total_potential_breach_loss / costData.active_fix_cost).toFixed(0) : 0)} in business value
          </p>
        </div>
      </div>

      {/* Damage Breakdown Categories */}
      {costData?.damage_breakdown && (
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Actuarial Breach Damage Cost Breakdown
              </h3>
              <p className="text-xs text-slate-400">Distribution of potential losses across four primary incident cost centers</p>
            </div>
            <span className="text-xs font-mono font-bold text-rose-400 bg-rose-500/10 px-3 py-1 rounded-lg border border-rose-500/20">
              Total Risk: ${(costData.total_potential_breach_loss || 0).toLocaleString()}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Business Downtime</span>
                <span className="text-rose-400 font-mono font-bold">35%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(costData.damage_breakdown.business_downtime_disruption || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-rose-500 h-full rounded-full" style={{ width: (costData.total_potential_breach_loss || 0) > 0 ? '35%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">SLA failure & outage loss</p>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">DFIR & Forensics</span>
                <span className="text-orange-400 font-mono font-bold">30%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(costData.damage_breakdown.incident_response_forensics || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-orange-500 h-full rounded-full" style={{ width: (costData.total_potential_breach_loss || 0) > 0 ? '30%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Incident response retainer</p>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Regulatory Penalties</span>
                <span className="text-amber-400 font-mono font-bold">20%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(costData.damage_breakdown.regulatory_penalties_fines || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-amber-500 h-full rounded-full" style={{ width: (costData.total_potential_breach_loss || 0) > 0 ? '20%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Statutory fines & penalties</p>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">Customer Notice & PR</span>
                <span className="text-sky-400 font-mono font-bold">15%</span>
              </div>
              <div className="text-lg font-bold text-white font-mono">
                ${(costData.damage_breakdown.customer_notification_pr || 0).toLocaleString()}
              </div>
              <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                <div className="bg-sky-500 h-full rounded-full" style={{ width: (costData.total_potential_breach_loss || 0) > 0 ? '15%' : '0%' }} />
              </div>
              <p className="text-[10px] text-slate-500">Notices, PR & defense</p>
            </div>
          </div>
        </div>
      )}

      {/* Cyber Insurance Readiness & Underwriter Score */}
      <CyberInsuranceCard scanId={scan?.id} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Interactive Parameter Controls */}
        <div className="lg:col-span-5 glass-panel rounded-2xl p-6 border-slate-800 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-sky-400" />
              Model Parameters & Sliders
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Live Recalculation</span>
          </div>

          {/* Scenario Toggle */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Staffing Scenario
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setScenario('both')}
                className={`py-2 px-3 rounded-xl text-xs font-bold transition cursor-pointer border ${
                  scenario === 'both'
                    ? 'bg-sky-500/10 border-sky-500 text-sky-400'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                Developer + QA Tester
              </button>
              <button
                type="button"
                onClick={() => setScenario('dev_only')}
                className={`py-2 px-3 rounded-xl text-xs font-bold transition cursor-pointer border ${
                  scenario === 'dev_only'
                    ? 'bg-sky-500/10 border-sky-500 text-sky-400'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                Developer Only
              </button>
            </div>
          </div>

          {/* Developer Rate */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">Developer Hourly Rate ($/hr)</span>
              <span className="text-white font-mono font-bold">${devRate}/hr</span>
            </div>
            <input
              type="range"
              min="40"
              max="250"
              step="5"
              value={devRate}
              onChange={(e) => setDevRate(e.target.value)}
              className="w-full accent-sky-500 cursor-pointer"
            />
          </div>

          {/* Tester Rate */}
          {scenario === 'both' && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300 font-medium">QA Tester Hourly Rate ($/hr)</span>
                <span className="text-white font-mono font-bold">${testerRate}/hr</span>
              </div>
              <input
                type="range"
                min="30"
                max="180"
                step="5"
                value={testerRate}
                onChange={(e) => setTesterRate(e.target.value)}
                className="w-full accent-indigo-500 cursor-pointer"
              />
            </div>
          )}

          {/* Asset Valuation */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">Commercial Asset Valuation</span>
              <span className="text-white font-mono font-bold">${Number(assetValue).toLocaleString()}</span>
            </div>
            <input
              type="range"
              min="50000"
              max="2000000"
              step="25000"
              value={assetValue}
              onChange={(e) => setAssetValue(e.target.value)}
              className="w-full accent-emerald-500 cursor-pointer"
            />
          </div>

          {/* Records Count */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-300 font-medium">Customer / PII Records Exposed</span>
              <span className="text-white font-mono font-bold">{Number(recordsCount).toLocaleString()} records</span>
            </div>
            <input
              type="range"
              min="5000"
              max="500000"
              step="5000"
              value={recordsCount}
              onChange={(e) => setRecordsCount(e.target.value)}
              className="w-full accent-purple-500 cursor-pointer"
            />
          </div>

          {/* Explanatory Box */}
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 space-y-1">
            <div className="font-bold text-slate-300 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-sky-400" />
              Formula & Methodology (docs/cost_model.md)
            </div>
            <p>
              Expected Loss = Asset Valuation &times; Likelihood (EPSS/KEV) &times; Severity Impact. Fix Cost = Hours &times; Rate.
            </p>
          </div>
        </div>

        {/* Right Charts and Table */}
        <div className="lg:col-span-7 space-y-6">
          {/* Comparison Chart */}
          <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Fix Cost vs Potential Breach Loss by Severity
                </h3>
                <p className="text-xs text-slate-400">Direct visualization of loss mitigation payoff</p>
              </div>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: 10, bottom: 20 }}>
                  <XAxis dataKey="severity" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} tickFormatter={(val) => `$${val >= 1000 ? `${(val/1000).toFixed(0)}k` : val}`} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
                    formatter={(val) => [`$${val.toLocaleString()}`]}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                  <Bar dataKey="breachLoss" fill="#ef4444" radius={[4, 4, 0, 0]} name="Potential Loss ($)" />
                  <Bar dataKey="fixCost" fill="#10b981" radius={[4, 4, 0, 0]} name="Fix Cost ($)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top Highest Financial Risk Findings */}
          <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Top Findings by Potential Breach Loss
            </h3>

            <div className="space-y-2.5">
              {(costData?.top_cost_findings || []).slice(0, 5).map((tf, i) => (
                <div key={i} className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 flex items-center justify-between gap-4 text-xs">
                  <div className="truncate max-w-md space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.2 rounded text-[9.5px] font-bold uppercase ${
                        tf.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400' : 'bg-orange-500/20 text-orange-400'
                      }`}>
                        {tf.severity}
                      </span>
                      <span className="font-bold text-white truncate">{tf.title}</span>
                    </div>
                    <div className="text-[10.5px] text-slate-500 font-mono">
                      Fix Effort: {tf.dev_hours}h Dev + {tf.tester_hours}h QA &bull; EPSS: {(tf.epss * 100).toFixed(1)}%
                    </div>
                  </div>

                  <div className="text-right shrink-0">
                    <div className="font-mono font-bold text-rose-400 text-sm">
                      ${tf.potential_loss.toLocaleString()} loss
                    </div>
                    <div className="text-[10px] text-emerald-400 font-mono">
                      ${tf.fix_cost_both.toLocaleString()} to fix
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
