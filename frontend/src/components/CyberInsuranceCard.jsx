import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  DollarSign,
  Download,
  CheckCircle2,
  XCircle,
  FileText,
  Percent,
  Sparkles,
  HelpCircle
} from 'lucide-react';

export default function CyberInsuranceCard({ scanId }) {
  const [insuranceData, setInsuranceData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    fetch(`/api/scans/${scanId}/insurance`)
      .then((r) => r.json())
      .then((d) => setInsuranceData(d))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scanId]);

  if (!insuranceData || insuranceData.error) return null;

  const score = insuranceData.insurability_score ?? 100;
  const surcharge = insuranceData.estimated_premium_surcharge_pct ?? 0;

  const handleDownloadUnderwriterPackage = () => {
    const blob = new Blob([JSON.stringify(insuranceData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber_insurance_underwriter_package_${insuranceData.target_domain || 'audit'}.json`;
    a.click();
  };

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 relative overflow-hidden backdrop-blur-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
            </span>
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Cyber Insurance Readiness &amp; Underwriter Score
              </h3>
              <p className="text-[11px] text-slate-400">
                Commercial carrier insurability model (Coalition, Chubb, Cowbell, Travelers criteria)
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={handleDownloadUnderwriterPackage}
          className="flex items-center gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3.5 py-2 rounded-lg shadow-md shadow-emerald-600/20 transition-all cursor-pointer"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Underwriter Package</span>
        </button>
      </div>

      {/* Hero Score Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Insurability Index</span>
          <div className={`text-3xl font-black font-mono mt-1 ${
            score >= 85 ? 'text-emerald-400' : score >= 65 ? 'text-amber-400' : 'text-rose-400'
          }`}>
            {score}/100
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            {score >= 85 ? 'Tier 1 Preferred' : 'Surplus Lines'}
          </span>
        </div>

        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Underwriter Decision</span>
          <div className="text-sm font-bold text-slate-200 mt-2 truncate">
            {insuranceData.disposition || 'Preferred'}
          </div>
          <span className="text-[10px] text-slate-500">Carrier Guidelines</span>
        </div>

        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Estimated Premium Load</span>
          <div className={`text-2xl font-black font-mono mt-1 ${
            surcharge === 0 ? 'text-emerald-400' : 'text-rose-400'
          }`}>
            {surcharge > 0 ? `+${surcharge}%` : '0% Load'}
          </div>
          <span className="text-[10px] text-slate-500">Pricing Surcharge</span>
        </div>

        <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800 text-center">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Recommended Retention</span>
          <div className="text-2xl font-black text-indigo-400 font-mono mt-1">
            {insuranceData.recommended_policy_retention || '$10,000'}
          </div>
          <span className="text-[10px] text-slate-500">Policy Deductible</span>
        </div>
      </div>

      {/* Underwriter Technical Warranties Checklist */}
      <div className="pt-2">
        <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
          Underwriter Technical Warranties
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
          {insuranceData.underwriter_warranties?.map((w, i) => (
            <div
              key={i}
              className={`p-2.5 rounded-lg border flex items-center justify-between ${
                w.met
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-slate-200'
                  : 'bg-rose-950/20 border-rose-500/30 text-rose-300'
              }`}
            >
              <div className="flex items-center gap-2">
                {w.met ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                )}
                <span className="text-[11px] font-medium">{w.warranty}</span>
              </div>
              <span className="text-[10px] font-mono opacity-70 uppercase">{w.criticality}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
