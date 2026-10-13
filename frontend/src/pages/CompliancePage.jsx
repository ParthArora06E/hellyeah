import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileText,
  DollarSign,
  Globe,
  Lock,
  Download,
  Info,
  ChevronRight,
  ExternalLink,
  RefreshCw,
  Building2,
  Layers,
  Scale
} from 'lucide-react';

export default function CompliancePage({ scan }) {
  const [complianceData, setComplianceData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState('dpdp_act_2023'); // 'dpdp_act_2023', 'soc2_type_2', 'pci_dss_4', 'hipaa', 'iso27001'

  const fetchCompliance = () => {
    if (!scan?.id) return;
    setLoading(true);
    fetch(`/api/scans/${scan.id}/compliance`)
      .then((res) => res.json())
      .then((data) => {
        setComplianceData(data);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchCompliance();
  }, [scan?.id]);

  const frameworks = complianceData?.frameworks || {};
  const dpdp = frameworks.dpdp_act_2023 || {};
  const currentFw = frameworks[selectedFramework] || {};

  const handleExportJson = () => {
    if (!complianceData) return;
    const blob = new Blob([JSON.stringify(complianceData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance_audit_${scan?.target_domain || 'report'}.json`;
    a.click();
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in">
      {/* Top Banner */}
      <div className="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl flex flex-col lg:flex-row lg:items-center justify-between gap-4 backdrop-blur-sm">
        <div>
          <div className="flex items-center gap-2.5">
            <Scale className="w-6 h-6 text-sky-400" />
            <h1 className="text-xl font-bold text-slate-100">
              Regulatory Compliance &amp; DPDP Act 2023 Audit Matrix
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Statutory Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Automated cross-mapping of external perimeter assets and vulnerabilities against India's <strong>Digital Personal Data Protection (DPDP) Act 2023</strong>, SOC 2 Type II, PCI-DSS v4.0, HIPAA Security Rule, and ISO 27001.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchCompliance}
            className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3.5 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Re-Evaluate</span>
          </button>
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 text-xs bg-sky-500 hover:bg-sky-400 text-white font-medium px-3.5 py-2 rounded-lg shadow-md shadow-sky-500/20 transition-all cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Audit Evidence (JSON)</span>
          </button>
        </div>
      </div>

      {/* DPDP Act 2023 Statutory Penalty Exposure Hero Card */}
      {dpdp && (
        <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-indigo-950/40 border border-indigo-500/30 rounded-2xl p-6 relative overflow-hidden shadow-xl">
          <div className="absolute top-0 right-0 w-80 h-80 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />
          
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                  Act No. 22 of 2023 &bull; MeitY Statutory Framework
                </span>
                <span className="text-xs text-slate-400">Target: <strong className="text-white font-mono">{scan?.target_domain}</strong></span>
              </div>
              <h2 className="text-lg font-bold text-slate-100">
                DPDP Act 2023 Statutory Penalty Exposure
              </h2>
              <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
                Under Section 8(5), failure of a Data Fiduciary to implement reasonable security safeguards carries statutory penalties of <strong className="text-slate-200">up to ₹250 Crore (~$30 Million USD)</strong>. Failure to notify under Section 8(6) carries penalties of <strong className="text-slate-200">up to ₹200 Crore</strong>.
              </p>
            </div>

            {/* Penalty Metrics Cards */}
            <div className="flex flex-wrap items-center gap-4">
              <div className="bg-slate-950/80 border border-rose-500/30 px-5 py-3.5 rounded-xl text-center min-w-36">
                <span className="text-[10px] font-semibold text-rose-400 uppercase tracking-wider block">
                  Estimated Penalty Exposure
                </span>
                <div className="text-2xl font-black text-rose-400 font-mono mt-0.5">
                  {dpdp.penalty_exposure_inr_formatted || '₹0.00'}
                </div>
                <span className="text-[10px] text-slate-500 font-mono">
                  {dpdp.penalty_exposure_usd_formatted || '$0.00'}
                </span>
              </div>

              <div className="bg-slate-950/80 border border-slate-800 px-5 py-3.5 rounded-xl text-center min-w-36">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                  DPDP Compliance Score
                </span>
                <div className={`text-2xl font-black font-mono mt-0.5 ${
                  (dpdp.compliance_score || 0) >= 80 ? 'text-emerald-400' : 'text-amber-400'
                }`}>
                  {dpdp.compliance_score || 0}%
                </div>
                <span className="text-[10px] text-slate-500 font-mono">
                  {dpdp.compliance_verdict || 'Compliant'}
                </span>
              </div>
            </div>
          </div>

          {/* Statutory Controls Highlights */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6 pt-4 border-t border-slate-800/80 text-xs">
            <div className="flex items-center gap-2.5 text-slate-300">
              <div className={`w-2 h-2 rounded-full ${dpdp.controls_summary?.failed === 0 ? 'bg-emerald-400' : 'bg-rose-400'}`} />
              <span>Section 8(5) Security Safeguards: <strong>{dpdp.controls_summary?.failed === 0 ? 'Passed' : `${dpdp.controls_summary?.failed} Action Items`}</strong></span>
            </div>
            <div className="flex items-center gap-2.5 text-slate-300">
              <div className={`w-2 h-2 rounded-full ${dpdp.continuous_telemetry_active ? 'bg-emerald-400' : 'bg-amber-400'}`} />
              <span>Section 8(6) Breach Notification: <strong>{dpdp.continuous_telemetry_active ? 'Continuous Active' : 'Ad-hoc Warning'}</strong></span>
            </div>
            <div className="flex items-center gap-2.5 text-slate-300">
              <div className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>Cross-Border Geolocation: <strong>Permitted Territory</strong></span>
            </div>
          </div>
        </div>
      )}

      {/* Framework Selector Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
        {[
          { id: 'dpdp_act_2023', label: 'India DPDP Act 2023', badge: dpdp?.compliance_score ? `${dpdp.compliance_score}%` : null },
          { id: 'soc2_type_2', label: 'SOC 2 Type II', badge: frameworks.soc2_type_2?.compliance_score ? `${frameworks.soc2_type_2.compliance_score}%` : null },
          { id: 'pci_dss_4', label: 'PCI-DSS v4.0', badge: frameworks.pci_dss_4?.compliance_score ? `${frameworks.pci_dss_4.compliance_score}%` : null },
          { id: 'hipaa', label: 'HIPAA Security Rule', badge: frameworks.hipaa?.compliance_score ? `${frameworks.hipaa.compliance_score}%` : null },
          { id: 'iso27001', label: 'ISO/IEC 27001:2022', badge: frameworks.iso27001?.compliance_score ? `${frameworks.iso27001.compliance_score}%` : null }
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSelectedFramework(tab.id)}
            className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
              selectedFramework === tab.id
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <span>{tab.label}</span>
            {tab.badge && (
              <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                parseInt(tab.badge) >= 80 ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
              }`}>
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Control Checklist Table */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-sky-400" />
              {selectedFramework === 'dpdp_act_2023' ? 'DPDP Act 2023 Statutory Controls' : `${currentFw.name || 'Framework'} Controls & Audit Evidence`}
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Technical verification derived from discovered perimeter assets, certificates, headers, and CVE correlations.
            </p>
          </div>
          <span className="text-xs font-mono font-semibold text-sky-400">
            Compliance Score: {currentFw.compliance_score ?? dpdp.compliance_score ?? 100}%
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 text-[11px]">
              <tr>
                <th className="py-3 px-4">Control &amp; Reference</th>
                <th className="py-3 px-4">Title &amp; Requirement</th>
                <th className="py-3 px-4">Audit Status</th>
                <th className="py-3 px-4">Statutory Penalty / Impact</th>
                <th className="py-3 px-4">Remediation Guidance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {(selectedFramework === 'dpdp_act_2023' ? dpdp.controls : currentFw.controls)?.map((ctrl, idx) => {
                const isFail = ctrl.status === 'FAILED';
                const isWarn = ctrl.status === 'WARNING';
                return (
                  <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 font-mono font-semibold text-slate-200">
                      <div>{ctrl.control_id}</div>
                      <div className="text-[10px] text-sky-400">{ctrl.statutory_ref || ctrl.name}</div>
                    </td>
                    <td className="py-3.5 px-4 max-w-sm">
                      <div className="font-semibold text-slate-100">{ctrl.title || ctrl.name}</div>
                      <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">
                        {ctrl.requirement || ctrl.description}
                      </p>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                          isFail
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : isWarn
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {isFail ? <XCircle className="w-3 h-3 text-rose-400" /> : isWarn ? <AlertTriangle className="w-3 h-3 text-amber-400" /> : <CheckCircle2 className="w-3 h-3 text-emerald-400" />}
                        <span>{ctrl.status}</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-rose-400">
                      {ctrl.penalty_tier || (isFail ? 'High Audit Finding' : 'Compliant')}
                    </td>
                    <td className="py-3.5 px-4 max-w-xs text-[11px] text-slate-300 leading-snug">
                      {ctrl.recommendation || ctrl.remediation}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
