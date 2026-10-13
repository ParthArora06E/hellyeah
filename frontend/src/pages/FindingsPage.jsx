import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  Flame, 
  Search, 
  Filter, 
  CheckCircle, 
  Clock, 
  ShieldCheck, 
  ExternalLink,
  ChevronRight,
  X,
  FileCode,
  DollarSign
} from 'lucide-react';
import RemediationDrawer from '../components/RemediationDrawer';
import AttackPathGraph from '../components/AttackPathGraph';

export default function FindingsPage({ scan }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [kevFilter, setKevFilter] = useState(false);
  const [showAttackGraph, setShowAttackGraph] = useState(false);

  // Selected finding for detailed side drawer or remediation
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [remediationFinding, setRemediationFinding] = useState(null);

  const fetchFindings = () => {
    if (!scan?.id) return;
    setLoading(true);
    let url = `/api/scans/${scan.id}/findings?`;
    if (sevFilter) url += `severity=${sevFilter}&`;
    if (statusFilter) url += `status=${statusFilter}&`;
    if (kevFilter) url += `is_kev=true&`;
    if (searchTerm) url += `search=${searchTerm}&`;

    fetch(url)
      .then(r => r.json())
      .then(d => setFindings(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchFindings();
  }, [scan?.id, sevFilter, statusFilter, kevFilter, searchTerm]);

  const handleStatusChange = async (findingId, newStatus) => {
    try {
      const resp = await fetch(`/api/findings/${findingId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
      if (resp.ok) {
        fetchFindings();
        if (selectedFinding?.id === findingId) {
          setSelectedFinding(prev => ({ ...prev, status: newStatus }));
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-rose-500" />
            Vulnerability Findings ({findings.length})
          </h1>
          <p className="text-xs text-slate-400">
            Ranked findings for {scan?.target_domain}. KEV flagged vulnerabilities represent immediate active threats.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAttackGraph(!showAttackGraph)}
            className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-rose-400 font-medium px-3.5 py-2 rounded-xl border border-slate-700 transition cursor-pointer"
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>{showAttackGraph ? 'Hide Attack Path Graph' : 'Attack Path Topology Graph'}</span>
          </button>
        </div>
      </div>

      {showAttackGraph && <AttackPathGraph scanId={scan?.id} />}

      {/* Filter Bar */}
      <div className="glass-panel p-4 rounded-xl flex flex-col md:flex-row items-center gap-3 border-slate-800">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            placeholder="Search vulnerability title, CVE ID, or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <select
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value)}
            className="bg-slate-900 text-slate-300 border border-slate-700 rounded-lg px-3 py-2 text-xs focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 text-slate-300 border border-slate-700 rounded-lg px-3 py-2 text-xs focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Fixed">Fixed</option>
            <option value="Accepted Risk">Accepted Risk</option>
          </select>

          <button
            onClick={() => setKevFilter(!kevFilter)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-bold transition cursor-pointer border ${
              kevFilter
                ? 'bg-rose-600 text-white border-rose-500 glow-badge-red'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-white'
            }`}
          >
            <Flame className="w-3.5 h-3.5 fill-current" />
            <span>CISA KEV Only</span>
          </button>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {findings.length === 0 ? (
          <div className="glass-panel p-12 text-center text-slate-500 rounded-2xl border-slate-800">
            No vulnerabilities matching current filters.
          </div>
        ) : (
          findings.map((f, idx) => (
            <div
              key={f.id || idx}
              onClick={() => setSelectedFinding(f)}
              className="glass-panel glass-panel-hover rounded-xl p-4 border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer"
            >
              <div className="space-y-1.5 max-w-3xl">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    f.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                    f.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                    f.severity === 'Medium' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                    'bg-sky-500/20 text-sky-400'
                  }`}>
                    {f.severity}
                  </span>

                  {f.is_kev && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-black tracking-wide bg-red-600 text-white flex items-center gap-1 glow-badge-red">
                      <Flame className="w-3 h-3 fill-current" /> CISA KEV
                    </span>
                  )}

                  {f.cve_ids && f.cve_ids.length > 0 && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-sky-400 font-mono border border-slate-700">
                      {f.cve_ids.join(', ')}
                    </span>
                  )}

                  <h3 className="text-xs font-bold text-white hover:text-sky-400 transition">
                    {f.title}
                  </h3>
                </div>

                <p className="text-[11.5px] text-slate-400 line-clamp-1">{f.description}</p>

                <div className="flex items-center gap-3 text-[10.5px] text-slate-500 font-mono">
                  <span>CVSS: <b className="text-slate-300">{f.cvss_score || 'N/A'}</b></span>
                  <span>&bull;</span>
                  <span>EPSS Exploit Prob: <b className="text-slate-300">{(f.epss_score * 100).toFixed(1)}%</b></span>
                  <span>&bull;</span>
                  <span>Confidence: <b className="text-slate-300">{f.confidence}</b></span>
                </div>
              </div>

              {/* Status and Action */}
              <div className="flex items-center gap-3 shrink-0" onClick={(e) => e.stopPropagation()}>
                <div className="text-right">
                  <div className="text-[10px] text-slate-500">Fix Cost</div>
                  <div className="text-xs font-mono font-bold text-emerald-400">
                    ${f.estimated_fix_cost || 150}
                  </div>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setRemediationFinding(f);
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition cursor-pointer"
                  title="Open Remediation Patch & Verification Probe"
                >
                  <FileCode className="w-3.5 h-3.5" />
                  <span>Remediate & Verify</span>
                </button>

                <select
                  value={f.status}
                  onChange={(e) => handleStatusChange(f.id, e.target.value)}
                  className={`text-xs font-bold rounded-lg px-2.5 py-1.5 border focus:outline-none cursor-pointer ${
                    f.status === 'Fixed' || f.status === 'Remediated' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                    f.status === 'Accepted Risk' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                    'bg-slate-800 text-slate-300 border-slate-700'
                  }`}
                >
                  <option value="Open">Open</option>
                  <option value="Fixed">Fixed</option>
                  <option value="Remediated">Remediated</option>
                  <option value="Accepted Risk">Accepted Risk</option>
                </select>

                <ChevronRight className="w-4 h-4 text-slate-500" />
              </div>
            </div>
          ))
        )}
      </div>

      {/* Side Drawer: Detailed Evidence & Remediation */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                  selectedFinding.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400' : 'bg-orange-500/20 text-orange-400'
                }`}>
                  {selectedFinding.severity}
                </span>
                {selectedFinding.is_kev && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-black bg-red-600 text-white">
                    CISA KEV WEAPONIZED
                  </span>
                )}
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-500 hover:text-white p-1 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2">
              <h2 className="text-base font-bold text-white leading-snug">{selectedFinding.title}</h2>
              <p className="text-xs text-slate-300 leading-relaxed">{selectedFinding.description}</p>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono">
              <div>
                <span className="text-[10px] text-slate-500 uppercase">CVSS Base Score</span>
                <div className="text-sm font-bold text-white">{selectedFinding.cvss_score || 'N/A'}/10.0</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">EPSS Probability</span>
                <div className="text-sm font-bold text-sky-400">{(selectedFinding.epss_score * 100).toFixed(2)}% in 30d</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Estimated Fix Effort</span>
                <div className="text-sm font-bold text-emerald-400">{selectedFinding.fix_hours_dev}h Dev + {selectedFinding.fix_hours_tester}h QA</div>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase">Compliance Mapping</span>
                <div className="text-sm font-bold text-purple-400 truncate">{selectedFinding.owasp_category || 'OWASP A05'}</div>
              </div>
            </div>

            {/* Remediation Guidance */}
            <div className="space-y-2 bg-emerald-500/5 border border-emerald-500/20 p-4 rounded-xl">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                <CheckCircle className="w-4 h-4" />
                Remediation Guidance
              </div>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {selectedFinding.remediation_text || 'Deploy the latest vendor patch and verify configuration.'}
              </p>
            </div>

            {/* Technical Evidence */}
            {selectedFinding.evidence && Object.keys(selectedFinding.evidence).length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-slate-400 font-bold text-xs uppercase tracking-wider">
                  <FileCode className="w-4 h-4 text-sky-400" />
                  Forensic Evidence & Banner
                </div>
                <pre className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedFinding.evidence, null, 2)}
                </pre>
              </div>
            )}

            {/* External References */}
            {selectedFinding.references && selectedFinding.references.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <span className="text-[11px] font-semibold text-slate-400 uppercase">Official Advisories</span>
                <div className="space-y-1">
                  {selectedFinding.references.map((r, i) => (
                    <a
                      key={i}
                      href={r}
                      target="_blank"
                      rel="noreferrer"
                      className="text-xs text-sky-400 hover:underline flex items-center gap-1.5 truncate"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{r}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Action button to open Remediation Suite */}
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={() => {
                  const target = selectedFinding;
                  setSelectedFinding(null);
                  setRemediationFinding(target);
                }}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-bold text-xs bg-emerald-600 hover:bg-emerald-500 text-white transition cursor-pointer shadow-lg shadow-emerald-600/20"
              >
                <FileCode className="w-4 h-4" />
                <span>Open Remediation Patch & Verification Suite</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Drawer */}
      {remediationFinding && (
        <RemediationDrawer
          finding={remediationFinding}
          onClose={() => setRemediationFinding(null)}
          onFindingUpdated={(updatedFinding) => {
            fetchFindings();
            setRemediationFinding(null);
          }}
        />
      )}
    </div>
  );
}
