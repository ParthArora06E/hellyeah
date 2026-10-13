import React, { useState, useEffect } from 'react';
import { 
  Layers, 
  Search, 
  Filter, 
  Plus, 
  Upload, 
  Edit3, 
  Check, 
  X, 
  Globe, 
  Server, 
  Cloud, 
  ExternalLink,
  ShieldAlert,
  Download,
  Package
} from 'lucide-react';

export default function AssetsPage({ scan }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [critFilter, setCritFilter] = useState('');
  const [activeTab, setActiveTab] = useState('assets'); // 'assets' or 'sbom'
  const [sbomData, setSbomData] = useState(null);

  // Editing state
  const [editingId, setEditingId] = useState(null);
  const [editOwner, setEditOwner] = useState('');
  const [editCriticality, setEditCriticality] = useState(3);

  // Manual Add Modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [newAssetVal, setNewAssetVal] = useState('');
  const [newAssetType, setNewAssetType] = useState('subdomain');
  const [newAssetOwner, setNewAssetOwner] = useState('Unassigned');
  const [newAssetCrit, setNewAssetCrit] = useState(3);

  const fetchAssets = () => {
    if (!scan?.id) return;
    setLoading(true);
    let url = `/api/scans/${scan.id}/assets?`;
    if (typeFilter) url += `asset_type=${typeFilter}&`;
    if (critFilter) url += `criticality=${critFilter}&`;
    if (searchTerm) url += `search=${searchTerm}&`;

    fetch(url)
      .then(r => r.json())
      .then(d => setAssets(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  const fetchSbom = () => {
    if (!scan?.id) return;
    fetch(`/api/scans/${scan.id}/sbom`)
      .then(r => r.json())
      .then(d => setSbomData(d))
      .catch(console.error);
  };

  useEffect(() => {
    fetchAssets();
    fetchSbom();
  }, [scan?.id, typeFilter, critFilter, searchTerm]);

  const handleDownloadSbom = (format) => {
    if (!scan?.id) return;
    fetch(`/api/scans/${scan.id}/sbom/${format}`)
      .then(r => r.json())
      .then(data => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sbom_${format}_${scan.target_domain || 'scan'}.json`;
        a.click();
      });
  };

  const handleSaveEdit = async (assetId) => {
    try {
      const resp = await fetch(`/api/assets/${assetId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: editOwner,
          criticality: editCriticality
        })
      });
      if (resp.ok) {
        setEditingId(null);
        fetchAssets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateAsset = async (e) => {
    e.preventDefault();
    if (!newAssetVal.trim()) return;

    try {
      const resp = await fetch(`/api/scans/${scan.id}/assets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          value: newAssetVal.trim(),
          type: newAssetType,
          owner: newAssetOwner,
          criticality: newAssetCrit,
          source: 'Manual Entry'
        })
      });
      if (resp.ok) {
        setShowAddModal(false);
        setNewAssetVal('');
        fetchAssets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleCSVUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const resp = await fetch(`/api/scans/${scan.id}/assets/csv`, {
        method: 'POST',
        body: formData
      });
      if (resp.ok) {
        fetchAssets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const getAssetIcon = (type) => {
    switch (type) {
      case 'cloud_bucket': return <Cloud className="w-4 h-4 text-amber-400" />;
      case 'ip': return <Server className="w-4 h-4 text-purple-400" />;
      default: return <Globe className="w-4 h-4 text-sky-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-sky-400" />
            Attack-Surface Assets ({assets.length})
          </h1>
          <p className="text-xs text-slate-400">
            Perimeter assets discovered for {scan?.target_domain}. Edit ownership and criticality ratings.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <label className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer transition border border-slate-700">
            <Upload className="w-3.5 h-3.5" />
            <span>Import CSV</span>
            <input type="file" accept=".csv" onChange={handleCSVUpload} className="hidden" />
          </label>

          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-white text-xs font-bold transition shadow-md shadow-sky-500/20 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Asset</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel p-4 rounded-xl flex flex-col md:flex-row items-center gap-3 border-slate-800">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            placeholder="Search domain, IP address, or owner..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-900 text-slate-300 border border-slate-700 rounded-lg px-3 py-2 text-xs focus:outline-none"
          >
            <option value="">All Types</option>
            <option value="domain">Apex Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="ip">IPv4 Address</option>
            <option value="cloud_bucket">Cloud Bucket</option>
          </select>

          <select
            value={critFilter}
            onChange={(e) => setCritFilter(e.target.value)}
            className="bg-slate-900 text-slate-300 border border-slate-700 rounded-lg px-3 py-2 text-xs focus:outline-none"
          >
            <option value="">All Criticality</option>
            <option value="5">Critical (5)</option>
            <option value="4">High (4)</option>
            <option value="3">Medium (3)</option>
            <option value="2">Low (2)</option>
            <option value="1">Minimal (1)</option>
          </select>
        </div>
      </div>

      {/* Sub Tabs: Perimeter Assets vs SBOM */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('assets')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer ${
            activeTab === 'assets' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          Perimeter Assets ({assets.length})
        </button>
        <button
          onClick={() => setActiveTab('sbom')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer flex items-center gap-1.5 ${
            activeTab === 'sbom' ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30' : 'text-slate-400 hover:text-white'
          }`}
        >
          <Package className="w-3.5 h-3.5" />
          <span>External SBOM Components ({sbomData?.total_components || 0})</span>
        </button>
      </div>

      {activeTab === 'assets' ? (
        /* Assets Table */
        <div className="glass-panel rounded-2xl overflow-hidden border-slate-800 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800 text-[10.5px]">
              <tr>
                <th className="py-3 px-4">Asset Value</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">IP / ASN</th>
                <th className="py-3 px-4">Owner</th>
                <th className="py-3 px-4">Criticality</th>
                <th className="py-3 px-4">Technologies & Tags</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {assets.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No assets matching filter criteria.
                  </td>
                </tr>
              ) : (
                assets.map((a) => {
                  const isEditing = editingId === a.id;
                  return (
                    <tr key={a.id} className="hover:bg-slate-900/50 transition">
                      {/* Value */}
                      <td className="py-3.5 px-4 font-mono font-medium text-white">
                        <div className="flex items-center gap-2">
                          {getAssetIcon(a.type)}
                          <span className="truncate max-w-xs">{a.value}</span>
                        </div>
                      </td>

                      {/* Type */}
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 uppercase tracking-wide">
                          {a.type}
                        </span>
                      </td>

                      {/* IP / ASN */}
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        {a.ip_address || a.asn ? (
                          <div className="space-y-0.5">
                            {a.ip_address && (
                              <span className="text-slate-300 block">{a.ip_address}</span>
                            )}
                            {a.asn && (
                              <span className="inline-block px-1.5 py-0.5 rounded text-[9.5px] font-sans font-medium bg-purple-500/10 text-purple-300 border border-purple-500/20">
                                {a.asn}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>

                      {/* Owner */}
                      <td className="py-3.5 px-4">
                        {isEditing ? (
                          <input
                            type="text"
                            value={editOwner}
                            onChange={(e) => setEditOwner(e.target.value)}
                            className="bg-slate-950 border border-sky-500 rounded px-2 py-1 text-xs text-white"
                          />
                        ) : (
                          <span className="text-slate-300 font-medium">{a.owner || 'Unassigned'}</span>
                        )}
                      </td>

                      {/* Criticality */}
                      <td className="py-3.5 px-4">
                        {isEditing ? (
                          <select
                            value={editCriticality}
                            onChange={(e) => setEditCriticality(parseInt(e.target.value))}
                            className="bg-slate-950 border border-sky-500 rounded px-2 py-1 text-xs text-white"
                          >
                            <option value={5}>5 - Critical</option>
                            <option value={4}>4 - High</option>
                            <option value={3}>3 - Medium</option>
                            <option value={2}>2 - Low</option>
                            <option value={1}>1 - Minimal</option>
                          </select>
                        ) : (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            a.criticality >= 4 ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-300'
                          }`}>
                            Level {a.criticality}/5
                          </span>
                        )}
                      </td>

                      {/* Tech & Tags */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-1.5 flex-wrap max-w-xs">
                          {a.technologies && a.technologies.slice(0, 3).map((t, i) => (
                            <span key={i} className="px-1.5 py-0.5 rounded text-[9.5px] font-medium bg-sky-500/10 text-sky-300 border border-sky-500/30">
                              {t}
                            </span>
                          ))}
                          {a.tags && a.tags.filter(tg => ['tls_cert', 'san_verified', 'asn_enriched', 'dns_resolved', 'ptr_record', 'shared-hosting', 'multi-tenant', 'dedicated-ip', 'cms-framework'].includes(tg)).slice(0, 3).map((tg, i) => (
                            <span key={`tag-${i}`} className={`px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider font-semibold border ${
                              tg === 'shared-hosting' || tg === 'multi-tenant'
                                ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}>
                              {tg.replace('_', ' ').replace('-', ' ')}
                            </span>
                          ))}
                          {a.ports && a.ports.length > 0 && (
                            <span className="px-1.5 py-0.5 rounded text-[9.5px] bg-slate-800 text-slate-400 font-mono">
                              Ports: {a.ports.slice(0, 3).join(',')}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Source */}
                      <td className="py-3.5 px-4 text-slate-400 text-[11px] truncate max-w-[130px]">
                        {a.source}
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        {isEditing ? (
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleSaveEdit(a.id)}
                              className="p-1 rounded bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30"
                            >
                              <Check className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => setEditingId(null)}
                              className="p-1 rounded bg-slate-800 text-slate-400 hover:bg-slate-700"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => {
                              setEditingId(a.id);
                              setEditOwner(a.owner || '');
                              setEditCriticality(a.criticality || 3);
                            }}
                            className="p-1 rounded text-slate-400 hover:text-sky-400 hover:bg-slate-800 transition cursor-pointer"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
      ) : (
        /* SBOM Components View */
        <div className="space-y-4">
          <div className="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Package className="w-4 h-4 text-sky-400" />
                External Software Bill of Materials (SBOM)
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Cataloged third-party JavaScript libraries, web servers, and runtime dependencies for {scan?.target_domain}.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleDownloadSbom('cyclonedx')}
                className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-sky-400 font-medium px-3 py-1.5 rounded-lg border border-slate-700 transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>CycloneDX v1.5 JSON</span>
              </button>
              <button
                onClick={() => handleDownloadSbom('spdx')}
                className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-indigo-400 font-medium px-3 py-1.5 rounded-lg border border-slate-700 transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>SPDX v2.3 JSON</span>
              </button>
            </div>
          </div>

          <div className="glass-panel rounded-2xl overflow-hidden border-slate-800 shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800 text-[10.5px]">
                  <tr>
                    <th className="py-3 px-4">Component Name</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Package URL (PURL)</th>
                    <th className="py-3 px-4">License</th>
                    <th className="py-3 px-4">Associated CVEs</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {sbomData?.components?.map((c, i) => (
                    <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3.5 px-4 font-bold text-white font-mono">{c.name}</td>
                      <td className="py-3.5 px-4 font-mono text-sky-400">{c.version}</td>
                      <td className="py-3.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono uppercase">
                          {c.category}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[10px] text-slate-400">{c.purl}</td>
                      <td className="py-3.5 px-4 font-mono text-[11px] text-slate-300">{c.license}</td>
                      <td className="py-3.5 px-4">
                        {c.vulnerabilities?.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {c.vulnerabilities.map((v, vi) => (
                              <span key={vi} className="px-1.5 py-0.2 rounded text-[9.5px] bg-rose-500/20 text-rose-300 font-mono font-bold">
                                {v}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-emerald-400 text-[10px] flex items-center gap-1">
                            <Check className="w-3 h-3" /> None detected
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Manual Asset Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-bold text-white text-sm">Add Perimeter Asset</h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-500 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateAsset} className="space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Asset Value / Host *</label>
                <input
                  type="text"
                  placeholder="e.g. portal.example.com"
                  value={newAssetVal}
                  onChange={(e) => setNewAssetVal(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white font-mono"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Asset Type</label>
                <select
                  value={newAssetType}
                  onChange={(e) => setNewAssetType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white"
                >
                  <option value="subdomain">Subdomain</option>
                  <option value="ip">IP Address</option>
                  <option value="cloud_bucket">Cloud Bucket</option>
                  <option value="endpoint">Web Endpoint</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Owner / Department</label>
                <input
                  type="text"
                  placeholder="e.g. Platform Engineering"
                  value={newAssetOwner}
                  onChange={(e) => setNewAssetOwner(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Criticality Level (1 to 5)</label>
                <input
                  type="number"
                  min={1}
                  max={5}
                  value={newAssetCrit}
                  onChange={(e) => setNewAssetCrit(parseInt(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-sky-500 hover:bg-sky-400 text-white shadow-md shadow-sky-500/20"
                >
                  Save Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
