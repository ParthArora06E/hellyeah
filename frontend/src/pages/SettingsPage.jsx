import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Key, 
  ShieldCheck, 
  CheckCircle, 
  AlertCircle, 
  Puzzle, 
  History, 
  RefreshCw,
  Sliders,
  DollarSign,
  Radio,
  Zap,
  Globe,
  Copy,
  Check,
  Code,
  FileCode,
  Plus,
  Shield,
  Server,
  ChevronDown,
  ChevronUp,
  Search
} from 'lucide-react';

export default function SettingsPage() {
  const [settingsData, setSettingsData] = useState(null);
  const [plugins, setPlugins] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(false);

  // Key update state
  const [selectedKey, setSelectedKey] = useState(null);
  const [keyValue, setKeyValue] = useState('');

  const loadData = () => {
    setLoading(true);
    Promise.all([
      fetch('/api/settings').then(r => r.json()),
      fetch('/api/plugins').then(r => r.json()),
      fetch('/api/audit-logs').then(r => r.json())
    ])
      .then(([s, p, l]) => {
        setSettingsData(s);
        setPlugins(p);
        setAuditLogs(l);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveKey = async (e) => {
    e.preventDefault();
    if (!selectedKey || !keyValue.trim()) return;

    try {
      const resp = await fetch('/api/settings/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          key_name: selectedKey,
          key_value: keyValue.trim()
        })
      });
      if (resp.ok) {
        setSelectedKey(null);
        setKeyValue('');
        loadData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
          <Settings className="w-5 h-5 text-sky-400" />
          Settings, Integrations & Audit Logs
        </h1>
        <p className="text-xs text-slate-400">
          Manage threat intelligence API keys, operational cost parameters, drop-in plugins, and immutable outbound audit logs.
        </p>
      </div>

      {/* Grid: API Keys + Operational Defaults */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Key Store */}
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-sky-400" />
              API Key Store & Integrations
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">Graceful Degradation</span>
          </div>

          <div className="space-y-2.5">
            {settingsData?.api_keys && Object.entries(settingsData.api_keys).map(([k, info]) => (
              <div key={k} className="bg-slate-900/80 p-3 rounded-xl border border-slate-800 flex items-center justify-between gap-3 text-xs">
                <div className="truncate">
                  <div className="font-mono font-bold text-white">{k}</div>
                  <div className="text-[10.5px] text-slate-500 truncate font-mono">
                    {info.configured ? info.masked : 'Missing key (module will skip gracefully)'}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    info.configured ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  }`}>
                    {info.configured ? 'Configured' : 'Missing Key'}
                  </span>

                  <button
                    onClick={() => {
                      setSelectedKey(k);
                      setKeyValue('');
                    }}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition cursor-pointer"
                  >
                    Edit
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Operational & Financial Defaults */}
        <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-emerald-400" />
              Financial & Cost Model Defaults
            </h3>
            <span className="text-[10px] text-slate-500 font-mono">Cost-of-Risk Engine</span>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Standard baseline rates used to calculate financial remediation costs and potential breach exposure during automated scans.
          </p>

          <div className="grid grid-cols-2 gap-3 pt-1">
            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10.5px] text-slate-500 uppercase font-semibold">Dev Hourly Rate</span>
              <div className="text-base font-bold font-mono text-white">
                ${settingsData?.rates?.dev_rate || 85}/hr
              </div>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10.5px] text-slate-500 uppercase font-semibold">QA Tester Rate</span>
              <div className="text-base font-bold font-mono text-white">
                ${settingsData?.rates?.tester_rate || 65}/hr
              </div>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10.5px] text-slate-500 uppercase font-semibold">Base Asset Valuation</span>
              <div className="text-base font-bold font-mono text-emerald-400">
                ${(settingsData?.rates?.asset_value || 250000).toLocaleString()}
              </div>
            </div>

            <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <span className="text-[10.5px] text-slate-500 uppercase font-semibold">Reporting Currency</span>
              <div className="text-base font-bold font-mono text-sky-400">
                {settingsData?.rates?.currency || 'USD'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Discovered Plugins Registry */}
      <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Puzzle className="w-4 h-4 text-purple-400" />
            Drop-in Plugins Registry (plugins/ directory)
          </h3>
          <span className="text-[10px] text-slate-500 font-mono">{Object.keys(plugins).length} Plugins Loaded</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {Object.entries(plugins).map(([name, p]) => (
            <div key={name} className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white font-mono">{name}</span>
                <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 font-bold uppercase">
                  {p.category || 'Plugin'}
                </span>
              </div>
              <p className="text-[11px] text-slate-400">{p.description}</p>
              <div className="text-[10px] text-slate-500 font-mono">
                Author: {p.author} &bull; File: {p.file}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Outbound Audit Logs Viewer */}
      <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <History className="w-4 h-4 text-sky-400" />
            Immutable Outbound Audit Trail
          </h3>
          <button onClick={loadData} className="text-slate-400 hover:text-white p-1">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="h-60 bg-slate-950 p-3 rounded-xl border border-slate-800 overflow-y-auto space-y-1.5 font-mono text-[11px]">
          {auditLogs.length === 0 ? (
            <div className="text-slate-600 text-center py-8">No outbound actions logged yet.</div>
          ) : (
            auditLogs.map((log) => (
              <div key={log.id} className="flex items-center gap-3 text-slate-300 border-b border-slate-900 pb-1">
                <span className="text-slate-600 text-[10px] shrink-0">{new Date(log.timestamp).toLocaleTimeString()}</span>
                <span className="text-sky-400 font-bold shrink-0">[{log.action}]</span>
                <span className="text-white truncate max-w-xs">{log.target}</span>
                <span className="text-slate-500 truncate flex-1">{log.details}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* IP Rotator & Obfuscation Engine Card */}
      <IPRotatorControlCard />

      {/* Custom Declarative Detection Rules Engine Card */}
      <CustomRulesControlCard />

      {/* Key Edit Modal */}
      {selectedKey && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="font-bold text-white text-sm">Update {selectedKey}</h3>
            <form onSubmit={handleSaveKey} className="space-y-4">
              <input
                type="text"
                placeholder={`Enter new key for ${selectedKey}`}
                value={keyValue}
                onChange={(e) => setKeyValue(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white font-mono"
                required
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedKey(null)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-sky-500 hover:bg-sky-400 text-white"
                >
                  Save Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function IPRotatorControlCard() {
  const [stats, setStats] = useState(null);
  const [headers, setHeaders] = useState({});
  const [loading, setLoading] = useState(false);
  const [benchmarkResult, setBenchmarkResult] = useState(null);
  const [rankResult, setRankResult] = useState(null);
  const [poolData, setPoolData] = useState(null);
  const [showPoolTable, setShowPoolTable] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [userPoolLoading, setUserPoolLoading] = useState(false);
  const [userPoolMsg, setUserPoolMsg] = useState('');

  const fetchStats = async () => {
    try {
      const [sRes, hRes] = await Promise.all([
        fetch('/api/rotator/stats'),
        fetch('/headers')
      ]);
      if (sRes.ok) setStats(await sRes.json());
      if (hRes.ok) setHeaders(await hRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchPool = async () => {
    try {
      const res = await fetch('/api/rotator/pool');
      if (res.ok) {
        setPoolData(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchPool();
    const interval = setInterval(fetchStats, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleForceRotate = async () => {
    setLoading(true);
    try {
      await fetch('/api/rotator/rotate-now', { method: 'POST' });
      await fetchStats();
      await fetchPool();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleToggle = async () => {
    try {
      await fetch(`/api/rotator/toggle?enabled=${!stats?.enabled}`, { method: 'POST' });
      await fetchStats();
    } catch (e) {
      console.error(e);
    }
  };

  const handleLoadUserPool = async () => {
    setUserPoolLoading(true);
    try {
      const res = await fetch('/api/rotator/load-user-pool', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setUserPoolMsg(`✓ 100 Verified User Proxies Activated!`);
        setTimeout(() => setUserPoolMsg(''), 4500);
        await fetchStats();
        await fetchPool();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setUserPoolLoading(false);
    }
  };

  const handleBenchmarkGenerate = async () => {
    setBenchmarkResult({ loading: true });
    try {
      const res = await fetch('/generate-ips?count=10000');
      if (res.ok) {
        const data = await res.json();
        setBenchmarkResult(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleRankAndTransfer = async () => {
    setRankResult({ loading: true });
    try {
      const res = await fetch('/rank-and-transfer?count=10000');
      if (res.ok) {
        const data = await res.json();
        setRankResult(data);
        await fetchStats();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const filteredPool = poolData?.items?.filter(item => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return (
      item.ip?.toLowerCase().includes(q) ||
      String(item.port).includes(q) ||
      item.country?.toLowerCase().includes(q) ||
      item.protocol?.toLowerCase().includes(q) ||
      item.isp?.toLowerCase().includes(q) ||
      item.anonymity?.toLowerCase().includes(q)
    );
  }) || [];

  return (
    <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-5">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              IP Rotator &amp; Outbound Traffic Obfuscation Engine
            </h3>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10.5px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              100 User Proxies Loaded
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Rotates through your 100 verified proxy nodes &amp; spoofed client headers on micro-intervals (0.6s) to bypass WAF bans, IP throttling, and rate limits.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleLoadUserPool}
            disabled={userPoolLoading}
            title="Reload/Reset active pool to the 100 user proxies"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30 hover:bg-purple-500/25 transition cursor-pointer"
          >
            <Shield className={`w-3.5 h-3.5 ${userPoolLoading ? 'animate-spin' : ''}`} />
            <span>Reload 100 Proxies</span>
          </button>
          <button
            onClick={handleToggle}
            className={`px-3 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer ${
              stats?.enabled 
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30' 
                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'
            }`}
          >
            {stats?.enabled ? 'Rotator Active' : 'Rotator Paused'}
          </button>
          <button
            onClick={handleForceRotate}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30 hover:bg-sky-500/30 transition cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Rotate Now</span>
          </button>
        </div>
      </div>

      {userPoolMsg && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs px-3.5 py-2 rounded-xl flex items-center justify-between animate-fadeIn">
          <span>{userPoolMsg}</span>
        </div>
      )}

      {/* Active Exit Node Spotlight */}
      {stats?.current_meta && (
        <div className="bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-950 p-4 rounded-xl border border-slate-800/90 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
              <Globe className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Current Exit Proxy:</span>
                <span className="text-sm font-mono font-bold text-emerald-300">{stats?.current_meta?.proxy_url || stats?.ip}</span>
              </div>
              <p className="text-xs text-slate-400 truncate max-w-md">
                {stats?.current_meta?.isp || stats?.current_meta?.org || 'High-Anonymity Proxy Node'} ({stats?.current_meta?.asn || 'Public ASN'})
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded-md font-mono bg-sky-500/15 text-sky-300 border border-sky-500/25 uppercase font-bold">
              {stats?.current_meta?.protocol || 'HTTP'}
            </span>
            <span className="px-2 py-0.5 rounded-md font-mono bg-indigo-500/15 text-indigo-300 border border-indigo-500/25 font-bold">
              {stats?.current_meta?.country || 'GLOBAL'}
            </span>
            <span className="px-2 py-0.5 rounded-md font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/25">
              {stats?.current_meta?.anonymity || 'elite'}
            </span>
            <span className="px-2 py-0.5 rounded-md font-mono bg-amber-500/15 text-amber-300 border border-amber-500/25">
              {stats?.current_meta?.latency_ms ? `${stats.current_meta.latency_ms}ms` : 'fast'}
            </span>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
          <span className="text-[10.5px] text-slate-500 uppercase font-semibold block">Current Active IP</span>
          <span className="text-sm font-mono font-bold text-emerald-400">{stats?.ip || 'Rotating...'}</span>
        </div>
        <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
          <span className="text-[10.5px] text-slate-500 uppercase font-semibold block">Rotation Interval</span>
          <span className="text-sm font-mono font-bold text-white">{stats?.rotation_interval || 0.6}s</span>
        </div>
        <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
          <span className="text-[10.5px] text-slate-500 uppercase font-semibold block">Rotations Completed</span>
          <span className="text-sm font-mono font-bold text-sky-400">#{stats?.rotations_completed || 0}</span>
        </div>
        <div className="bg-slate-900/80 p-3.5 rounded-xl border border-slate-800">
          <span className="text-[10.5px] text-slate-500 uppercase font-semibold block">Pool Mode / Size</span>
          <span className="text-sm font-mono font-bold text-purple-400">
            {stats?.mode} ({stats?.pool_size || 100} Proxies)
          </span>
        </div>
      </div>

      {/* 100 User Proxies Inventory Explorer Bar */}
      <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/40">
        <button
          onClick={() => {
            setShowPoolTable(!showPoolTable);
            if (!poolData) fetchPool();
          }}
          className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-800/40 transition cursor-pointer text-left"
        >
          <div className="flex items-center gap-2.5">
            <Server className="w-4 h-4 text-purple-400" />
            <span className="text-xs font-bold text-slate-200">
              User Proxy Pool Inventory ({poolData?.total_items || 100} Configured Proxies)
            </span>
            {poolData?.protocol_breakdown && (
              <div className="hidden sm:flex items-center gap-1.5 ml-2">
                {Object.entries(poolData.protocol_breakdown).map(([proto, count]) => (
                  <span key={proto} className="text-[10px] px-1.5 py-0.2 bg-slate-800 text-slate-400 rounded border border-slate-700/60 uppercase font-mono">
                    {proto}: {count}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span>{showPoolTable ? 'Hide Inventory' : 'View All 100 Proxies'}</span>
            {showPoolTable ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {showPoolTable && (
          <div className="p-4 border-t border-slate-800/80 space-y-3 bg-slate-950/60">
            {/* Search Filter */}
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter 100 proxies by IP, Country, Protocol, ISP..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500/50 font-mono"
                />
              </div>
              <span className="text-[11px] text-slate-500 font-mono shrink-0">
                Showing {filteredPool.length} of {poolData?.total_items || 100}
              </span>
            </div>

            {/* Scrollable Proxy List Table */}
            <div className="max-h-72 overflow-y-auto rounded-lg border border-slate-800 scrollbar-thin">
              <table className="w-full text-left text-[11px]">
                <thead className="bg-slate-900/90 text-slate-400 uppercase font-mono sticky top-0 border-b border-slate-800 z-10">
                  <tr>
                    <th className="py-2 px-3">#</th>
                    <th className="py-2 px-3">Proxy Endpoint</th>
                    <th className="py-2 px-3">Protocol</th>
                    <th className="py-2 px-3">Country</th>
                    <th className="py-2 px-3">Anonymity</th>
                    <th className="py-2 px-3">Latency</th>
                    <th className="py-2 px-3">ISP / Organization</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredPool.map((item, idx) => {
                    const isActive = item.ip === stats?.ip;
                    return (
                      <tr 
                        key={`${item.ip}-${item.port}-${idx}`} 
                        className={`transition ${isActive ? 'bg-emerald-500/15 font-semibold text-emerald-200' : 'hover:bg-slate-900/60'}`}
                      >
                        <td className="py-1.5 px-3 font-mono text-slate-500">{idx + 1}</td>
                        <td className="py-1.5 px-3 font-mono flex items-center gap-1.5">
                          <span>{item.ip}:{item.port}</span>
                          {isActive && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 uppercase">
                              Active Now
                            </span>
                          )}
                        </td>
                        <td className="py-1.5 px-3 uppercase font-mono text-[10px]">
                          <span className={`px-1.5 py-0.5 rounded ${
                            item.protocol === 'https' ? 'bg-emerald-500/20 text-emerald-300' :
                            item.protocol === 'socks5' ? 'bg-purple-500/20 text-purple-300' :
                            item.protocol === 'socks4' ? 'bg-amber-500/20 text-amber-300' :
                            'bg-sky-500/20 text-sky-300'
                          }`}>
                            {item.protocol}
                          </span>
                        </td>
                        <td className="py-1.5 px-3 font-mono font-bold text-slate-200">{item.country}</td>
                        <td className="py-1.5 px-3 text-slate-400 capitalize">{item.anonymity}</td>
                        <td className="py-1.5 px-3 font-mono text-slate-400">{item.latency_ms}ms</td>
                        <td className="py-1.5 px-3 truncate max-w-xs text-slate-400" title={item.isp || item.org}>
                          {item.isp || item.org || '—'}
                        </td>
                      </tr>
                    );
                  })}
                  {filteredPool.length === 0 && (
                    <tr>
                      <td colSpan={7} className="text-center py-6 text-slate-500">
                        No proxies matching "{searchTerm}"
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Action Benchmarks */}
      <div className="flex flex-wrap items-center gap-3 pt-1">
        <button
          onClick={handleBenchmarkGenerate}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition cursor-pointer"
        >
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span>Benchmark Generate (10,000 IPs)</span>
        </button>

        <button
          onClick={handleRankAndTransfer}
          className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition cursor-pointer"
        >
          <Globe className="w-3.5 h-3.5 text-sky-400" />
          <span>Rank &amp; Save 10k Pool (ranked_ips.json)</span>
        </button>

        {benchmarkResult && (
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
            ✓ Generated 10,000 IPs in {benchmarkResult.duration_ms}ms
          </span>
        )}

        {rankResult && (
          <span className="text-xs font-mono text-sky-400 bg-sky-500/10 px-2.5 py-1 rounded-lg border border-sky-500/20">
            ✓ Saved {rankResult.metrics?.saved_count} ranked IPs in {rankResult.metrics?.duration_ms}ms
          </span>
        )}
      </div>

      {/* Active Spoofed Headers Preview */}
      <div className="space-y-2 pt-1">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-slate-300">Live Outbound Request Headers (Injected by AsyncHttpClient):</span>
          <span className="text-[10px] text-slate-500 font-mono">Bypasses IP Tracking &amp; Rate Limits</span>
        </div>
        <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
          {Object.entries(headers).length > 0 ? (
            Object.entries(headers).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between bg-slate-900/60 px-2.5 py-1.5 rounded border border-slate-800/80">
                <span className="text-slate-400 font-semibold">{k}:</span>
                <span className="text-emerald-400 font-bold">{v}</span>
              </div>
            ))
          ) : (
            <div className="col-span-2 text-center text-slate-600 py-2">No active headers (Rotator disabled)</div>
          )}
        </div>
      </div>
    </div>
  );
}

function CustomRulesControlCard() {
  const [rules, setRules] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [newRule, setNewRule] = useState({
    id: '',
    name: '',
    severity: 'Medium',
    cvss: 5.3,
    path: '',
    matcher_type: 'body_contains',
    matcher_pattern: '',
    description: '',
    remediation: ''
  });

  const fetchRules = async () => {
    try {
      const res = await fetch('/api/rules/custom');
      if (res.ok) setRules(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleAddRule = async (e) => {
    e.preventDefault();
    if (!newRule.id || !newRule.name || !newRule.path) return;
    setLoading(true);
    try {
      const res = await fetch('/api/rules/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newRule)
      });
      if (res.ok) {
        setShowForm(false);
        setNewRule({
          id: '',
          name: '',
          severity: 'Medium',
          cvss: 5.3,
          path: '',
          matcher_type: 'body_contains',
          matcher_pattern: '',
          description: '',
          remediation: ''
        });
        fetchRules();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel rounded-2xl p-6 border-slate-800 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <FileCode className="w-4 h-4 text-purple-400" />
            Custom Declarative Detection Rules Engine (Nuclei-Style Safe Probes)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Define custom safe perimeter probes for internal diagnostics, compliance files, and leaked microservices.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-2 py-0.5 rounded-full text-[10px] bg-purple-500/10 text-purple-300 font-mono border border-purple-500/30">
            {rules.length} Rules Active
          </span>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold cursor-pointer transition shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showForm ? 'Cancel' : 'New Rule'}</span>
          </button>
        </div>
      </div>

      {showForm && (
        <form onSubmit={handleAddRule} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
          <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Create Custom Safe Detection Rule</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Rule ID (Slug):</label>
              <input
                type="text"
                required
                placeholder="e.g. detect-git-head"
                value={newRule.id}
                onChange={e => setNewRule({ ...newRule, id: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white font-mono text-xs"
              />
            </div>
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Rule Title:</label>
              <input
                type="text"
                required
                placeholder="e.g. Exposed Git HEAD File"
                value={newRule.name}
                onChange={e => setNewRule({ ...newRule, name: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white text-xs"
              />
            </div>
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Target Path:</label>
              <input
                type="text"
                required
                placeholder="e.g. /.git/HEAD or /metrics"
                value={newRule.path}
                onChange={e => setNewRule({ ...newRule, path: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white font-mono text-xs"
              />
            </div>
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Matcher Type:</label>
              <select
                value={newRule.matcher_type}
                onChange={e => setNewRule({ ...newRule, matcher_type: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white text-xs"
              >
                <option value="body_contains">body_contains (String exists in response body)</option>
                <option value="body_absent">body_absent (String missing from body or 404)</option>
                <option value="status_code">status_code (Exact HTTP response status)</option>
                <option value="header_contains">header_contains (Header key/value pattern)</option>
              </select>
            </div>
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Matcher Pattern:</label>
              <input
                type="text"
                required
                placeholder="e.g. ref: refs/ or 200"
                value={newRule.matcher_pattern}
                onChange={e => setNewRule({ ...newRule, matcher_pattern: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white font-mono text-xs"
              />
            </div>
            <div>
              <label className="text-slate-400 text-[11px] block mb-1">Severity &amp; CVSS:</label>
              <div className="flex gap-2">
                <select
                  value={newRule.severity}
                  onChange={e => setNewRule({ ...newRule, severity: e.target.value })}
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-white text-xs flex-1"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={newRule.cvss}
                  onChange={e => setNewRule({ ...newRule, cvss: parseFloat(e.target.value) || 5.0 })}
                  className="w-20 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-white font-mono text-xs"
                />
              </div>
            </div>
            <div className="sm:col-span-2">
              <label className="text-slate-400 text-[11px] block mb-1">Description &amp; Remediation:</label>
              <input
                type="text"
                placeholder="Vulnerability impact description..."
                value={newRule.description}
                onChange={e => setNewRule({ ...newRule, description: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white text-xs mb-2"
              />
              <input
                type="text"
                placeholder="Remediation instructions..."
                value={newRule.remediation}
                onChange={e => setNewRule({ ...newRule, remediation: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-white text-xs"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="px-3 py-1.5 rounded text-xs text-slate-400 hover:bg-slate-900"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs"
            >
              {loading ? 'Saving...' : 'Register Rule'}
            </button>
          </div>
        </form>
      )}

      {/* Rules Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800 text-[10px]">
            <tr>
              <th className="py-2.5 px-3">Rule Name &amp; ID</th>
              <th className="py-2.5 px-3">Target Path</th>
              <th className="py-2.5 px-3">Matcher</th>
              <th className="py-2.5 px-3">Severity / CVSS</th>
              <th className="py-2.5 px-3">Remediation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
            {rules.map((r) => (
              <tr key={r.id} className="hover:bg-slate-900/40">
                <td className="py-2.5 px-3 font-sans">
                  <div className="font-bold text-slate-200">{r.name}</div>
                  <div className="text-[10px] text-slate-500 font-mono">{r.id}</div>
                </td>
                <td className="py-2.5 px-3 text-sky-400 font-semibold">{r.path}</td>
                <td className="py-2.5 px-3 text-slate-300">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-sans mr-1">
                    {r.matcher_type}
                  </span>
                  <span className="text-emerald-400 font-bold font-mono">"{r.matcher_pattern}"</span>
                </td>
                <td className="py-2.5 px-3 font-sans">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    r.severity === 'Critical' ? 'bg-rose-500/20 text-rose-300' :
                    r.severity === 'High' ? 'bg-orange-500/20 text-orange-300' :
                    r.severity === 'Medium' ? 'bg-amber-500/20 text-amber-300' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {r.severity} ({r.cvss})
                  </span>
                </td>
                <td className="py-2.5 px-3 font-sans text-slate-400 text-[11px] truncate max-w-xs">
                  {r.remediation}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

