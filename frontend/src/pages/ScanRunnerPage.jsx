import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Terminal, 
  ShieldCheck, 
  ShieldAlert, 
  Zap, 
  CheckCircle2, 
  AlertCircle,
  ExternalLink,
  Layers,
  HelpCircle,
  RefreshCw,
  History,
  Calendar,
  ArrowRight,
  Search,
  FileText,
  AlertTriangle
} from 'lucide-react';

export default function ScanRunnerPage({ 
  onScanCompleted, 
  onScanStarted, 
  activeScan, 
  scans = [], 
  runningScan, 
  onSelectScan 
}) {
  const [activeTab, setActiveTab] = useState('runner'); // 'runner' or 'history'

  // Form State
  const [targetDomain, setTargetDomain] = useState('');
  const [companyName, setCompanyName] = useState('');
  const [scanMode, setScanMode] = useState('passive'); // passive, active
  const [manualAssets, setManualAssets] = useState('');
  const [runPlugins, setRunPlugins] = useState(true);

  // Live Console & Execution State
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('Idle');
  const [logs, setLogs] = useState([]);
  const [monitoredScan, setMonitoredScan] = useState(null);

  // History search filter
  const [historySearch, setHistorySearch] = useState('');

  const logEndRef = useRef(null);
  const eventSourceRef = useRef(null);

  // Auto-scroll log console
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Synchronize with external runningScan when navigating to this page
  useEffect(() => {
    if (runningScan && (!monitoredScan || monitoredScan.id !== runningScan.id)) {
      attachToScan(runningScan);
    }
  }, [runningScan?.id, runningScan?.progress, runningScan?.status]);

  // Cleanup EventSource on unmount
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  const attachToScan = (scanObj) => {
    if (!scanObj) return;
    setMonitoredScan(scanObj);
    setIsScanning(scanObj.status === 'running' || scanObj.status === 'queued');
    setScanProgress(scanObj.progress || 0);
    setCurrentStep(scanObj.current_step || 'In Progress');

    // Close any previous SSE
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    // Fetch past logs first so we have the full history immediately
    fetch(`/api/scans/${scanObj.id}/logs`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          setLogs(data);
        } else {
          setLogs([
            { timestamp: new Date().toLocaleTimeString(), level: 'info', message: `Connected to audit for ${scanObj.target_domain}...` }
          ]);
        }
      })
      .catch(() => {
        setLogs([
          {
            timestamp: new Date().toLocaleTimeString(),
            level: 'info',
            message: `Audit for ${scanObj.target_domain} (${scanObj.mode?.toUpperCase()} Mode) - Status: ${scanObj.status?.toUpperCase()}. Progress: ${scanObj.progress || 0}%. Assets: ${scanObj.total_assets || 0}, Findings: ${scanObj.total_findings || 0}.`
          }
        ]);
      });

    // If still active, subscribe to SSE
    if (scanObj.status === 'running' || scanObj.status === 'queued') {
      const es = new EventSource(`/api/scans/${scanObj.id}/events`);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.message) {
            setLogs(prev => {
              // Avoid duplicate identical message with same step
              const last = prev[prev.length - 1];
              if (last && last.message === data.message) return prev;
              return [...prev, {
                timestamp: data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString(),
                level: data.level || 'info',
                message: data.message
              }];
            });
          }
          if (data.progress !== undefined && data.progress !== null) {
            setScanProgress(data.progress);
          }
          if (data.step) {
            setCurrentStep(data.step);
          }
          if (data.progress === 100 || data.level === 'error') {
            setIsScanning(false);
            es.close();
            if (data.progress === 100 && onScanCompleted) {
              onScanCompleted(scanObj.id);
            }
          }
        } catch (err) {
          console.error('SSE parse error:', err);
        }
      };

      es.onerror = () => {
        es.close();
        setIsScanning(false);
      };
    }
  };

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!targetDomain.trim()) return;

    setIsScanning(true);
    setScanProgress(5);
    setCurrentStep('Initializing Scan Engine');
    setLogs([
      { timestamp: new Date().toLocaleTimeString(), level: 'info', message: `Initializing Auditor scan for target: ${targetDomain} (Mode: ${scanMode.toUpperCase()})...` }
    ]);

    const manualList = manualAssets
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean);

    try {
      const resp = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_domain: targetDomain.trim(),
          company_name: companyName.trim() || undefined,
          mode: scanMode,
          manual_assets: manualList,
          run_plugins: runPlugins
        })
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || 'Failed to start scan');
      }

      const scanData = await resp.json();
      setMonitoredScan(scanData);
      if (onScanStarted) onScanStarted(scanData);

      // Connect to SSE stream
      attachToScan(scanData);

    } catch (err) {
      setLogs(prev => [...prev, {
        timestamp: new Date().toLocaleTimeString(),
        level: 'error',
        message: `Scan initialization failed: ${err.message}`
      }]);
      setIsScanning(false);
    }
  };

  const handleInspectPastScanLogs = (scanItem) => {
    setActiveTab('runner');
    attachToScan(scanItem);
  };

  const handleResetForm = () => {
    setMonitoredScan(null);
    setLogs([]);
    setScanProgress(0);
    setCurrentStep('Idle');
    setIsScanning(false);
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
  };

  const filteredScans = scans.filter(s => {
    if (!historySearch.trim()) return true;
    const q = historySearch.toLowerCase();
    return (s.target_domain || '').toLowerCase().includes(q) ||
           (s.company_name || '').toLowerCase().includes(q) ||
           (s.mode || '').toLowerCase().includes(q) ||
           (s.status || '').toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Top Header & View Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-white tracking-tight flex items-center gap-2">
            <Terminal className="w-5 h-5 text-sky-400" />
            Audit Execution Engine
          </h1>
          <p className="text-xs text-slate-400">
            Launch perimeter audits, monitor live multi-stage telemetry, or inspect historical audit logs.
          </p>
        </div>

        {/* View Switcher: Live Runner vs Past Audits */}
        <div className="flex items-center gap-2 bg-slate-900 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('runner')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'runner'
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Audit Runner &amp; Console</span>
            {isScanning && (
              <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'history'
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5" />
            <span>Past Audits &amp; History</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
              {scans.length}
            </span>
          </button>
        </div>
      </div>

      {/* Active Running Scan Alert Banner (shown on both tabs if a scan is active) */}
      {runningScan && (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-sky-950/40 via-indigo-950/30 to-slate-900 border border-sky-500/30 shadow-lg shadow-sky-500/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400">
              <RefreshCw className="w-4 h-4 animate-spin" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white">Active Audit Running</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/20 text-sky-300 uppercase">
                  {runningScan.mode}
                </span>
                <span className="text-xs font-mono font-bold text-sky-400">{runningScan.progress}%</span>
              </div>
              <p className="text-xs text-slate-300 font-mono mt-0.5">
                Target: <strong className="text-white">{runningScan.target_domain}</strong> &bull; Current Phase: <span className="text-sky-300">{runningScan.current_step || 'Executing'}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {activeTab !== 'runner' && (
              <button
                onClick={() => {
                  setActiveTab('runner');
                  attachToScan(runningScan);
                }}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-sky-500 hover:bg-sky-400 text-slate-950 transition cursor-pointer"
              >
                Attach Live Console &rarr;
              </button>
            )}
          </div>
        </div>
      )}

      {/* TAB 1: RUNNER & CONSOLE */}
      {activeTab === 'runner' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Launch Form OR Monitored Scan Card */}
          <div className="lg:col-span-5 glass-panel rounded-2xl p-6 border-slate-800 space-y-5">
            {isScanning && monitoredScan ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-sky-400 animate-pulse" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Audit In Progress
                    </h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-sky-500/10 text-sky-400 border border-sky-500/20 font-mono">
                    {monitoredScan.mode} Mode
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Target Perimeter</div>
                  <div className="text-base font-bold text-white font-mono break-all">
                    {monitoredScan.target_domain}
                  </div>
                  {monitoredScan.company_name && (
                    <div className="text-xs text-slate-400">
                      Entity: <span className="text-slate-200">{monitoredScan.company_name}</span>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Current Phase</span>
                    <span className="text-sky-400 font-mono font-semibold">{currentStep}</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-sky-500 to-indigo-500 h-full transition-all duration-300 rounded-full"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-400 space-y-1">
                  <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Background Resilience Active
                  </div>
                  <p className="text-[11px] leading-relaxed">
                    You can freely browse Findings, Cost Analytics, or Compliance. This audit continues uninterrupted in the background.
                  </p>
                </div>
              </div>
            ) : monitoredScan && !isScanning ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      Audit Inspection
                    </h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                    {monitoredScan.status}
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Target Domain</div>
                  <div className="text-base font-bold text-white font-mono break-all">
                    {monitoredScan.target_domain}
                  </div>
                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-900 text-xs font-mono">
                    <div>
                      <span className="text-slate-500 text-[10px]">Assets Discovered:</span>
                      <div className="text-slate-200 font-bold">{monitoredScan.total_assets || 0}</div>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px]">Findings Identified:</span>
                      <div className="text-rose-400 font-bold">{monitoredScan.total_findings || 0}</div>
                    </div>
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <button
                    onClick={() => onSelectScan && onSelectScan(monitoredScan)}
                    className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-bold text-xs bg-emerald-600 hover:bg-emerald-500 text-white transition cursor-pointer shadow-md shadow-emerald-600/20"
                  >
                    <span>Inspect Findings &amp; Dashboard</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>

                  <button
                    onClick={handleResetForm}
                    className="w-full py-2 rounded-xl font-medium text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 transition cursor-pointer"
                  >
                    + Launch New Audit
                  </button>
                </div>
              </div>
            ) : (
              /* Launch New Audit Form */
              <form onSubmit={handleStartScan} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Target Domain or Hostname *
                  </label>
                  <input
                    type="text"
                    value={targetDomain}
                    onChange={(e) => setTargetDomain(e.target.value)}
                    placeholder="e.g. example.com or app.target.io"
                    disabled={isScanning}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono disabled:opacity-50"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Company Name (For Executive Reports)
                  </label>
                  <input
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    placeholder="e.g. Acme Corporation"
                    disabled={isScanning}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-xs text-white focus:outline-none focus:border-sky-500 disabled:opacity-50"
                  />
                </div>

                {/* Scan Mode Selection */}
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                    Audit Execution Mode
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => setScanMode('passive')}
                      disabled={isScanning}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                        scanMode === 'passive'
                          ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400'
                          : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold text-xs mb-1">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Passive</span>
                      </div>
                      <p className="text-[10px] text-slate-500 leading-tight">External OSINT &amp; perimeter discovery</p>
                    </button>

                    <button
                      type="button"
                      onClick={() => setScanMode('active')}
                      disabled={isScanning}
                      className={`p-3 rounded-xl border text-left transition cursor-pointer ${
                        scanMode === 'active'
                          ? 'bg-amber-500/10 border-amber-500 text-amber-400'
                          : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-bold text-xs mb-1">
                        <Zap className="w-3.5 h-3.5 text-amber-400" />
                        <span>Safe Active Recon</span>
                      </div>
                      <p className="text-[10px] text-slate-500 leading-tight">Port scanning, WAF, AXFR, CORS, VHosts &amp; APIs</p>
                    </button>
                  </div>

                  {scanMode === 'active' && (
                    <div className="mt-3 p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                          <Zap className="w-3 h-3 text-amber-400" />
                          Active Reconnaissance Suite (9 Methods)
                        </span>
                        <span className="text-[10px] font-mono text-amber-300/80 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/30">
                          Non-Destructive
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 text-[10px] text-slate-300">
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>TCP Port &amp; Banner Grab (28 Ports)</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>DNS AXFR Zone Transfer</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>HTTP TRACE/PUT Verb Prober</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>WAF &amp; Reverse Proxy Fingerprint</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>CORS Origin Reflection Audit</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>Robots.txt &amp; Sitemap Crawler</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>Virtual Host (VHost) Header Prober</span>
                        </div>
                        <div className="flex items-center gap-1.5 bg-slate-900/80 px-2 py-1.5 rounded-lg border border-slate-800">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                          <span>TLS 1.0/1.1 &amp; SAN Asset Harvester</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Manual Assets list */}
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Manual Known Assets (Optional, 1 per line)
                  </label>
                  <textarea
                    value={manualAssets}
                    onChange={(e) => setManualAssets(e.target.value)}
                    placeholder="vpn.example.com&#10;192.168.1.100&#10;s3://corp-backups"
                    rows={3}
                    disabled={isScanning}
                    className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono resize-none disabled:opacity-50"
                  />
                </div>

                <div className="flex items-center justify-between text-xs text-slate-300 pt-1">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={runPlugins}
                      onChange={(e) => setRunPlugins(e.target.checked)}
                      disabled={isScanning}
                      className="rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0"
                    />
                    <span>Execute Drop-in Plugins (plugins/ dir)</span>
                  </label>
                </div>

                <button
                  type="submit"
                  disabled={isScanning}
                  className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-xs uppercase tracking-wider transition cursor-pointer ${
                    isScanning
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                      : 'bg-gradient-to-r from-sky-500 via-indigo-600 to-sky-500 bg-size-200 hover:bg-right text-white shadow-lg shadow-sky-500/20 active:scale-98'
                  }`}
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isScanning ? 'Scan in Progress...' : 'Launch Perimeter Audit'}</span>
                </button>
              </form>
            )}

            {/* Scope Notice */}
            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400 space-y-1">
              <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                <HelpCircle className="w-3.5 h-3.5 text-sky-400" />
                Scope &amp; Safety Policy
              </div>
              <p>
                Passive mode queries public intelligence feeds and DNS. Safe active mode executes non-destructive security header, SSL/TLS, and exposed configuration checks.
              </p>
            </div>
          </div>

          {/* Right Column: Live EventStream & Log Console */}
          <div className="lg:col-span-7 glass-panel rounded-2xl p-6 border-slate-800 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-sky-400" />
                    Live EventStream &amp; Audit Console
                  </h3>
                  <span className="text-[11px] text-slate-400 font-mono">
                    Target: <span className="text-white font-semibold">{monitoredScan?.target_domain || targetDomain || 'Unassigned'}</span> &bull; Phase: <span className="text-sky-400">{currentStep}</span>
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-lg font-black font-mono text-white">{scanProgress}%</span>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="w-full bg-slate-800 h-2 rounded-full mt-4 overflow-hidden">
                <div
                  className="bg-gradient-to-r from-sky-500 to-indigo-500 h-full transition-all duration-300 rounded-full"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
            </div>

            {/* Streaming Log Terminal */}
            <div className="h-96 bg-slate-950/90 border border-slate-800/80 rounded-xl p-4 font-mono text-[11.5px] overflow-y-auto space-y-2 select-text shadow-inner">
              {logs.length === 0 ? (
                <div className="text-slate-600 flex flex-col items-center justify-center h-full space-y-2">
                  <Terminal className="w-6 h-6" />
                  <p>Waiting for audit launch or select a past scan to view logs...</p>
                </div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="flex items-start gap-2 leading-relaxed">
                    <span className="text-slate-600 shrink-0 text-[10px]">{log.timestamp}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[9.5px] font-bold uppercase shrink-0 ${
                      log.level === 'good' ? 'bg-emerald-500/20 text-emerald-400' :
                      log.level === 'warn' ? 'bg-amber-500/20 text-amber-400' :
                      log.level === 'error' ? 'bg-rose-500/20 text-rose-400' :
                      'bg-sky-500/10 text-sky-400'
                    }`}>
                      {log.level}
                    </span>
                    <span className={`break-all ${
                      log.level === 'good' ? 'text-slate-200' :
                      log.level === 'warn' ? 'text-amber-200' :
                      log.level === 'error' ? 'text-rose-300' :
                      'text-slate-300'
                    }`}>
                      {log.message}
                    </span>
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </div>

            {/* Completion Banner */}
            {scanProgress === 100 && monitoredScan && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-xs">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Audit Finished Successfully!</span>
                </div>
                <button
                  onClick={() => onSelectScan && onSelectScan(monitoredScan)}
                  className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-white font-bold text-xs transition cursor-pointer"
                >
                  View Dashboard Findings &rarr;
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: PAST AUDITS & HISTORY */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="glass-panel p-4 rounded-xl border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
              <input
                type="text"
                placeholder="Search past scans by domain, company, mode, or status..."
                value={historySearch}
                onChange={(e) => setHistorySearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
              />
            </div>

            <button
              onClick={() => {
                setActiveTab('runner');
                handleResetForm();
              }}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-sky-600 hover:bg-sky-500 text-white transition cursor-pointer shrink-0"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Launch New Audit</span>
            </button>
          </div>

          {filteredScans.length === 0 ? (
            <div className="glass-panel p-12 text-center text-slate-500 rounded-2xl border-slate-800">
              No historical audits found matching your query.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredScans.map((s) => (
                <div
                  key={s.id}
                  className="glass-panel glass-panel-hover rounded-xl p-4 border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        s.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                        s.status === 'running' ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30 animate-pulse' :
                        s.status === 'failed' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}>
                        {s.status}
                      </span>

                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                        {s.mode?.toUpperCase()} MODE
                      </span>

                      <h3 className="text-sm font-bold text-white font-mono">
                        {s.target_domain}
                      </h3>

                      {s.company_name && s.company_name !== s.target_domain && (
                        <span className="text-xs text-slate-400 font-sans">
                          ({s.company_name})
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs text-slate-400 font-mono">
                      <span>Assets: <strong className="text-slate-200">{s.total_assets || 0}</strong></span>
                      <span>&bull;</span>
                      <span>Findings: <strong className="text-rose-400">{s.total_findings || 0}</strong></span>
                      <span>&bull;</span>
                      <span>Risk: <strong className={s.risk_score > 50 ? 'text-rose-400' : s.risk_score > 20 ? 'text-amber-400' : 'text-emerald-400'}>{s.risk_score || 0}/100</strong></span>
                      <span>&bull;</span>
                      <span className="text-slate-500 flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {s.created_at ? new Date(s.created_at).toLocaleString() : 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleInspectPastScanLogs(s)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 transition cursor-pointer"
                      title="Inspect full audit logs in the terminal"
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>{s.status === 'running' ? 'Monitor Live' : 'View Audit Logs'}</span>
                    </button>

                    <button
                      onClick={() => onSelectScan && onSelectScan(s)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 transition cursor-pointer"
                      title="Open scan findings on dashboard"
                    >
                      <span>Open Dashboard</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
