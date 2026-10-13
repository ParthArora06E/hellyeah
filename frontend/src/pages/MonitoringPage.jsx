import React, { useState, useEffect } from 'react';
import {
  Activity,
  Clock,
  Bell,
  Play,
  Pause,
  Trash2,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Send,
  Inbox,
  Sliders,
  ShieldCheck,
  ShieldAlert,
  Layers,
  Lock,
  Mail,
  MessageSquare,
  Globe,
  ChevronRight,
  Info,
  Calendar,
  DollarSign,
  TrendingUp,
  Sparkles,
  RotateCcw,
  UserCheck
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ReferenceLine,
  Area,
  AreaChart
} from 'recharts';

export default function MonitoringPage() {
  const [jobs, setJobs] = useState([]);
  const [selectedJobId, setSelectedJobId] = useState(null);
  const [trendData, setTrendData] = useState(null);
  const [jobRuns, setJobRuns] = useState([]);
  const [channels, setChannels] = useState([]);
  const [outbox, setOutbox] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'runs', 'channels', 'outbox'
  const [userRole, setUserRole] = useState('CISO'); // 'CISO', 'FINANCE', 'AUDITOR'

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showChannelModal, setShowChannelModal] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  // New Job Form State
  const [newJobName, setNewJobName] = useState('');
  const [newJobTarget, setNewJobTarget] = useState('');
  const [newScheduleType, setNewScheduleType] = useState('preset'); // 'preset' or 'cron'
  const [newScheduleValue, setNewScheduleValue] = useState('daily_midnight');
  const [newCronExpr, setNewCronExpr] = useState('0 0 * * *');
  const [newThreshold, setNewThreshold] = useState(25000);
  const [newChannels, setNewChannels] = useState(['in_app', 'email', 'slack']);
  const [newScanMode, setNewScanMode] = useState('passive');

  // New Channel Form State
  const [channelName, setChannelName] = useState('');
  const [channelType, setChannelType] = useState('slack');
  const [channelUrl, setChannelUrl] = useState('');

  // Fetch all monitor jobs
  const fetchJobs = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/monitor/jobs');
      const data = await res.json();
      if (Array.isArray(data)) {
        setJobs(data);
        if (data.length > 0 && !selectedJobId) {
          setSelectedJobId(data[0].id);
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch trend for selected job
  const fetchTrend = async (jobId) => {
    if (!jobId) return;
    try {
      const res = await fetch(`/api/monitor/jobs/${jobId}/trend`);
      if (res.ok) {
        const data = await res.json();
        setTrendData(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Fetch runs for selected job
  const fetchRuns = async (jobId) => {
    if (!jobId) return;
    try {
      const res = await fetch(`/api/monitor/jobs/${jobId}/runs`);
      if (res.ok) {
        const data = await res.json();
        setJobRuns(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Fetch channels & outbox
  const fetchChannelsAndOutbox = async () => {
    try {
      const chRes = await fetch('/api/monitor/channels');
      if (chRes.ok) {
        const data = await chRes.json();
        setChannels(data);
      }
      const outRes = await fetch('/api/notifications/outbox');
      if (outRes.ok) {
        const data = await outRes.json();
        setOutbox(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchJobs();
    fetchChannelsAndOutbox();
  }, []);

  useEffect(() => {
    if (selectedJobId) {
      fetchTrend(selectedJobId);
      fetchRuns(selectedJobId);
    }
  }, [selectedJobId]);

  // Periodic polling for runs & trend
  useEffect(() => {
    const timer = setInterval(() => {
      if (selectedJobId) {
        fetchTrend(selectedJobId);
        fetchRuns(selectedJobId);
      }
      fetchChannelsAndOutbox();
    }, 15000);
    return () => clearInterval(timer);
  }, [selectedJobId]);

  const showToast = (msg, isErr = false) => {
    if (isErr) {
      setErrorMessage(msg);
      setTimeout(() => setErrorMessage(null), 5000);
    } else {
      setActionMessage(msg);
      setTimeout(() => setActionMessage(null), 4000);
    }
  };

  // Actions
  const handleRunNow = async (jobId) => {
    try {
      const res = await fetch(`/api/monitor/jobs/${jobId}/run`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message || 'Execution started in background.');
        setTimeout(() => {
          fetchRuns(jobId);
          fetchTrend(jobId);
          fetchJobs();
        }, 3000);
      } else {
        showToast(data.detail || 'Failed to trigger run.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  const handleTogglePause = async (job) => {
    try {
      const endpoint = job.enabled
        ? `/api/monitor/jobs/${job.id}/pause`
        : `/api/monitor/jobs/${job.id}/resume`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'X-User-Role': userRole }
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchJobs();
      } else {
        showToast(data.detail || 'Operation forbidden.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  const handleDeleteJob = async (jobId) => {
    if (!window.confirm('Are you sure you want to delete this monitoring schedule?')) return;
    try {
      const res = await fetch(`/api/monitor/jobs/${jobId}`, {
        method: 'DELETE',
        headers: { 'X-User-Role': userRole }
      });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setSelectedJobId(null);
        fetchJobs();
      } else {
        showToast(data.detail || 'Failed to delete job.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  const handleCreateJob = async (e) => {
    e.preventDefault();
    if (!newJobName || !newJobTarget) {
      showToast('Please specify job name and target domain.', true);
      return;
    }

    const payload = {
      name: newJobName,
      target_domain: newJobTarget,
      scope: [newJobTarget],
      schedule_type: newScheduleType,
      schedule_value: newScheduleType === 'preset' ? newScheduleValue : newCronExpr,
      timezone: 'UTC',
      scan_mode: newScanMode,
      metric: 'estimated_audit_cost',
      threshold: Number(newThreshold),
      channels: newChannels
    };

    try {
      const res = await fetch('/api/monitor/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Role': userRole
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.ok) {
        showToast(`Monitor created: ${data.name}`);
        setShowCreateModal(false);
        setNewJobName('');
        setNewJobTarget('');
        fetchJobs();
        setSelectedJobId(data.id);
      } else {
        showToast(data.detail || 'Failed to create job.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  const handleTestChannel = async (channelId) => {
    try {
      const res = await fetch(`/api/monitor/channels/${channelId}/test`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        fetchChannelsAndOutbox();
      } else {
        showToast(data.detail || 'Test delivery failed.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  const handleCreateChannel = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/monitor/channels', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-Role': userRole
        },
        body: JSON.stringify({
          name: channelName,
          type: channelType,
          config: { url: channelUrl, destination: channelUrl },
          enabled: true
        })
      });
      const data = await res.json();
      if (res.ok) {
        showToast(`Channel created: ${data.name}`);
        setShowChannelModal(false);
        setChannelName('');
        setChannelUrl('');
        fetchChannelsAndOutbox();
      } else {
        showToast(data.detail || 'Failed to register channel.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  // Demo Mode Seed and Reset
  const handleSeedDemo = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/monitor/demo/seed', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast('Demo scenario initialized! Threshold breach synthesized.');
        await fetchJobs();
        setSelectedJobId('demo-monitor-job-001');
        await fetchTrend('demo-monitor-job-001');
        await fetchRuns('demo-monitor-job-001');
        await fetchChannelsAndOutbox();
      } else {
        showToast(data.detail || 'Failed to initialize demo.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    } finally {
      setLoading(false);
    }
  };

  const handleResetDemo = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/monitor/demo/reset', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        showToast(data.message);
        setSelectedJobId(null);
        await fetchJobs();
        setTrendData(null);
        setJobRuns([]);
        await fetchChannelsAndOutbox();
      } else {
        showToast(data.detail || 'Failed to reset demo.', true);
      }
    } catch (err) {
      showToast(err.message, true);
    } finally {
      setLoading(false);
    }
  };

  const selectedJob = jobs.find((j) => j.id === selectedJobId);
  const activeThreshold = trendData?.threshold || 25000;

  // Cron preview translator
  const getScheduleHumanText = (type, val) => {
    if (type === 'preset') {
      if (val === 'demo_30s') return 'Demo High-Frequency (Every 30s)';
      if (val === 'hourly') return 'Hourly (at :00)';
      if (val === 'daily_midnight') return 'Daily (00:00 UTC)';
      if (val === 'weekly_sun') return 'Weekly (Sundays at 00:00 UTC)';
      if (val === 'monthly_1st') return 'Monthly (1st at 00:00 UTC)';
      return `Preset: ${val}`;
    }
    return `Cron Pattern (${val})`;
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Toast Alerts */}
      {actionMessage && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-xl flex items-center gap-3 shadow-lg shadow-emerald-500/10 animate-in fade-in slide-in-from-top-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <span className="text-xs font-medium">{actionMessage}</span>
        </div>
      )}
      {errorMessage && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-300 px-4 py-3 rounded-xl flex items-center gap-3 shadow-lg shadow-rose-500/10 animate-in fade-in slide-in-from-top-2">
          <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <span className="text-xs font-medium">{errorMessage}</span>
        </div>
      )}

      {/* Top Banner & Control Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-2xl backdrop-blur-sm">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-5 h-5 text-sky-400" />
              Scheduled Monitoring & Cost-Threshold Alerts
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Live Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated perimeter discovery, cost-of-risk re-evaluations, edge-triggered alerting, and multi-channel incident dispatches.
          </p>
        </div>

        {/* Action Controls & RBAC Selector */}
        <div className="flex flex-wrap items-center gap-3">
          {/* RBAC Role Selector */}
          <div className="flex items-center gap-1.5 bg-slate-800/80 border border-slate-700/80 rounded-lg px-2.5 py-1 text-xs">
            <UserCheck className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-[11px] text-slate-400">Role:</span>
            <select
              value={userRole}
              onChange={(e) => setUserRole(e.target.value)}
              className="bg-transparent text-slate-200 font-semibold focus:outline-none text-xs cursor-pointer"
            >
              <option value="CISO">CISO (Full Admin)</option>
              <option value="FINANCE">Finance (Thresholds & Audits)</option>
              <option value="AUDITOR">Auditor (Read-Only)</option>
            </select>
          </div>

          {/* Hackathon Demo Quick Button */}
          <button
            onClick={handleSeedDemo}
            className="flex items-center gap-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium text-xs px-3.5 py-2 rounded-lg transition-all shadow-md shadow-indigo-500/20 active:scale-95 cursor-pointer"
            title="Instantly synthesizes a 30s schedule and cost drift scenario exceeding $25k"
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-300" />
            <span>Seed 60s Demo</span>
          </button>

          <button
            onClick={handleResetDemo}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-medium text-xs px-3 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
            title="Reset demo data and clear local outbox"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Demo</span>
          </button>

          {/* New Schedule Button */}
          <button
            onClick={() => setShowCreateModal(true)}
            disabled={userRole === 'AUDITOR'}
            className={`flex items-center gap-1.5 font-medium text-xs px-3.5 py-2 rounded-lg transition-all shadow-md cursor-pointer ${
              userRole === 'AUDITOR'
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                : 'bg-sky-500 hover:bg-sky-400 text-white shadow-sky-500/20 active:scale-95'
            }`}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Monitor Job</span>
          </button>
        </div>
      </div>

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Active Schedules</span>
            <div className="text-2xl font-bold text-slate-100 mt-1">
              {jobs.filter((j) => j.enabled).length} / {jobs.length}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-sky-500/10 text-sky-400 flex items-center justify-center border border-sky-500/20">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Cost Threshold Limit</span>
            <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">
              ${activeThreshold.toLocaleString()}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center border border-emerald-500/20">
            <DollarSign className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Latest Verdict</span>
            <div className={`text-base font-bold mt-1 ${
              selectedJob?.latest_run?.verdict === 'Audit Recommended'
                ? 'text-rose-400'
                : 'text-emerald-400'
            }`}>
              {selectedJob?.latest_run?.verdict || 'Compliant'}
            </div>
          </div>
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center border ${
            selectedJob?.latest_run?.verdict === 'Audit Recommended'
              ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
          }`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">Dispatch Channels</span>
            <div className="text-2xl font-bold text-slate-100 mt-1">
              {channels.filter((c) => c.enabled).length + 3}
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center border border-indigo-500/20">
            <Bell className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main Monitoring Section: Trend Chart & Hysteresis Rule Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend Chart (2 columns) */}
        <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 rounded-2xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-sky-400" />
                <span>Audit Cost Trajectory vs. Cost Threshold Limit</span>
              </h2>
              <p className="text-[11px] text-slate-400">
                Time-series re-evaluations with edge-triggered alert line
              </p>
            </div>

            {/* Target Job Selector */}
            {jobs.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400">Target Job:</span>
                <select
                  value={selectedJobId || ''}
                  onChange={(e) => setSelectedJobId(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-sky-500"
                >
                  {jobs.map((j) => (
                    <option key={j.id} value={j.id}>
                      {j.name} ({j.target_domain})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Recharts Area / Line Chart */}
          <div className="h-64 w-full">
            {trendData?.points && trendData.points.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData.points} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="costGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.5} />
                  <XAxis
                    dataKey="date"
                    stroke="#64748b"
                    fontSize={11}
                    tickLine={false}
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={11}
                    tickFormatter={(val) => `$${val / 1000}k`}
                    tickLine={false}
                  />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload || !payload.length) return null;
                      const d = payload[0].payload;
                      return (
                        <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl text-xs space-y-1.5 font-sans">
                          <div className="text-slate-400 font-mono text-[10px]">{d.date} (Run: {d.run_id?.slice(0, 10)})</div>
                          <div className="flex items-center justify-between gap-4">
                            <span className="text-slate-300">Estimated Cost:</span>
                            <span className="font-bold text-sky-400 font-mono">${d.estimated_audit_cost?.toLocaleString()}</span>
                          </div>
                          <div className="flex items-center justify-between gap-4">
                            <span className="text-slate-300">Annual Risk Loss:</span>
                            <span className="font-semibold text-rose-400 font-mono">${d.expected_annual_loss?.toLocaleString()}</span>
                          </div>
                          <div className="flex items-center justify-between gap-4">
                            <span className="text-slate-300">Risk Score:</span>
                            <span className="font-semibold text-amber-400 font-mono">{d.risk_score} / 100</span>
                          </div>
                          <div className="flex items-center justify-between gap-4 pt-1 border-t border-slate-800">
                            <span className="text-slate-400">Verdict:</span>
                            <span className={`font-semibold ${d.exceeded ? 'text-rose-400' : 'text-emerald-400'}`}>
                              {d.verdict}
                            </span>
                          </div>
                          {d.exceeded && (
                            <div className="text-[10px] bg-rose-500/20 text-rose-300 p-1 rounded font-semibold text-center border border-rose-500/30">
                              LIMIT CROSSED: ALERT DISPATCHED
                            </div>
                          )}
                        </div>
                      );
                    }}
                  />
                  {/* Limit Reference Line */}
                  <ReferenceLine
                    y={activeThreshold}
                    stroke="#f43f5e"
                    strokeDasharray="4 4"
                    strokeWidth={2}
                    label={{
                      value: `Limit: $${activeThreshold.toLocaleString()}`,
                      fill: '#f43f5e',
                      fontSize: 10,
                      position: 'top'
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="estimated_audit_cost"
                    stroke="#38bdf8"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#costGradient)"
                    dot={(props) => {
                      const isBreach = props.payload.exceeded;
                      return (
                        <circle
                          key={`dot-${props.cx}-${props.cy}`}
                          cx={props.cx}
                          cy={props.cy}
                          r={isBreach ? 5 : 3.5}
                          fill={isBreach ? '#f43f5e' : '#38bdf8'}
                          stroke={isBreach ? '#fff' : '#0f172a'}
                          strokeWidth={isBreach ? 2 : 1.5}
                        />
                      );
                    }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center text-slate-500 space-y-2">
                <Clock className="w-8 h-8 text-slate-600" />
                <p className="text-xs">No scan history for this target yet.</p>
                <button
                  onClick={handleSeedDemo}
                  className="text-xs text-sky-400 hover:text-sky-300 underline"
                >
                  Load 60s demo data
                </button>
              </div>
            )}
          </div>
        </div>

        {/* You Set the Rules & Alert Sample Preview (1 column) */}
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs mb-1">
              <Sliders className="w-4 h-4" />
              <span>You Set The Rules: Edge-Triggered Logic</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Alerts fire <strong className="text-slate-200">only once</strong> when your metric crosses the threshold upward. Repeat scans above limit are muted until the metric drops below the hysteresis re-arm floor.
            </p>

            <div className="mt-3 space-y-2 text-[11px] font-mono bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
              <div className="flex justify-between text-slate-400">
                <span>Threshold Limit:</span>
                <span className="text-rose-400 font-bold">${activeThreshold.toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Rearm Floor (0.9x):</span>
                <span className="text-emerald-400">${Math.round(activeThreshold * 0.9).toLocaleString()}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Cooldown Window:</span>
                <span className="text-slate-300">60 mins</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>State:</span>
                <span className="text-sky-400 font-bold">Armed (Edge-Triggered)</span>
              </div>
            </div>
          </div>

          {/* Sample Notification Preview Card */}
          <div className="border border-rose-500/30 bg-rose-950/20 p-3.5 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" />
                Audit Recommended Alert
              </span>
              <span className="text-[9px] text-rose-300/70 font-mono">Simulated Payload</span>
            </div>
            <p className="text-[11px] text-slate-300 font-medium">
              Target <span className="font-mono text-white">{selectedJob?.target_domain || 'demo-corp.internal'}</span> exceeded limit: <span className="font-bold text-rose-400">${trendData?.points?.slice(-1)[0]?.estimated_audit_cost?.toLocaleString() || '29,800'}</span> &gt; ${activeThreshold.toLocaleString()}.
            </p>
            <div className="text-[10px] text-slate-400 space-y-0.5 pt-1 border-t border-rose-900/40">
              <div className="flex items-center gap-1 text-slate-300">
                <span>&bull;</span> 1 CISA KEV weaponized exploit found
              </div>
              <div className="flex items-center gap-1 text-slate-300">
                <span>&bull;</span> 4 new external web CVEs surfaced
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs for Details */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'overview'
              ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Scheduled Jobs ({jobs.length})
        </button>
        <button
          onClick={() => setActiveTab('runs')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'runs'
              ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Run History & Diffs ({jobRuns.length})
        </button>
        <button
          onClick={() => setActiveTab('channels')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'channels'
              ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Notification Channels ({channels.length + 3})
        </button>
        <button
          onClick={() => setActiveTab('outbox')}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
            activeTab === 'outbox'
              ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Demo Outbox Viewer ({outbox.length})
        </button>
      </div>

      {/* TAB 1: Scheduled Jobs Table */}
      {activeTab === 'overview' && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Configured Monitoring Schedules
            </h3>
            <span className="text-[11px] text-slate-500">
              Coalescing enabled &bull; Non-destructive passive scans
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 text-[11px]">
                <tr>
                  <th className="py-3 px-4">Job Name & Target</th>
                  <th className="py-3 px-4">Schedule</th>
                  <th className="py-3 px-4">Threshold</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Next Run</th>
                  <th className="py-3 px-4">Last Result</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {jobs.map((job) => (
                  <tr
                    key={job.id}
                    className={`hover:bg-slate-800/30 transition-colors ${
                      selectedJobId === job.id ? 'bg-sky-500/5' : ''
                    }`}
                  >
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-100">{job.name}</div>
                      <div className="text-[11px] font-mono text-sky-400 flex items-center gap-1">
                        <Globe className="w-3 h-3" />
                        {job.target_domain}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 font-mono">
                        {getScheduleHumanText(job.schedule_type, job.schedule_value)}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-medium text-amber-400">
                      ${job.rules && job.rules[0] ? job.rules[0].threshold.toLocaleString() : '25,000'}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          job.enabled
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {job.enabled ? 'Active' : 'Paused'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-[11px] text-slate-400 font-mono">
                      {job.next_run ? new Date(job.next_run).toLocaleString() : 'Pending'}
                    </td>
                    <td className="py-3 px-4">
                      {job.latest_run ? (
                        <div>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              job.latest_run.verdict === 'Audit Recommended'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}
                          >
                            {job.latest_run.verdict}
                          </span>
                          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                            Cost: ${job.latest_run.estimated_audit_cost?.toLocaleString()}
                          </div>
                        </div>
                      ) : (
                        <span className="text-slate-500 text-[11px]">No runs yet</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => {
                            setSelectedJobId(job.id);
                            handleRunNow(job.id);
                          }}
                          className="p-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 transition-all cursor-pointer"
                          title="Run scan pipeline now"
                        >
                          <Play className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleTogglePause(job)}
                          disabled={userRole === 'AUDITOR'}
                          className={`p-1.5 rounded-lg border transition-all cursor-pointer ${
                            userRole === 'AUDITOR'
                              ? 'bg-slate-800 text-slate-600 border-slate-700 cursor-not-allowed'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
                          }`}
                          title={job.enabled ? 'Pause job' : 'Resume job'}
                        >
                          {job.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
                        </button>
                        <button
                          onClick={() => handleDeleteJob(job.id)}
                          disabled={userRole === 'AUDITOR'}
                          className={`p-1.5 rounded-lg border transition-all cursor-pointer ${
                            userRole === 'AUDITOR'
                              ? 'bg-slate-800 text-slate-600 border-slate-700 cursor-not-allowed'
                              : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/30'
                          }`}
                          title="Delete job"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Run History & Diffs */}
      {activeTab === 'runs' && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Historical Scan Runs & Drift Diffs ({selectedJob?.name || 'Selected Job'})
            </h3>
            <button
              onClick={() => selectedJobId && fetchRuns(selectedJobId)}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 text-[11px]">
                <tr>
                  <th className="py-3 px-4">Run ID & Timestamp</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Assets Count</th>
                  <th className="py-3 px-4">Estimated Cost</th>
                  <th className="py-3 px-4">Annual Loss</th>
                  <th className="py-3 px-4">Risk Verdict</th>
                  <th className="py-3 px-4">Drift Diff (vs Prev)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {jobRuns.length > 0 ? (
                  jobRuns.map((r) => {
                    const diff = r.diff_vs_previous || {};
                    return (
                      <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-mono text-slate-100 font-medium">{r.id.slice(0, 14)}...</div>
                          <div className="text-[11px] text-slate-500 font-mono">
                            {new Date(r.started_at).toLocaleString()}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                              r.status === 'completed'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                : r.status === 'running'
                                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20 animate-pulse'
                                : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            }`}
                          >
                            {r.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono">{r.assets_count}</td>
                        <td className="py-3 px-4 font-mono font-bold text-sky-400">
                          ${r.estimated_audit_cost?.toLocaleString()}
                        </td>
                        <td className="py-3 px-4 font-mono text-rose-400">
                          ${r.expected_annual_loss?.toLocaleString()}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              r.verdict === 'Audit Recommended'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}
                          >
                            {r.verdict}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2 text-[11px] font-mono">
                            {diff.new_assets > 0 ? (
                              <span className="text-amber-400">+{diff.new_assets} assets</span>
                            ) : (
                              <span className="text-slate-500">0 assets</span>
                            )}
                            <span>&bull;</span>
                            {diff.new_cves > 0 ? (
                              <span className="text-rose-400">+{diff.new_cves} CVEs</span>
                            ) : (
                              <span className="text-slate-500">0 CVEs</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan="7" className="py-8 text-center text-slate-500">
                      No historical runs recorded for this schedule yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Channels Configuration */}
      {activeTab === 'channels' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Alert Dispatch Channels (Isolated &amp; Retried)
            </h3>
            <button
              onClick={() => setShowChannelModal(true)}
              disabled={userRole === 'AUDITOR'}
              className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-sky-400 px-3 py-1.5 rounded-lg border border-slate-700 transition-all cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Custom Webhook</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Built-in In-App */}
            <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Bell className="w-4 h-4 text-sky-400" />
                  <span className="font-semibold text-xs text-slate-200">In-App Notification Bell</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  Built-In
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Pushes live incident notifications to the top header bell with unread counters.
              </p>
              <div className="text-[10px] text-slate-500 font-mono">Status: Always Active</div>
            </div>

            {/* Built-in Email (SMTP) */}
            <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-emerald-400" />
                  <span className="font-semibold text-xs text-slate-200">Email Alerts (SMTP / Outbox)</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  Active
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Sends full HTML reports. In zero-setup demo mode, auto-captured into Local Outbox.
              </p>
              <div className="text-[10px] text-slate-500 font-mono">Recipient: security-team@internal</div>
            </div>

            {/* Built-in Slack */}
            <div className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-purple-400" />
                  <span className="font-semibold text-xs text-slate-200">Slack Incoming Webhook</span>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  Active
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Rich block-kit cards with top breach drivers. Captured to Local Outbox when unconfigured.
              </p>
              <div className="text-[10px] text-slate-500 font-mono">SSRF Protection: Enforced</div>
            </div>

            {/* Custom Registered Channels */}
            {channels.map((ch) => (
              <div key={ch.id} className="bg-slate-900/40 border border-slate-800 p-4 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-sky-400" />
                    <span className="font-semibold text-xs text-slate-200">{ch.name}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-semibold uppercase">
                    {ch.type}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 truncate">
                  Target: {ch.config?.url || ch.config?.destination || 'Configured'}
                </p>
                <div className="flex items-center justify-between pt-1">
                  <span className="text-[10px] text-slate-500">
                    {ch.verified ? 'Verified' : 'Unverified'}
                  </span>
                  <button
                    onClick={() => handleTestChannel(ch.id)}
                    className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 cursor-pointer"
                  >
                    <Send className="w-3 h-3" />
                    <span>Send Test</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: Demo Outbox Viewer */}
      {activeTab === 'outbox' && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Inbox className="w-4 h-4 text-sky-400" />
                Local Outbox Message Store (Zero-Setup Demo Mode)
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Emails and Slack alerts dispatched without external credentials are automatically archived here.
              </p>
            </div>
            <button
              onClick={fetchChannelsAndOutbox}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          </div>

          <div className="divide-y divide-slate-800/60">
            {outbox.length > 0 ? (
              outbox.map((msg) => (
                <div key={msg.id} className="p-4 hover:bg-slate-800/20 transition-colors space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-sky-500/10 text-sky-400 border border-sky-500/20 font-mono">
                        {msg.channel}
                      </span>
                      <span className="font-semibold text-slate-200">{msg.subject || 'Dispatch Payload'}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(msg.created_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    Recipient: {msg.recipient || 'Local Slack Outbox'}
                  </div>
                  <pre className="text-[10px] bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 text-slate-300 font-mono overflow-x-auto max-h-32">
                    {msg.body}
                  </pre>
                </div>
              ))
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs">
                Outbox is clean. Run the 60s Demo Seed or execute a scan to generate notification dispatches.
              </div>
            )}
          </div>
        </div>
      )}

      {/* CREATE MONITOR JOB MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Clock className="w-4 h-4 text-sky-400" />
                Configure New Scheduled Monitoring Job
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateJob} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Schedule Name</label>
                <input
                  type="text"
                  placeholder="e.g. Core Production Infrastructure"
                  value={newJobName}
                  onChange={(e) => setNewJobName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Target Domain / Scope</label>
                <input
                  type="text"
                  placeholder="e.g. example.com or app.example.com"
                  value={newJobTarget}
                  onChange={(e) => setNewJobTarget(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                  required
                />
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Only authorized domains within verified organizational scope will be accepted.
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Schedule Type</label>
                  <select
                    value={newScheduleType}
                    onChange={(e) => setNewScheduleType(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                  >
                    <option value="preset">Preset Interval</option>
                    <option value="cron">Custom Cron Expression</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Frequency</label>
                  {newScheduleType === 'preset' ? (
                    <select
                      value={newScheduleValue}
                      onChange={(e) => setNewScheduleValue(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                    >
                      <option value="demo_30s">Demo: Every 30 seconds</option>
                      <option value="hourly">Hourly</option>
                      <option value="daily_midnight">Daily (Midnight UTC)</option>
                      <option value="weekly_sun">Weekly (Sunday)</option>
                      <option value="monthly_1st">Monthly (1st of Month)</option>
                    </select>
                  ) : (
                    <input
                      type="text"
                      placeholder="*/15 * * * *"
                      value={newCronExpr}
                      onChange={(e) => setNewCronExpr(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                    />
                  )}
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-slate-300 font-medium">Audit Cost Limit Threshold</label>
                  <span className="text-rose-400 font-bold font-mono">${Number(newThreshold).toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="5000"
                  max="100000"
                  step="2500"
                  value={newThreshold}
                  onChange={(e) => setNewThreshold(e.target.value)}
                  className="w-full accent-rose-500"
                />
                <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                  <span>$5,000</span>
                  <span>$50,000</span>
                  <span>$100,000</span>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Scan Mode</label>
                <div className="flex items-center gap-4 text-xs">
                  <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="scan_mode"
                      value="passive"
                      checked={newScanMode === 'passive'}
                      onChange={() => setNewScanMode('passive')}
                    />
                    <span>Passive Reconnaissance (Default, Safe)</span>
                  </label>
                  <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                    <input
                      type="radio"
                      name="scan_mode"
                      value="active"
                      checked={newScanMode === 'active'}
                      onChange={() => setNewScanMode('active')}
                    />
                    <span>Safe Active Probing</span>
                  </label>
                </div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-medium shadow-md shadow-sky-500/20 cursor-pointer"
                >
                  Schedule Job
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE CHANNEL MODAL */}
      {showChannelModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Plus className="w-4 h-4 text-sky-400" />
                Add Alert Notification Webhook
              </h3>
              <button
                onClick={() => setShowChannelModal(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateChannel} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Channel Label</label>
                <input
                  type="text"
                  placeholder="e.g. CISO Emergency Webhook"
                  value={channelName}
                  onChange={(e) => setChannelName(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Channel Type</label>
                <select
                  value={channelType}
                  onChange={(e) => setChannelType(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-sky-500"
                >
                  <option value="slack">Slack Webhook</option>
                  <option value="webhook">Generic Signed Webhook (HMAC-SHA256)</option>
                  <option value="telegram">Telegram Bot</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Webhook Endpoint URL</label>
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/... or https://api.mycorp.com/..."
                  value={channelUrl}
                  onChange={(e) => setChannelUrl(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-sky-500"
                  required
                />
                <span className="text-[10px] text-slate-500 mt-1 block">
                  Strict SSRF protection active: Private IPs (127.0.0.1, 10.x, 192.168.x) will be blocked.
                </span>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowChannelModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 text-slate-300 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-medium shadow-md shadow-sky-500/20 cursor-pointer"
                >
                  Save Channel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
