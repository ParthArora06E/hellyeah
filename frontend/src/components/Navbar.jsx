import React, { useState, useEffect, useRef, memo } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Zap, 
  Bell, 
  Check, 
  ExternalLink, 
  AlertTriangle, 
  RefreshCw,
  Crown,
  User as UserIcon,
  ChevronDown,
  Sparkles
} from 'lucide-react';

/**
 * Isolated IP Rotator Badge:
 * Handles its own polling and animation so that IP rotations NEVER cause
 * the parent Navbar or the Domain Target selector to re-render.
 */
const IPRotatorBadge = memo(function IPRotatorBadge() {
  const [rotatorIp, setRotatorIp] = useState('');
  const [rotatorMeta, setRotatorMeta] = useState(null);
  const [isRotating, setIsRotating] = useState(false);

  const fetchRotator = async () => {
    try {
      const res = await fetch('/get-ip');
      if (res.ok) {
        const data = await res.json();
        if (data.ip) {
          setRotatorIp(data.ip);
          setRotatorMeta(data);
        }
      }
    } catch (e) {}
  };

  const handleManualRotate = async () => {
    setIsRotating(true);
    try {
      const res = await fetch('/api/rotator/rotate-now', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.new_ip) setRotatorIp(data.new_ip);
      }
      fetchRotator();
    } catch (e) {}
    setTimeout(() => setIsRotating(false), 500);
  };

  useEffect(() => {
    fetchRotator();
    const rotTimer = setInterval(fetchRotator, 3000);
    return () => clearInterval(rotTimer);
  }, []);

  return (
    <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs">
      <span className="text-slate-400">Exit IP:</span>
      <span className="text-emerald-400 font-bold">{rotatorIp || '127.0.0.1'}</span>
      {rotatorMeta?.country && (
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20 font-bold">
          {rotatorMeta.country} {rotatorMeta.protocol ? `• ${rotatorMeta.protocol}` : ''}
        </span>
      )}
      <button
        onClick={handleManualRotate}
        title="Rotate IP immediately through active proxy pool"
        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
      >
        <RefreshCw className={`w-3 h-3 ${isRotating ? 'animate-spin text-sky-400' : ''}`} />
      </button>
    </div>
  );
});

export default function Navbar({ 
  activeScan, 
  onNewScanClick, 
  scans, 
  runningScan, 
  onSelectScan, 
  onNavigateTab,
  user,
  onSwitchUser,
  onUpgradeUser
}) {
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState([]);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);
  const [isRescanning, setIsRescanning] = useState(false);
  const dropdownRef = useRef(null);
  const userDropdownRef = useRef(null);

  const fetchNotifications = async () => {
    try {
      const res = await fetch('/api/notifications?limit=15');
      if (res.ok) {
        const data = await res.json();
        setUnreadCount(data.unread_count || 0);
        setNotifications(data.notifications || []);
      }
    } catch (err) {
      // Ignore background fetch error
    }
  };

  useEffect(() => {
    fetchNotifications();
    const timer = setInterval(fetchNotifications, 10000);
    return () => clearInterval(timer);
  }, []);

  // Close dropdowns on click outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsDropdownOpen(false);
      }
      if (userDropdownRef.current && !userDropdownRef.current.contains(event.target)) {
        setIsUserDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleMarkAllRead = async () => {
    try {
      await fetch('/api/notifications/read-all', { method: 'POST' });
      setUnreadCount(0);
      setNotifications(prev => prev.map(n => ({ ...n, read_at: new Date().toISOString() })));
    } catch (err) {
      console.error(err);
    }
  };

  const handleMarkOneRead = async (id) => {
    try {
      await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read_at: new Date().toISOString() } : n));
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      console.error(err);
    }
  };

  const isPro = user?.role === 'pro';

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-brand-600 via-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
          <ShieldCheck className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-white text-base tracking-tight">AUDITOR</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-bold">
              v1.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-none">Attack Surface Management</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Active Scan / Scanned Domain Selector */}
        {scans && scans.length > 0 && (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 hidden md:inline font-medium">Target:</span>
            <select
              value={activeScan?.id || ''}
              onChange={(e) => {
                const found = scans.find(s => s.id === e.target.value);
                if (found && onSelectScan) onSelectScan(found);
              }}
              className="bg-slate-950 text-slate-200 border border-slate-800 hover:border-slate-700 rounded-xl px-3 py-1.5 focus:outline-none focus:border-sky-500 text-xs font-mono transition-all cursor-pointer shadow-sm min-w-[200px] max-w-[260px] sm:max-w-[340px] truncate"
              title="Switch scanned target or historical scan run"
            >
              {scans.map((s) => {
                const shortId = s.id ? s.id.slice(0, 6) : '';
                const timeStr = s.created_at ? new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' }) : '';
                const score = s.risk_score != null ? `${s.risk_score}/100` : s.status;
                const timeSnippet = dateStr ? ` [${dateStr} ${timeStr}]` : '';
                return (
                  <option key={s.id} value={s.id}>
                    {s.target_domain} #{shortId}{timeSnippet} ({score})
                  </option>
                );
              })}
            </select>
            {activeScan && (
              <button
                onClick={async () => {
                  if (isRescanning || runningScan) return;
                  setIsRescanning(true);
                  try {
                    await fetch(`/api/scans/${activeScan.id}/rescan`, { method: 'POST' });
                  } catch (e) {}
                  setTimeout(() => setIsRescanning(false), 2500);
                }}
                disabled={isRescanning || runningScan != null}
                title={`Quick Re-Scan ${activeScan.target_domain}`}
                className="p-1.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-sky-400 transition cursor-pointer disabled:opacity-40"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRescanning ? 'animate-spin text-sky-400' : ''}`} />
              </button>
            )}
          </div>
        )}

        {/* IP Rotator Indicator (Isolated sub-component) */}
        <IPRotatorBadge />

        {/* User Account & Subscription Tier Switcher Pill */}
        <div className="relative" ref={userDropdownRef}>
          <button
            onClick={() => setIsUserDropdownOpen(!isUserDropdownOpen)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-medium transition-all cursor-pointer ${
              isPro
                ? 'bg-gradient-to-r from-amber-500/15 via-orange-500/10 to-indigo-500/15 border-amber-500/40 text-amber-300 shadow-sm'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            {isPro ? (
              <Crown className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            ) : (
              <UserIcon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            )}
            <div className="flex flex-col text-left leading-none">
              <span className="text-[9px] font-extrabold uppercase tracking-wider text-slate-400">
                {isPro ? 'Pro User' : 'Standard User'}
              </span>
              <span className="text-[11px] font-semibold text-slate-200 mt-0.5 max-w-[120px] truncate">
                {user?.email || (isPro ? 'pro@hackingly.io' : 'user@hackingly.io')}
              </span>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-500 ml-1" />
          </button>

          {/* Account Dropdown */}
          {isUserDropdownOpen && (
            <div className="absolute right-0 mt-2 w-72 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-3 z-50 space-y-3">
              <div className="border-b border-slate-800 pb-2">
                <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Active Account</div>
                <div className="text-xs font-bold text-white mt-0.5">{user?.full_name || 'Auditor User'}</div>
                <div className="text-[11px] text-slate-400 font-mono">{user?.email}</div>
                <div className="mt-1.5 inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {isPro ? '★ Pro Tier Unlocked' : 'Standard Tier'}
                </div>
              </div>

              {/* Demo Account Switcher */}
              <div className="space-y-1.5">
                <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Switch Demo Account</div>
                
                {/* Pro Account Option */}
                <button
                  onClick={() => {
                    onSwitchUser && onSwitchUser('pro');
                    setIsUserDropdownOpen(false);
                  }}
                  className={`w-full text-left p-2 rounded-lg text-xs transition-all flex items-center justify-between cursor-pointer ${
                    isPro ? 'bg-amber-500/10 border border-amber-500/30 text-amber-300' : 'hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Crown className="w-3.5 h-3.5 text-amber-400" />
                    <div>
                      <div className="font-bold text-[11px]">Pro User (Full AI Patches)</div>
                      <div className="text-[10px] text-slate-500 font-mono">pro@hackingly.io / Pro@123456</div>
                    </div>
                  </div>
                  {isPro && <Check className="w-3.5 h-3.5 text-amber-400" />}
                </button>

                {/* Standard Account Option */}
                <button
                  onClick={() => {
                    onSwitchUser && onSwitchUser('standard');
                    setIsUserDropdownOpen(false);
                  }}
                  className={`w-full text-left p-2 rounded-lg text-xs transition-all flex items-center justify-between cursor-pointer ${
                    !isPro ? 'bg-sky-500/10 border border-sky-500/30 text-sky-300' : 'hover:bg-slate-800 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <UserIcon className="w-3.5 h-3.5 text-slate-400" />
                    <div>
                      <div className="font-bold text-[11px]">Standard User (Normal Scans)</div>
                      <div className="text-[10px] text-slate-500 font-mono">user@hackingly.io / User@123456</div>
                    </div>
                  </div>
                  {!isPro && <Check className="w-3.5 h-3.5 text-sky-400" />}
                </button>
              </div>

              {!isPro && (
                <div className="pt-2 border-t border-slate-800">
                  <button
                    onClick={() => {
                      onUpgradeUser && onUpgradeUser();
                      setIsUserDropdownOpen(false);
                    }}
                    className="w-full py-2 rounded-lg bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 font-bold text-xs shadow-md transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>1-Click Upgrade to Pro Tier</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Notifications Bell */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setIsDropdownOpen(!isDropdownOpen)}
            className="p-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors relative cursor-pointer"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-[10px] font-bold text-white flex items-center justify-center ring-2 ring-slate-900">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown */}
          {isDropdownOpen && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden z-50">
              <div className="p-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-xs text-white">Alerts &amp; Incidents</span>
                  {unreadCount > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      {unreadCount} new
                    </span>
                  )}
                </div>
                {unreadCount > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    className="text-[10px] text-sky-400 hover:text-sky-300 flex items-center gap-1 cursor-pointer"
                  >
                    <Check className="w-3 h-3" />
                    <span>Mark all read</span>
                  </button>
                )}
              </div>

              <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
                {notifications.length > 0 ? (
                  notifications.map((n) => {
                    const isUnread = !n.read_at;
                    const p = n.payload || {};
                    return (
                      <div
                        key={n.id}
                        onClick={() => {
                          if (isUnread) handleMarkOneRead(n.id);
                          if (onNavigateTab) onNavigateTab('monitoring');
                          setIsDropdownOpen(false);
                        }}
                        className={`p-3 text-xs transition-colors cursor-pointer ${
                          isUnread ? 'bg-rose-500/5 hover:bg-rose-500/10' : 'hover:bg-slate-800/30'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-1.5 font-semibold text-slate-100">
                            <span className={`w-1.5 h-1.5 rounded-full ${isUnread ? 'bg-rose-500 ring-2 ring-rose-500/30' : 'bg-transparent'}`} />
                            <span className={isUnread ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                              {p.title || 'Audit Recommended'}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-500 font-mono">
                            {n.sent_at ? new Date(n.sent_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300 mt-1">
                          Target <span className="font-mono text-white font-medium">{p.target_domain || 'System'}</span> crossed cost threshold.
                        </p>
                      </div>
                    );
                  })
                ) : (
                  <div className="p-6 text-center text-slate-500 text-xs">
                    No incident notifications yet.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* New Audit Button */}
        <button
          onClick={onNewScanClick}
          className="flex items-center gap-2 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-medium text-xs px-4 py-2 rounded-lg transition-all shadow-md shadow-sky-500/20 active:scale-95 cursor-pointer"
        >
          <Zap className="w-3.5 h-3.5 fill-current" />
          <span>New Audit</span>
        </button>
      </div>
    </header>
  );
}
