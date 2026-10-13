import React from 'react';
import { 
  LayoutDashboard, 
  Terminal, 
  Layers, 
  AlertTriangle, 
  DollarSign, 
  FileText, 
  Settings, 
  ShieldCheck,
  Activity,
  Scale,
  GitCompare,
  Sparkles,
  Flame
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'graph', label: 'Attack Graph', icon: Flame, isHighlight: true },
  { id: 'runner', label: 'Scan Runner', icon: Terminal },
  { id: 'diff', label: 'Scan Diff & Drift', icon: GitCompare },
  { id: 'assets', label: 'Assets Explorer', icon: Layers },
  { id: 'findings', label: 'Vulnerabilities', icon: AlertTriangle },
  { id: 'playbook', label: 'AI Patch Playbook', icon: Sparkles, isPro: true },
  { id: 'compliance', label: 'Compliance & DPDP', icon: Scale },
  { id: 'cost', label: 'Cost Analytics', icon: DollarSign },
  { id: 'monitoring', label: 'Continuous Monitoring', icon: Activity },
  { id: 'reports', label: 'Report & Exports', icon: FileText },
  { id: 'settings', label: 'Settings & Scope', icon: Settings },
];

export default function Sidebar({ currentTab, onSelectTab, counts, runningScan }) {
  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-900/50 flex flex-col justify-between shrink-0">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
          Navigation
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                isActive
                  ? 'bg-sky-500/10 text-sky-400 border border-sky-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : item.isHighlight ? 'text-rose-400' : item.isPro ? 'text-amber-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.isHighlight && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-extrabold bg-gradient-to-r from-rose-500/20 to-amber-500/20 text-rose-300 border border-rose-500/40 tracking-wider">
                  VISUAL
                </span>
              )}
              {item.isPro && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-extrabold bg-gradient-to-r from-amber-500/20 to-orange-500/20 text-amber-300 border border-amber-500/40 tracking-wider">
                  PRO
                </span>
              )}
              {item.id === 'runner' && runningScan && (
                <span className="px-1.5 py-0.5 rounded-full text-[9px] bg-sky-500/20 text-sky-300 font-mono font-bold flex items-center gap-1 border border-sky-500/30">
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
                  {runningScan.progress || 0}%
                </span>
              )}
              {item.id === 'assets' && counts?.assets !== undefined && (
                <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {counts.assets}
                </span>
              )}
              {item.id === 'findings' && counts?.findings !== undefined && (
                <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono ${
                  counts.findings > 0 ? 'bg-rose-500/20 text-rose-300 font-bold' : 'bg-slate-800 text-slate-400'
                }`}>
                  {counts.findings}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Safety & Compliance Badge */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 text-[11px] text-slate-400 space-y-2">
        <div className="flex items-center gap-2 text-emerald-400 font-medium">
          <ShieldCheck className="w-4 h-4" />
          <span>Safety Guardrails Active</span>
        </div>
        <p className="text-[10px] text-slate-500 leading-tight">
          Passive discovery by default. Safe active probes adhere to strict non-destructive policies.
        </p>
      </div>
    </aside>
  );
}
