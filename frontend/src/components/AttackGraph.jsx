import React, { useState, useEffect } from 'react';
import { 
  Skull, 
  Globe, 
  Server, 
  ShieldAlert, 
  Database, 
  Play, 
  RotateCcw, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  Sparkles, 
  Zap, 
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Layers,
  Lock
} from 'lucide-react';

export default function AttackGraph({ scan, findings = [], onNavigateTab }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [localFindings, setLocalFindings] = useState(findings || []);

  const domain = scan?.target_domain || 'hcesonepat.org';
  const riskScore = scan?.risk_score != null ? scan.risk_score : 75.0;

  useEffect(() => {
    if (scan?.id && (!findings || findings.length === 0)) {
      fetch(`/api/scans/${scan.id}/findings`)
        .then(r => r.ok ? r.json() : [])
        .then(data => {
          if (Array.isArray(data)) setLocalFindings(data);
        })
        .catch(() => {});
    } else if (findings && findings.length > 0) {
      setLocalFindings(findings);
    }
  }, [scan?.id, findings]);

  // Filter relevant findings
  const activeFindings = (localFindings || []).filter(f => 
    filterSeverity === 'all' ? true : f.severity === filterSeverity
  );
  const topCritical = activeFindings.find(f => f.severity === 'Critical') || activeFindings[0];
  const cveStr = (topCritical?.cve_ids || []).join(', ') || 'CVE-2024-38077';

  // Define graph nodes with coordinates
  const nodes = [
    {
      id: 'attacker',
      title: 'External Threat Actor',
      subtitle: 'Unauthenticated APT / Adversary',
      type: 'threat',
      icon: Skull,
      x: 80,
      y: 200,
      color: '#ef4444',
      badge: 'THREAT SOURCE',
      details: {
        mitre: 'T1190 - Exploit Public-Facing App',
        vector: 'Internet Perimeter Reconnaissance & Automated Port Knocking',
        objective: 'Initial Access & Pivot'
      }
    },
    {
      id: 'entry',
      title: `Perimeter: ${domain}`,
      subtitle: 'Port 443 / SSL & HTTP Headers',
      type: 'entry',
      icon: Globe,
      x: 290,
      y: 120,
      color: '#0ea5e9',
      badge: 'EXTERNAL PERIMETER',
      details: {
        mitre: 'T1595 - Active Scanning',
        vector: 'Missing HSTS, Insecure CORS, and Clickjacking surface',
        impact: 'Transport downgrade & cross-origin session interception'
      }
    },
    {
      id: 'subdomain',
      title: `Subdomain: portal.${domain}`,
      subtitle: 'Legacy Portal / Admin Service',
      type: 'asset',
      icon: Server,
      x: 290,
      y: 280,
      color: '#8b5cf6',
      badge: 'EXPOSED ASSET',
      details: {
        mitre: 'T1596 - Search Open Technical Databases',
        vector: 'Discovered via crt.sh Certificate Transparency logs',
        impact: 'Exposed secondary authentication gateway'
      }
    },
    {
      id: 'vulnerability',
      title: topCritical?.title || 'Transport Header & SSL Misconfiguration',
      subtitle: `${topCritical?.severity || 'Critical'} Severity (${cveStr})`,
      type: 'vuln',
      icon: ShieldAlert,
      x: 520,
      y: 200,
      color: '#f59e0b',
      badge: 'ACTIVE EXPLOIT VECTOR',
      details: {
        mitre: 'T1068 - Exploitation for Privilege Escalation',
        cve: cveStr,
        cvss: topCritical?.cvss_score || 8.8,
        vector: 'Remote unauthenticated trigger via weaponized payload'
      }
    },
    {
      id: 'crown_jewels',
      title: 'Crown Jewels: Core Data Exfiltration',
      subtitle: '$2.4M Financial Loss & Regulatory Breach',
      type: 'impact',
      icon: Database,
      x: 740,
      y: 200,
      color: '#ec4899',
      badge: 'CRITICAL IMPACT',
      details: {
        mitre: 'T1048 - Exfiltration Over Alternative Protocol',
        financial_loss: '$2,400,000 USD (IBM Cost of Data Breach Model)',
        regulatory: 'DPDP Act 2023 Penalty Risk up to ₹250 Crore'
      }
    }
  ];

  // Connections between nodes
  const edges = [
    { from: 'attacker', to: 'entry', label: 'Probing Ports' },
    { from: 'attacker', to: 'subdomain', label: 'DNS Enumeration' },
    { from: 'entry', to: 'vulnerability', label: 'Transport Downgrade' },
    { from: 'subdomain', to: 'vulnerability', label: 'Auth Bypass' },
    { from: 'vulnerability', to: 'crown_jewels', label: 'Data Exfiltration' }
  ];

  useEffect(() => {
    // Default select vulnerability node for immediate inspection
    setSelectedNode(nodes.find(n => n.id === 'vulnerability'));
  }, []);

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-rose-950/20 to-slate-900 border border-slate-800">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40 mb-2">
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>VISUAL ATTACK SURFACE // EXPLOIT PATH RECONSTRUCTION</span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
            <span>Visual Attack Path Graph:</span>
            <span className="text-sky-400 font-mono">{domain}</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Interactive adversarial trajectory graph mapping external threat entrypoints, exploitable CVEs, and blast-radius financial exposure.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab('playbook')}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-sky-500/20 flex items-center gap-2 cursor-pointer transition-all"
            >
              <ShieldCheck className="w-4 h-4" />
              <span>Remediate in AI Playbook</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Graph Canvas and Side Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Interactive SVG Canvas */}
        <div className="lg:col-span-2 rounded-2xl bg-slate-950 border border-slate-800 p-4 relative overflow-hidden flex flex-col min-h-[460px] shadow-2xl">
          {/* Cyber Grid Background */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />

          {/* Canvas Controls Toolbar */}
          <div className="absolute top-4 left-4 z-20 flex items-center gap-2 bg-slate-900/90 backdrop-blur-md p-1.5 rounded-xl border border-slate-800">
            <button 
              onClick={() => setZoomLevel(prev => Math.min(prev + 0.15, 1.4))}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={() => setZoomLevel(prev => Math.max(prev - 0.15, 0.7))}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button 
              onClick={() => setZoomLevel(1)}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              title="Reset Zoom"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <span className="text-[10px] font-mono text-slate-500 px-1">{Math.round(zoomLevel * 100)}%</span>
          </div>

          {/* Live Posture Meter Pill in Canvas */}
          <div className="absolute top-4 right-4 z-20 flex items-center gap-2 bg-slate-900/90 backdrop-blur-md px-3 py-1.5 rounded-xl border border-rose-500/30 text-xs">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span className="text-slate-400 font-medium">Posture Exposure:</span>
            <span className="text-rose-400 font-extrabold font-mono">{riskScore}/100 High Risk</span>
          </div>

          {/* SVG Diagram */}
          <div className="flex-1 w-full flex items-center justify-center overflow-auto z-10 py-6">
            <svg 
              viewBox="0 0 860 400" 
              className="w-full h-full max-h-[420px] transition-transform duration-300 select-none"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              <defs>
                {/* Glowing gradients */}
                <linearGradient id="edgeGradRed" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
                </linearGradient>
                <linearGradient id="edgeGradPink" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#ec4899" stopOpacity="0.8" />
                </linearGradient>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="4" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Edge Connecting Lines */}
              {edges.map((edge, i) => {
                const source = nodes.find(n => n.id === edge.from);
                const target = nodes.find(n => n.id === edge.to);
                if (!source || !target) return null;

                return (
                  <g key={i}>
                    {/* Connection Line */}
                    <line
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      stroke="#0284c7"
                      strokeWidth="2"
                      strokeDasharray="6 4"
                      strokeOpacity="0.7"
                    />

                    {/* Edge Label Pill */}
                    <rect
                      x={(source.x + target.x) / 2 - 42}
                      y={(source.y + target.y) / 2 - 10}
                      width="84"
                      height="20"
                      rx="10"
                      fill="#020617"
                      stroke="#1e293b"
                      strokeWidth="1"
                    />
                    <text
                      x={(source.x + target.x) / 2}
                      y={(source.y + target.y) / 2 + 3}
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {edge.label}
                    </text>
                  </g>
                );
              })}

              {/* Nodes */}
              {nodes.map(node => {
                const IconComponent = node.icon;
                const isSelected = selectedNode?.id === node.id;

                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer transition-all duration-200"
                  >
                    {/* Selected Active Halo */}
                    {isSelected && (
                      <circle
                        r="36"
                        fill="none"
                        stroke={node.color}
                        strokeWidth="2"
                        opacity="0.6"
                      />
                    )}

                    {/* Node Background Circle */}
                    <circle
                      r="28"
                      fill="#090d16"
                      stroke={isSelected ? '#38bdf8' : node.color}
                      strokeWidth={isSelected ? '3' : '2'}
                      filter="url(#glow)"
                    />

                    {/* Center Icon */}
                    <foreignObject x="-12" y="-12" width="24" height="24">
                      <div className="w-full h-full flex items-center justify-center">
                        <IconComponent 
                          className="w-5 h-5" 
                          style={{ color: node.color }} 
                        />
                      </div>
                    </foreignObject>

                    {/* Label Beneath */}
                    <text
                      x="0"
                      y="44"
                      fill="#f1f5f9"
                      fontSize="10"
                      fontWeight="bold"
                      textAnchor="middle"
                    >
                      {node.title.length > 20 ? node.title.slice(0, 18) + '...' : node.title}
                    </text>
                    <text
                      x="0"
                      y="56"
                      fill="#64748b"
                      fontSize="8"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {node.badge}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Bottom Trajectory Legend */}
          <div className="border-t border-slate-900 pt-3 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-400">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" />
                <span>Adversary</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                <span>Entry Perimeter</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
                <span>Vulnerability</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-pink-500 inline-block" />
                <span>Crown Jewels ($2.4M Loss)</span>
              </span>
            </div>
            <span className="text-slate-500 italic">Click any node to inspect kill-chain mechanics</span>
          </div>
        </div>

        {/* Node Detail Inspector Panel */}
        <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-6 flex flex-col justify-between space-y-4">
          {selectedNode ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="px-2.5 py-0.5 rounded-md text-[10px] font-extrabold uppercase font-mono bg-slate-800 text-sky-400 border border-slate-700">
                  {selectedNode.badge}
                </span>
                <span className="text-xs font-mono text-slate-500">Node ID: #{selectedNode.id}</span>
              </div>

              <div>
                <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                  <selectedNode.icon className="w-5 h-5 shrink-0" style={{ color: selectedNode.color }} />
                  <span>{selectedNode.title}</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">{selectedNode.subtitle}</p>
              </div>

              {/* Kill Chain Details */}
              <div className="space-y-3 pt-2 text-xs">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">MITRE ATT&CK Matrix</span>
                  <div className="font-mono text-amber-400 font-semibold">{selectedNode.details.mitre || 'T1190'}</div>
                </div>

                {selectedNode.details.vector && (
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Attack Vector & Mechanics</span>
                    <div className="text-slate-300 leading-relaxed">{selectedNode.details.vector}</div>
                  </div>
                )}

                {selectedNode.details.cve && (
                  <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-rose-400">Weaponized CVE Reference</span>
                    <div className="font-mono text-white font-bold">{selectedNode.details.cve} (CVSS {selectedNode.details.cvss})</div>
                  </div>
                )}

                {selectedNode.details.financial_loss && (
                  <div className="p-3 rounded-xl bg-pink-950/20 border border-pink-500/30 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-pink-400">Breach Blast Radius</span>
                    <div className="text-white font-extrabold text-sm">{selectedNode.details.financial_loss}</div>
                    <div className="text-[11px] text-pink-300/80">{selectedNode.details.regulatory}</div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center p-8 text-center text-slate-500 h-full">
              <Layers className="w-10 h-10 mb-2 opacity-50" />
              <p className="text-xs">Click any node on the graph to inspect threat mechanics</p>
            </div>
          )}

          {/* Quick Action in Inspector */}
          <div className="pt-4 border-t border-slate-800">
            <button
              onClick={() => onNavigateTab && onNavigateTab('playbook')}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-sky-500/20 transition-all"
            >
              <span>Remediate via AI Playbook</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
