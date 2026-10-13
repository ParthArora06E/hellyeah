import React, { useState, useEffect, useMemo } from 'react';
import {
  Globe,
  Layers,
  AlertTriangle,
  ShieldAlert,
  DollarSign,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Sparkles,
  Info,
  ExternalLink,
  ChevronRight,
  Flame,
  CheckCircle2
} from 'lucide-react';

export default function AttackPathGraph({ scanId, onSelectFinding }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterCriticalOnly, setFilterCriticalOnly] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    fetch(`/api/scans/${scanId}/attack-graph`)
      .then((res) => res.json())
      .then((data) => {
        setGraphData(data);
        if (data.nodes && data.nodes.length > 0) {
          const firstVuln = data.nodes.find((n) => n.type === 'vulnerability' && n.is_critical_path) || data.nodes[0];
          setSelectedNode(firstVuln);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scanId]);

  // Layout node coordinates by hierarchical level
  const layout = useMemo(() => {
    if (!graphData?.nodes) return { positionedNodes: [], computedEdges: [] };

    const nodesByLevel = {};
    graphData.nodes.forEach((node) => {
      const lvl = node.level || 0;
      if (!nodesByLevel[lvl]) nodesByLevel[lvl] = [];
      nodesByLevel[lvl].push(node);
    });

    const nodePositions = {};
    const levelSpacing = 280;
    const nodeSpacing = 90;

    Object.keys(nodesByLevel).forEach((lvlStr) => {
      const lvl = parseInt(lvlStr);
      const list = nodesByLevel[lvl];
      const totalH = list.length * nodeSpacing;
      const startY = Math.max(60, 260 - totalH / 2);

      list.forEach((node, idx) => {
        const x = lvl * levelSpacing + 60;
        const y = startY + idx * nodeSpacing;
        nodePositions[node.id] = { ...node, x, y };
      });
    });

    // Compute curved bezier edges
    const computedEdges = (graphData.edges || [])
      .map((edge) => {
        const s = nodePositions[edge.source];
        const t = nodePositions[edge.target];
        if (!s || !t) return null;

        const path = `M ${s.x + 160} ${s.y + 24} C ${s.x + 220} ${s.y + 24}, ${t.x - 60} ${t.y + 24}, ${t.x} ${t.y + 24}`;
        return {
          ...edge,
          path,
          sourceNode: s,
          targetNode: t
        };
      })
      .filter(Boolean);

    return {
      positionedNodes: Object.values(nodePositions),
      computedEdges
    };
  }, [graphData]);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setIsDragging(false);

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 overflow-hidden relative backdrop-blur-sm">
      {/* Header and Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Flame className="w-4 h-4 text-rose-400" />
              Attack Path &amp; Blast Radius Topology
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
              Interactive Flow
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Visual attack graph showing how external perimeters connect to exploitable CVEs and quantifiable financial loss.
          </p>
        </div>

        {/* View Controls */}
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-slate-300 bg-slate-800/80 px-2.5 py-1.5 rounded-lg border border-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={filterCriticalOnly}
              onChange={(e) => setFilterCriticalOnly(e.target.checked)}
              className="accent-rose-500"
            />
            <span className="text-[11px]">Critical Conduits Only</span>
          </label>

          <button
            onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 cursor-pointer"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.15))}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 cursor-pointer"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 cursor-pointer"
            title="Reset View"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Canvas + Inspector Drawer Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 min-h-[460px]">
        {/* SVG Topology Graph Canvas (3 cols) */}
        <div
          className="lg:col-span-3 bg-slate-950/80 rounded-xl border border-slate-800/80 relative overflow-hidden cursor-grab active:cursor-grabbing select-none"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {/* Subtle Grid Background Pattern */}
          <div
            className="absolute inset-0 opacity-15 pointer-events-none"
            style={{
              backgroundImage: 'radial-gradient(#38bdf8 1px, transparent 1px)',
              backgroundSize: '24px 24px'
            }}
          />

          <svg
            className="w-full h-[460px]"
            style={{
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              transformOrigin: '0 0'
            }}
          >
            <defs>
              <linearGradient id="critEdgeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#f43f5e" stopOpacity="1" />
              </linearGradient>
            </defs>

            {/* Edges */}
            {layout.computedEdges.map((edge, idx) => {
              const isHighlighted = edge.is_critical;
              if (filterCriticalOnly && !isHighlighted) return null;

              return (
                <g key={`edge-${idx}`}>
                  <path
                    d={edge.path}
                    fill="none"
                    stroke={isHighlighted ? '#f43f5e' : '#334155'}
                    strokeWidth={isHighlighted ? 2.5 : 1.5}
                    strokeDasharray={isHighlighted ? '6 4' : 'none'}
                    className={isHighlighted ? 'animate-pulse' : ''}
                    opacity={isHighlighted ? 1 : 0.6}
                  />
                  {/* Subtle Direction Indicator Arrow or Label */}
                  {isHighlighted && (
                    <circle
                      r="3"
                      fill="#f43f5e"
                      cx={(edge.sourceNode.x + edge.targetNode.x) / 2 + 50}
                      cy={(edge.sourceNode.y + edge.targetNode.y) / 2 + 24}
                    />
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {layout.positionedNodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const isCrit = node.is_critical_path;
              if (filterCriticalOnly && !isCrit && node.type !== 'target' && node.type !== 'impact') {
                return null;
              }

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                  }}
                  className="cursor-pointer transition-transform duration-150 hover:scale-105"
                >
                  {/* Node Rect Card */}
                  <rect
                    width="170"
                    height="48"
                    rx="10"
                    fill={
                      isSelected
                        ? '#0f172a'
                        : node.type === 'impact'
                        ? '#1e1b4b'
                        : '#090d16'
                    }
                    stroke={
                      isSelected
                        ? '#38bdf8'
                        : isCrit
                        ? '#f43f5e'
                        : node.type === 'impact'
                        ? '#818cf8'
                        : '#334155'
                    }
                    strokeWidth={isSelected ? 2.5 : isCrit ? 2 : 1}
                    className="drop-shadow-md"
                  />

                  {/* Node Type Icon */}
                  <g transform="translate(10, 14)">
                    {node.type === 'target' && <Globe className="w-5 h-5 text-sky-400" />}
                    {node.type === 'asset' && <Layers className="w-5 h-5 text-slate-300" />}
                    {node.type === 'vulnerability' && (
                      <ShieldAlert className={`w-5 h-5 ${isCrit ? 'text-rose-400' : 'text-amber-400'}`} />
                    )}
                    {node.type === 'impact' && <DollarSign className="w-5 h-5 text-indigo-400" />}
                  </g>

                  {/* Node Text Label & Sublabel */}
                  <text
                    x="38"
                    y="20"
                    fill={isCrit ? '#fca5a5' : '#f8fafc'}
                    fontSize="11"
                    fontWeight="bold"
                    className="select-none font-sans"
                  >
                    {node.label.length > 17 ? node.label.slice(0, 16) + '…' : node.label}
                  </text>
                  <text
                    x="38"
                    y="34"
                    fill="#94a3b8"
                    fontSize="9"
                    className="select-none font-mono"
                  >
                    {node.sublabel?.length > 22 ? node.sublabel.slice(0, 20) + '…' : node.sublabel}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Help Overlay Badge */}
          <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg text-[10px] text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
            <span>Pulsing Crimson = Weaponized Exploit Pathway</span>
          </div>
        </div>

        {/* Node Inspection Drawer (1 col) */}
        <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-4">
          {selectedNode ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-sky-400 flex items-center gap-1">
                  <Info className="w-3.5 h-3.5" />
                  Node Inspector
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    selectedNode.severity === 'Critical'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {selectedNode.type}
                </span>
              </div>

              <div>
                <h4 className="text-xs font-bold text-slate-100 break-words">{selectedNode.label}</h4>
                <p className="text-[11px] text-slate-400 mt-0.5 font-mono">{selectedNode.sublabel}</p>
              </div>

              {selectedNode.type === 'vulnerability' && (
                <div className="space-y-2 bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Severity:</span>
                    <span className="font-bold text-rose-400">{selectedNode.severity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">CISA KEV Weaponized:</span>
                    <span className={`font-bold ${selectedNode.is_kev ? 'text-rose-400' : 'text-slate-400'}`}>
                      {selectedNode.is_kev ? 'YES (Active in wild)' : 'No'}
                    </span>
                  </div>
                  {selectedNode.cvss && (
                    <div className="flex justify-between">
                      <span className="text-slate-400">CVSS v3.1:</span>
                      <span className="font-mono text-amber-400 font-bold">{selectedNode.cvss}</span>
                    </div>
                  )}
                  {selectedNode.fix_cost > 0 && (
                    <div className="flex justify-between pt-1 border-t border-slate-800">
                      <span className="text-slate-400">Estimated Fix Cost:</span>
                      <span className="font-mono text-sky-400 font-bold">${selectedNode.fix_cost?.toLocaleString()}</span>
                    </div>
                  )}
                </div>
              )}

              {selectedNode.type === 'asset' && selectedNode.ports?.length > 0 && (
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-xs space-y-1">
                  <span className="text-slate-400 text-[10px] uppercase font-bold">Open Ports:</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedNode.ports.map((p, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-sky-400 font-mono text-[10px]">
                        Port {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedNode.type === 'impact' && (
                <p className="text-[11px] text-slate-400 leading-relaxed bg-indigo-950/20 p-3 rounded-lg border border-indigo-500/20">
                  Represents the cumulative financial liability should perimeter exploits breach sensitive crown jewel records.
                </p>
              )}
            </div>
          ) : (
            <div className="text-center text-slate-500 text-xs py-12">
              Click any node on the graph to inspect vulnerability and remediation drivers.
            </div>
          )}

          <div className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
            Tip: Drag canvas to pan &bull; Scroll or use buttons to zoom
          </div>
        </div>
      </div>
    </div>
  );
}
