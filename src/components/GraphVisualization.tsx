import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Transaction, AccountNode, FraudRing } from '../types';
import { cn } from '../lib/utils';

const COLORS = {
  cycle: '#ef4444',
  smurfing: '#f59e0b',
  shell: '#3b82f6',
  default: '#94a3b8'
};

interface GraphProps {
  transactions: Transaction[];
  fraudRings: FraudRing[];
  transactionPatterns: Record<string, "cycle" | "smurfing" | "shell">;
  filter: "all" | "cycle" | "smurfing" | "shell";
  onNodeClick: (node: AccountNode) => void;
}

const GraphVisualization: React.FC<GraphProps> = ({ 
  transactions, 
  fraudRings, 
  transactionPatterns, 
  filter,
  onNodeClick 
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [showAll, setShowAll] = useState(false);
  const isLargeDataset = transactions.length > 2000;

  useEffect(() => {
    if (!canvasRef.current || !containerRef.current || transactions.length === 0) return;

    const canvas = canvasRef.current;
    const context = canvas.getContext('2d')!;
    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight || 600;

    // Support High DPI Displays
    const dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.scale(dpr, dpr);

    // Process data
    const nodesMap = new Map<string, any>();
    const edges: any[] = [];
    const suspiciousAccounts = new Set<string>();
    const accountPatternMap = new Map<string, "cycle" | "smurfing" | "shell">();
    const ringMap = new Map<string, string>();
    
    fraudRings.forEach(ring => {
      ring.member_accounts.forEach(acc => {
        suspiciousAccounts.add(acc);
        ringMap.set(acc, ring.ring_id);
        accountPatternMap.set(acc, ring.pattern_type);
      });
    });

    const nodeStats = new Map<string, { count: number, volume: number }>();
    transactions.forEach(tx => {
      [tx.sender_id, tx.receiver_id].forEach(id => {
        const stats = nodeStats.get(id) || { count: 0, volume: 0 };
        stats.count += 1;
        stats.volume += tx.amount;
        nodeStats.set(id, stats);
      });
    });

    transactions.forEach(tx => {
      const pattern = transactionPatterns[tx.transaction_id];
      const isSuspicious = !!pattern;

      if (isLargeDataset && !isSuspicious && !showAll) return;
      if (!isSuspicious && filter !== 'all') return;

      if (!nodesMap.has(tx.sender_id)) {
        nodesMap.set(tx.sender_id, {
          id: tx.sender_id,
          isSuspicious: suspiciousAccounts.has(tx.sender_id),
          ringId: ringMap.get(tx.sender_id),
          patternType: accountPatternMap.get(tx.sender_id),
          txCount: nodeStats.get(tx.sender_id)?.count || 0,
          totalVolume: nodeStats.get(tx.sender_id)?.volume || 0
        });
      }
      if (!nodesMap.has(tx.receiver_id)) {
        nodesMap.set(tx.receiver_id, {
          id: tx.receiver_id,
          isSuspicious: suspiciousAccounts.has(tx.receiver_id),
          ringId: ringMap.get(tx.receiver_id),
          patternType: accountPatternMap.get(tx.receiver_id),
          txCount: nodeStats.get(tx.receiver_id)?.count || 0,
          totalVolume: nodeStats.get(tx.receiver_id)?.volume || 0
        });
      }
      edges.push({
        source: tx.sender_id,
        target: tx.receiver_id,
        isSuspicious,
        patternType: pattern
      });
    });

    let filteredNodes = Array.from(nodesMap.values());
    let filteredEdges = edges;

    if (filter !== 'all') {
      filteredEdges = edges.filter(e => e.patternType === filter);
      const activeNodeIds = new Set<string>();
      filteredEdges.forEach(e => {
        activeNodeIds.add(typeof e.source === 'string' ? e.source : e.source.id);
        activeNodeIds.add(typeof e.target === 'string' ? e.target : e.target.id);
      });
      filteredNodes = filteredNodes.filter(n => activeNodeIds.has(n.id) || n.patternType === filter);
    }

    // Force Simulation
    const simulation = d3.forceSimulation(filteredNodes)
      .force('link', d3.forceLink(filteredEdges).id((d: any) => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(isLargeDataset ? -50 : -200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(15));

    // Fast-forward physics if graph is huge
    if (filteredNodes.length > 500) {
      for (let i = 0; i < 50; i++) simulation.tick();
    }

    let transform = d3.zoomIdentity;

    const draw = () => {
      context.save();
      context.clearRect(0, 0, width, height);
      context.translate(transform.x, transform.y);
      context.scale(transform.k, transform.k);

      // Draw Edges with Arrowheads (Directed Graph)
      filteredEdges.forEach(d => {
        const dx = d.target.x - d.source.x;
        const dy = d.target.y - d.source.y;
        const angle = Math.atan2(dy, dx);
        
        // Stop the line at the edge of the target node, not its center
        const targetRadius = d.target.isSuspicious ? 10 : 5;
        const tipX = d.target.x - targetRadius * Math.cos(angle);
        const tipY = d.target.y - targetRadius * Math.sin(angle);

        const color = COLORS[d.patternType as keyof typeof COLORS || 'default'];
        
        // Draw the main line
        context.beginPath();
        context.moveTo(d.source.x, d.source.y);
        context.lineTo(tipX, tipY);
        context.strokeStyle = color;
        context.globalAlpha = d.isSuspicious ? 0.8 : 0.2;
        context.lineWidth = d.isSuspicious ? 2 : 0.5;
        
        if (d.patternType === 'shell') context.setLineDash([4, 4]);
        else context.setLineDash([]);
        context.stroke();

        // Draw the arrowhead
        const headlen = d.isSuspicious ? 8 : 5; // Arrowhead size
        context.beginPath();
        context.moveTo(tipX, tipY);
        context.lineTo(tipX - headlen * Math.cos(angle - Math.PI / 7), tipY - headlen * Math.sin(angle - Math.PI / 7));
        context.lineTo(tipX - headlen * Math.cos(angle + Math.PI / 7), tipY - headlen * Math.sin(angle + Math.PI / 7));
        context.closePath();
        context.fillStyle = color;
        context.fill();
      });

      // Draw Nodes
      context.globalAlpha = 1;
      context.setLineDash([]);
      filteredNodes.forEach(d => {
        context.beginPath();
        context.arc(d.x, d.y, d.isSuspicious ? 10 : 5, 0, 2 * Math.PI);
        context.fillStyle = d.isSuspicious ? COLORS[d.patternType as keyof typeof COLORS || 'default'] : '#ffffff';
        context.fill();
        context.strokeStyle = COLORS[d.patternType as keyof typeof COLORS || 'default'];
        context.lineWidth = 2;
        context.stroke();
      });

      context.restore();
    };

    simulation.on('tick', draw);

    // Zoom setup
    const zoom = d3.zoom<HTMLCanvasElement, unknown>()
      .scaleExtent([0.1, 8])
      .on('zoom', (e) => {
        transform = e.transform;
        draw();
      });
    
    d3.select(canvas).call(zoom);

    // Click & Hover interaction via Quadtree
    d3.select(canvas).on('mousemove', (e) => {
      const [mouseX, mouseY] = d3.pointer(e);
      const graphX = transform.invertX(mouseX);
      const graphY = transform.invertY(mouseY);
      
      const node = filteredNodes.find(n => Math.hypot(n.x - graphX, n.y - graphY) < 15);
      
      if (node && tooltipRef.current) {
        tooltipRef.current.style.opacity = '1';
        tooltipRef.current.style.left = `${e.pageX + 15}px`;
        tooltipRef.current.style.top = `${e.pageY - 15}px`;
        tooltipRef.current.innerHTML = `
          <div class="p-3 bg-slate-900 text-white rounded-lg shadow-xl border border-slate-700 text-xs font-mono min-w-[200px]">
            <div class="flex items-center justify-between mb-2 border-b border-slate-700 pb-1">
              <span class="font-bold text-blue-400">${node.id}</span>
              ${node.isSuspicious ? `<span class="text-red-400 font-bold">SUSPICIOUS</span>` : ''}
            </div>
            <div class="space-y-1">
              <div class="flex justify-between"><span>Txs:</span> <span>${node.txCount}</span></div>
              <div class="flex justify-between"><span>Vol:</span> <span>$${node.totalVolume.toLocaleString()}</span></div>
            </div>
          </div>
        `;
      } else if (tooltipRef.current) {
        tooltipRef.current.style.opacity = '0';
      }
    });

    d3.select(canvas).on('click', (e) => {
      const [mouseX, mouseY] = d3.pointer(e);
      const graphX = transform.invertX(mouseX);
      const graphY = transform.invertY(mouseY);
      const node = filteredNodes.find(n => Math.hypot(n.x - graphX, n.y - graphY) < 15);
      if (node) onNodeClick(node as AccountNode);
    });

    return () => {
      simulation.stop();
    };
  }, [transactions, fraudRings, transactionPatterns, filter, showAll, onNodeClick]);

  return (
    <div ref={containerRef} className="w-full h-full bg-slate-50 rounded-xl overflow-hidden border border-slate-200 shadow-inner relative">
      <div ref={tooltipRef} className="fixed pointer-events-none z-[100] opacity-0 transition-opacity duration-200" />
      <div className="absolute top-4 left-4 z-10 flex flex-col gap-2">
        <LegendItem color={COLORS.default} label="Legitimate" />
        <LegendItem color={COLORS.cycle} label="Cycle Pattern" />
        <LegendItem color={COLORS.smurfing} label="Smurfing Pattern" />
        <LegendItem color={COLORS.shell} label="Shell Network" dashed />
        
        {isLargeDataset && (
          <button 
            onClick={() => setShowAll(!showAll)}
            className={cn(
              "mt-2 px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase transition-all shadow-sm border cursor-pointer",
              showAll ? "bg-slate-900 text-white border-slate-900" : "bg-white text-slate-600 border-slate-200 hover:bg-slate-50"
            )}
          >
            {showAll ? "Focus Mode (Suspicious Only)" : "Show Full Graph"}
          </button>
        )}
      </div>
      <canvas ref={canvasRef} className="block cursor-grab active:cursor-grabbing" />
    </div>
  );
};

const LegendItem = ({ color, label, dashed }: { color: string, label: string, dashed?: boolean }) => (
  <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-600 bg-white/90 backdrop-blur px-2 py-1 rounded border border-slate-200 shadow-sm">
    <div className={cn("w-3 h-3 rounded-full", dashed && "border-2 border-dashed bg-transparent")} style={{ backgroundColor: dashed ? 'transparent' : color, borderColor: color }}></div>
    <span>{label}</span>
  </div>
);

export default GraphVisualization;