/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  Download, 
  RefreshCcw, 
  LayoutDashboard, 
  Network, 
  Table as TableIcon,
  Info,
  ChevronRight,
  Search,
  Activity,
  Users,
  Clock
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import FileUpload from './components/FileUpload';
import GraphVisualization from './components/GraphVisualization';
import { Transaction, DetectionResult, AccountNode } from './types';
import { cn } from './lib/utils';

export default function App() {
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [detectionResult, setDetectionResult] = useState<(DetectionResult & { transactionPatterns: Record<string, "cycle" | "smurfing" | "shell"> }) | null>(null);
  const [selectedNode, setSelectedNode] = useState<AccountNode | null>(null);
  const [activeTab, setActiveTab] = useState<'graph' | 'table'>('graph');
  const [graphFilter, setGraphFilter] = useState<"all" | "cycle" | "smurfing" | "shell">("all");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleDataLoaded = async (data: Transaction[]) => {
    setTransactions(data);
    setIsAnalyzing(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ transactions: data }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze transactions');
      }

      const result = await response.json();
      setDetectionResult(result);
    } catch (error) {
      console.error('Analysis error:', error);
      alert('An error occurred during analysis. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setTransactions([]);
    setDetectionResult(null);
    setSelectedNode(null);
    setGraphFilter("all");
  };

  const downloadJson = () => {
    if (!detectionResult) return;
    const { transactionPatterns, ...rest } = detectionResult;
    const blob = new Blob([JSON.stringify(rest, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mule_detection_report_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
      {/* Header */}
      <header className="border-b border-[#141414] px-6 py-4 flex items-center justify-between bg-white/50 backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-[#141414] text-[#E4E3E0] flex items-center justify-center rounded-lg">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight uppercase">RIFT 2026: Forensics Engine</h1>
            <p className="text-[10px] font-mono opacity-50 uppercase tracking-widest">Money Muling Detection / Graph Theory Track</p>
          </div>
        </div>

        {transactions.length > 0 && (
          <div className="flex items-center gap-4">
            <button 
              onClick={downloadJson}
              className="flex items-center gap-2 px-4 py-2 bg-[#141414] text-[#E4E3E0] rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
            <button 
              onClick={handleReset}
              className="flex items-center gap-2 px-4 py-2 border border-[#141414] rounded-lg text-sm font-medium hover:bg-[#141414] hover:text-[#E4E3E0] transition-all"
            >
              <RefreshCcw className="w-4 h-4" />
              Reset
            </button>
          </div>
        )}
      </header>

      <main className="p-6 max-w-[1600px] mx-auto">
        <AnimatePresence mode="wait">
          {isAnalyzing ? (
            <motion.div 
              key="analyzing"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="py-40 flex flex-col items-center justify-center gap-6"
            >
              <div className="relative">
                <div className="w-24 h-24 border-4 border-slate-200 border-t-[#141414] rounded-full animate-spin" />
                <ShieldAlert className="w-10 h-10 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-[#141414]" />
              </div>
              <div className="text-center">
                <h2 className="text-2xl font-serif italic mb-2">Analyzing Network Patterns...</h2>
                <p className="text-slate-500 font-mono text-xs uppercase tracking-widest">Running Graph Algorithms & Temporal Clustering</p>
              </div>
            </motion.div>
          ) : transactions.length === 0 ? (
            <motion.div 
              key="upload"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="py-20"
            >
              <div className="text-center mb-12">
                <h2 className="text-5xl font-serif italic mb-4">Follow the Money.</h2>
                <p className="text-slate-500 max-w-xl mx-auto">
                  Upload your transaction dataset to expose sophisticated money muling networks through multi-hop graph analysis and temporal pattern recognition.
                </p>
              </div>
              <FileUpload onDataLoaded={handleDataLoaded} />
            </motion.div>
          ) : (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="grid grid-cols-12 gap-6"
            >
              {/* Summary Stats */}
              <div className="col-span-12 grid grid-cols-1 md:grid-cols-4 gap-4">
                <StatCard 
                  label="Total Accounts" 
                  value={detectionResult?.summary.total_accounts_analyzed || 0} 
                  icon={Users}
                />
                <StatCard 
                  label="Suspicious Flagged" 
                  value={detectionResult?.summary.suspicious_accounts_flagged || 0} 
                  icon={ShieldAlert}
                  variant="danger"
                />
                <StatCard 
                  label="Fraud Rings" 
                  value={detectionResult?.summary.fraud_rings_detected || 0} 
                  icon={Activity}
                  variant="warning"
                />
                <StatCard 
                  label="Processing Time" 
                  value={`${detectionResult?.summary.processing_time_seconds || 0}s`} 
                  icon={Clock}
                />
              </div>

              {/* Main View */}
              <div className="col-span-12 lg:col-span-8 flex flex-col gap-6">
                <div className="bg-white border border-[#141414] rounded-2xl overflow-hidden shadow-sm flex flex-col h-[700px]">
                  <div className="px-6 py-4 border-b border-[#141414] flex items-center justify-between bg-slate-50">
                    <div className="flex items-center gap-4">
                      <button 
                        onClick={() => setActiveTab('graph')}
                        className={cn(
                          "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all",
                          activeTab === 'graph' ? "bg-[#141414] text-[#E4E3E0]" : "text-slate-500 hover:bg-slate-200"
                        )}
                      >
                        <Network className="w-4 h-4" />
                        Graph View
                      </button>
                      <button 
                        onClick={() => setActiveTab('table')}
                        className={cn(
                          "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all",
                          activeTab === 'table' ? "bg-[#141414] text-[#E4E3E0]" : "text-slate-500 hover:bg-slate-200"
                        )}
                      >
                        <TableIcon className="w-4 h-4" />
                        Fraud Rings
                      </button>
                    </div>
                    
                    {activeTab === 'graph' && (
                      <div className="flex items-center gap-2 bg-white p-1 rounded-lg border border-slate-200">
                        {(['all', 'cycle', 'smurfing', 'shell'] as const).map((f) => (
                          <button
                            key={f}
                            onClick={() => setGraphFilter(f)}
                            className={cn(
                              "px-2 py-1 text-[10px] font-bold uppercase rounded transition-all",
                              graphFilter === f ? "bg-slate-900 text-white" : "text-slate-400 hover:text-slate-600"
                            )}
                          >
                            {f}
                          </button>
                        ))}
                      </div>
                    )}

                    <div className="text-[10px] font-mono opacity-50 uppercase tracking-widest hidden md:block">
                      Live Analysis Engine v1.0.4
                    </div>
                  </div>

                  <div className="flex-1 relative">
                    {activeTab === 'graph' ? (
                      <GraphVisualization 
                        transactions={transactions} 
                        fraudRings={detectionResult?.fraud_rings || []}
                        transactionPatterns={detectionResult?.transactionPatterns || {}}
                        filter={graphFilter}
                        onNodeClick={setSelectedNode}
                      />
                    ) : (
                      <div className="p-6 overflow-auto h-full">
                        <table className="w-full text-left border-collapse">
                          <thead>
                            <tr className="border-b border-[#141414] text-[11px] font-serif italic uppercase tracking-wider text-slate-500">
                              <th className="pb-3 font-normal">Ring ID</th>
                              <th className="pb-3 font-normal">Pattern Type</th>
                              <th className="pb-3 font-normal">Members</th>
                              <th className="pb-3 font-normal">Risk Score</th>
                              <th className="pb-3 font-normal">Account IDs</th>
                            </tr>
                          </thead>
                          <tbody className="text-sm font-mono">
                            {detectionResult?.fraud_rings.map((ring) => (
                              <tr key={ring.ring_id} className="border-b border-slate-200 hover:bg-slate-50 transition-colors">
                                <td className="py-4 font-bold">{ring.ring_id}</td>
                                <td className="py-4">
                                  <span className={cn(
                                    "px-2 py-0.5 rounded text-[10px] font-bold uppercase",
                                    ring.pattern_type === 'cycle' ? "bg-red-100 text-red-700" :
                                    ring.pattern_type === 'smurfing' ? "bg-amber-100 text-amber-700" :
                                    "bg-blue-100 text-blue-700"
                                  )}>
                                    {ring.pattern_type}
                                  </span>
                                </td>
                                <td className="py-4">{ring.member_accounts.length}</td>
                                <td className="py-4">
                                  <div className="flex items-center gap-2">
                                    <div className="w-12 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                                      <div 
                                        className="h-full bg-[#141414]" 
                                        style={{ width: `${ring.risk_score}%` }}
                                      />
                                    </div>
                                    <span>{ring.risk_score.toFixed(1)}</span>
                                  </div>
                                </td>
                                <td className="py-4 text-[10px] text-slate-500 max-w-xs truncate">
                                  {ring.member_accounts.join(', ')}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Sidebar Details */}
              <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
                {/* Node Details */}
                <div className="bg-white border border-[#141414] rounded-2xl p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-serif italic text-lg">Account Intelligence</h3>
                    <Info className="w-4 h-4 text-slate-400" />
                  </div>

                  {selectedNode ? (
                    <div className="space-y-6">
                      <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl border border-slate-200">
                        <div>
                          <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Account ID</p>
                          <p className="font-mono font-bold text-lg">{selectedNode.id}</p>
                        </div>
                        <div className={cn(
                          "w-12 h-12 rounded-full flex items-center justify-center border-2",
                          selectedNode.isSuspicious ? "bg-red-50 border-red-200 text-red-600" : "bg-blue-50 border-blue-200 text-blue-600"
                        )}>
                          {selectedNode.isSuspicious ? <ShieldAlert className="w-6 h-6" /> : <Users className="w-6 h-6" />}
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="p-3 bg-slate-50 rounded-lg border border-slate-100">
                          <p className="text-[9px] font-mono text-slate-400 uppercase tracking-widest mb-1">Total Tx</p>
                          <p className="font-bold">{selectedNode.txCount}</p>
                        </div>
                        <div className="p-3 bg-slate-50 rounded-lg border border-slate-100">
                          <p className="text-[9px] font-mono text-slate-400 uppercase tracking-widest mb-1">Total Volume</p>
                          <p className="font-bold">${selectedNode.totalVolume.toLocaleString()}</p>
                        </div>
                      </div>

                      {selectedNode.isSuspicious && (
                        <div className="space-y-4">
                          <div>
                            <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-2">Suspicion Score</p>
                            <div className="flex items-end gap-2">
                              <span className="text-4xl font-bold tracking-tighter">
                                {detectionResult?.suspicious_accounts.find(a => a.account_id === selectedNode.id)?.suspicion_score.toFixed(1) || "0.0"}
                              </span>
                              <span className="text-sm font-medium text-slate-400 mb-1.5">/ 100.0</span>
                            </div>
                          </div>

                          <div>
                            <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-2">Detected Patterns</p>
                            <div className="flex flex-wrap gap-2">
                              {detectionResult?.suspicious_accounts.find(a => a.account_id === selectedNode.id)?.detected_patterns.map(p => (
                                <span key={p} className="px-2 py-1 bg-red-50 text-red-700 text-[10px] font-bold rounded border border-red-100 uppercase">
                                  {p.replace(/_/g, ' ')}
                                </span>
                              ))}
                            </div>
                          </div>

                          <div>
                            <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-2">Associated Ring</p>
                            <div className="flex items-center gap-2 px-3 py-2 bg-slate-900 text-white rounded-lg text-xs font-mono">
                              <Network className="w-3 h-3" />
                              {detectionResult?.suspicious_accounts.find(a => a.account_id === selectedNode.id)?.ring_id || "N/A"}
                            </div>
                          </div>
                        </div>
                      )}

                      {!selectedNode.isSuspicious && (
                        <div className="py-8 text-center border-2 border-dashed border-slate-100 rounded-xl">
                          <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                          <p className="text-sm font-medium text-slate-900">No Fraud Patterns Detected</p>
                          <p className="text-xs text-slate-500 mt-1">This account shows normal transaction behavior.</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="py-20 text-center border-2 border-dashed border-slate-100 rounded-xl">
                      <Search className="w-8 h-8 text-slate-300 mx-auto mb-2" />
                      <p className="text-sm text-slate-400">Select a node in the graph to view detailed forensics</p>
                    </div>
                  )}
                </div>

                {/* Top Suspicious Table */}
                <div className="bg-white border border-[#141414] rounded-2xl p-6 shadow-sm flex-1 overflow-hidden flex flex-col">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="font-serif italic text-lg">High-Risk Targets</h3>
                    <span className="text-[10px] font-mono bg-red-100 text-red-700 px-2 py-0.5 rounded">TOP 10</span>
                  </div>
                  <div className="space-y-2 overflow-auto">
                    {detectionResult?.suspicious_accounts.slice(0, 10).map((acc) => (
                      <button 
                        key={acc.account_id}
                        onClick={() => {
                          const stats = transactions.reduce((accStats, tx) => {
                            if (tx.sender_id === acc.account_id || tx.receiver_id === acc.account_id) {
                              accStats.count += 1;
                              accStats.volume += tx.amount;
                            }
                            return accStats;
                          }, { count: 0, volume: 0 });

                          setSelectedNode({
                            id: acc.account_id,
                            isSuspicious: true,
                            suspicionScore: acc.suspicion_score,
                            patterns: acc.detected_patterns,
                            ringId: acc.ring_id,
                            txCount: stats.count,
                            totalVolume: stats.volume
                          });
                        }}
                        className={cn(
                          "w-full flex items-center justify-between p-3 rounded-xl border transition-all group",
                          selectedNode?.id === acc.account_id ? "bg-[#141414] border-[#141414] text-[#E4E3E0]" : "bg-white border-slate-200 hover:border-slate-400"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold",
                            selectedNode?.id === acc.account_id ? "bg-white/20" : "bg-red-50 text-red-600"
                          )}>
                            {acc.suspicion_score.toFixed(0)}
                          </div>
                          <div className="text-left">
                            <p className="text-xs font-mono font-bold">{acc.account_id}</p>
                            <p className={cn(
                              "text-[9px] uppercase tracking-wider",
                              selectedNode?.id === acc.account_id ? "text-white/50" : "text-slate-400"
                            )}>
                              {acc.detected_patterns[0].replace(/_/g, ' ')}
                            </p>
                          </div>
                        </div>
                        <ChevronRight className={cn(
                          "w-4 h-4 transition-transform group-hover:translate-x-1",
                          selectedNode?.id === acc.account_id ? "text-white/50" : "text-slate-300"
                        )} />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="mt-20 border-t border-[#141414] px-6 py-8 bg-white/30">
        <div className="max-w-[1600px] mx-auto flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="space-y-2">
            <p className="text-xs font-bold uppercase tracking-widest">RIFT 2026 Money Muling Detection Challenge</p>
            <p className="text-[10px] text-slate-500 max-w-md">
              This engine uses advanced graph algorithms including DFS-based cycle detection, 
              temporal smurfing analysis, and layered shell network identification to detect 
              sophisticated financial crimes.
            </p>
          </div>
          <div className="flex gap-8">
            <div>
              <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Algorithm</p>
              <p className="text-xs font-bold">Graph Theory / DFS</p>
            </div>
            <div>
              <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Precision</p>
              <p className="text-xs font-bold">Target ≥ 70%</p>
            </div>
            <div>
              <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mb-1">Recall</p>
              <p className="text-xs font-bold">Target ≥ 60%</p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, variant = 'default' }: { 
  label: string, 
  value: string | number, 
  icon: any,
  variant?: 'default' | 'danger' | 'warning'
}) {
  return (
    <div className="bg-white border border-[#141414] rounded-2xl p-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <p className="text-[10px] font-mono text-slate-400 uppercase tracking-widest">{label}</p>
        <div className={cn(
          "w-8 h-8 rounded-lg flex items-center justify-center",
          variant === 'danger' ? "bg-red-50 text-red-600" : 
          variant === 'warning' ? "bg-amber-50 text-amber-600" : 
          "bg-slate-50 text-slate-600"
        )}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <p className="text-3xl font-bold tracking-tighter">{value}</p>
    </div>
  );
}

function CheckCircle2(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}
