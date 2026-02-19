import {
  Transaction,
  DetectionResult,
  FraudRing,
  SuspiciousAccount,
  DetectionSummary
} from "../types";

// Extended transaction with parsed epoch time for fast sliding windows
interface ParsedTx extends Transaction {
  time: number;
}

export class DetectionEngine {
  private transactions: ParsedTx[];
  private adjacencyList = new Map<string, Set<string>>();
  private reverseAdjacencyList = new Map<string, Set<string>>();
  private accountTransactions = new Map<string, ParsedTx[]>();
  private transactionPatterns = new Map<string, "cycle" | "smurfing" | "shell">();
  private startTime: number;

  private inDegree = new Map<string, number>();
  private outDegree = new Map<string, number>();
  private totalInAmount = new Map<string, number>();
  private totalOutAmount = new Map<string, number>();

  constructor(transactions: Transaction[]) {
    // Pre-parse timestamps to milliseconds to avoid repetitive Date parsing
    this.transactions = transactions.map(tx => ({
      ...tx,
      time: new Date(tx.timestamp).getTime()
    }));
    this.startTime = performance.now();
    this.buildGraph();
  }

  private buildGraph() {
    for (const tx of this.transactions) {
      if (!this.adjacencyList.has(tx.sender_id)) this.adjacencyList.set(tx.sender_id, new Set());
      this.adjacencyList.get(tx.sender_id)!.add(tx.receiver_id);

      if (!this.reverseAdjacencyList.has(tx.receiver_id)) this.reverseAdjacencyList.set(tx.receiver_id, new Set());
      this.reverseAdjacencyList.get(tx.receiver_id)!.add(tx.sender_id);

      if (!this.accountTransactions.has(tx.sender_id)) this.accountTransactions.set(tx.sender_id, []);
      if (!this.accountTransactions.has(tx.receiver_id)) this.accountTransactions.set(tx.receiver_id, []);

      this.accountTransactions.get(tx.sender_id)!.push(tx);
      this.accountTransactions.get(tx.receiver_id)!.push(tx);

      this.inDegree.set(tx.receiver_id, (this.inDegree.get(tx.receiver_id) || 0) + 1);
      this.outDegree.set(tx.sender_id, (this.outDegree.get(tx.sender_id) || 0) + 1);
      this.totalInAmount.set(tx.receiver_id, (this.totalInAmount.get(tx.receiver_id) || 0) + tx.amount);
      this.totalOutAmount.set(tx.sender_id, (this.totalOutAmount.get(tx.sender_id) || 0) + tx.amount);
    }
  }

  public analyze(): DetectionResult & { transactionPatterns: Record<string, "cycle" | "smurfing" | "shell"> } {
    const suspiciousAccountsMap = new Map<string, SuspiciousAccount>();
    const fraudRings: FraudRing[] = [];
    let ringCounter = 1;

    // 1. Detect Cycles (Length 3 to 5) - Bounded DFS
    ringCounter = this.detectCycles(suspiciousAccountsMap, fraudRings, ringCounter);

    // 2. Detect Smurfing (72h Window, 10+ Fan-in/Fan-out)
    ringCounter = this.detectSmurfing(suspiciousAccountsMap, fraudRings, ringCounter);

    // 3. Detect Shell Networks (3+ hops, intermediate has 2-3 txs)
    ringCounter = this.detectShellNetworks(suspiciousAccountsMap, fraudRings, ringCounter);

    // 4. Boost Risk via PageRank (Industry Secret Weapon)
    this.applyPageRankBoost(suspiciousAccountsMap);

    const suspicious_accounts = Array.from(suspiciousAccountsMap.values())
      .filter(a => !this.isLikelyMerchant(a.account_id)) // Merchant shielding
      .sort((a, b) => b.suspicion_score - a.suspicion_score);

    const allAccounts = new Set<string>();
    this.transactions.forEach(tx => {
      allAccounts.add(tx.sender_id);
      allAccounts.add(tx.receiver_id);
    });

    const summary: DetectionSummary = {
      total_accounts_analyzed: allAccounts.size,
      suspicious_accounts_flagged: suspicious_accounts.length,
      fraud_rings_detected: fraudRings.length,
      processing_time_seconds: Number(((performance.now() - this.startTime) / 1000).toFixed(3))
    };

    return { 
      suspicious_accounts, 
      fraud_rings: fraudRings, 
      summary,
      transactionPatterns: Object.fromEntries(this.transactionPatterns)
    };
  }

  // ==========================================
  // 1. CYCLE DETECTION (STRICT LENGTH 3-5)
  // ==========================================
  private detectCycles(map: Map<string, SuspiciousAccount>, rings: FraudRing[], counter: number): number {
    const nodes = Array.from(this.adjacencyList.keys());
    
    for (const startNode of nodes) {
      this.dfsCycles(startNode, startNode, [startNode], new Set([startNode]), map, rings, () => counter++);
    }
    return counter;
  }

  private dfsCycles(
    startNode: string, 
    currentNode: string, 
    path: string[], 
    visited: Set<string>, 
    map: Map<string, SuspiciousAccount>, 
    rings: FraudRing[],
    incrementCounter: () => number
  ) {
    if (path.length > 5) return; // Prompt limit

    const neighbors = this.adjacencyList.get(currentNode) || new Set();
    for (const neighbor of neighbors) {
      // Prevent duplicate cycles by enforcing startNode is the minimum string ID in the cycle
      if (neighbor < startNode) continue; 

      if (neighbor === startNode && path.length >= 3) {
        // Cycle found
        const ringId = `RING_${String(incrementCounter()).padStart(3, '0')}`;
        rings.push({
          ring_id: ringId,
          member_accounts: [...path],
          pattern_type: "cycle",
          risk_score: 95
        });

        path.forEach(acc => this.addSuspicious(map, acc, ringId, "cycle", 95));

        // Mark transactions
        for (let i = 0; i < path.length; i++) {
          const u = path[i];
          const v = path[(i + 1) % path.length];
          this.markPattern(u, v, "cycle");
        }
        continue;
      }

      if (!visited.has(neighbor)) {
        visited.add(neighbor);
        path.push(neighbor);
        this.dfsCycles(startNode, neighbor, path, visited, map, rings, incrementCounter);
        path.pop();
        visited.delete(neighbor);
      }
    }
  }

  // ==========================================
  // 2. SMURFING DETECTION (72H SLIDING WINDOW)
  // ==========================================
  private detectSmurfing(map: Map<string, SuspiciousAccount>, rings: FraudRing[], counter: number): number {
    const WINDOW_MS = 72 * 60 * 60 * 1000;

    const allAccounts = Array.from(this.accountTransactions.keys());
    
    for (const account of allAccounts) {
      const txs = this.accountTransactions.get(account) || [];
      
      // Separate In and Out
      const incoming = txs.filter(t => t.receiver_id === account).sort((a, b) => a.time - b.time);
      const outgoing = txs.filter(t => t.sender_id === account).sort((a, b) => a.time - b.time);

      // Check Fan-In
      if (this.hasSlidingWindowThreshold(incoming, WINDOW_MS, 10)) {
        const senders = new Set(incoming.map(t => t.sender_id));
        if (senders.size >= 10 && this.hasLowVariance(incoming)) {
          const ringId = `RING_${String(counter++).padStart(3, '0')}`;
          rings.push({ ring_id: ringId, member_accounts: [account, ...Array.from(senders)], pattern_type: "smurfing", risk_score: 88 });
          this.addSuspicious(map, account, ringId, "smurfing_fan_in", 88);
          incoming.forEach(t => this.transactionPatterns.set(t.transaction_id, "smurfing"));
        }
      }

      // Check Fan-Out
      if (this.hasSlidingWindowThreshold(outgoing, WINDOW_MS, 10)) {
        const receivers = new Set(outgoing.map(t => t.receiver_id));
        if (receivers.size >= 10) {
          const ringId = `RING_${String(counter++).padStart(3, '0')}`;
          rings.push({ ring_id: ringId, member_accounts: [account, ...Array.from(receivers)], pattern_type: "smurfing", risk_score: 85 });
          this.addSuspicious(map, account, ringId, "smurfing_fan_out", 85);
          outgoing.forEach(t => this.transactionPatterns.set(t.transaction_id, "smurfing"));
        }
      }
    }
    return counter;
  }

  private hasSlidingWindowThreshold(sortedTxs: ParsedTx[], windowMs: number, threshold: number): boolean {
    let left = 0;
    for (let right = 0; right < sortedTxs.length; right++) {
      while (sortedTxs[right].time - sortedTxs[left].time > windowMs) {
        left++;
      }
      if (right - left + 1 >= threshold) return true;
    }
    return false;
  }

  // ==========================================
  // 3. SHELL NETWORKS (STRICT 2-3 TX LIMIT)
  // ==========================================
  private detectShellNetworks(map: Map<string, SuspiciousAccount>, rings: FraudRing[], counter: number): number {
    for (const [a, aNeighbors] of this.adjacencyList.entries()) {
      for (const b of aNeighbors) {
        if (!this.isStrictShell(b)) continue;
        
        const bNeighbors = this.adjacencyList.get(b) || new Set();
        for (const c of bNeighbors) {
          if (!this.isStrictShell(c) || c === a) continue;
          
          const cNeighbors = this.adjacencyList.get(c) || new Set();
          for (const d of cNeighbors) {
            if (d === a || d === b) continue;
            
            // Found A -> B -> C -> D
            const ringId = `RING_${String(counter++).padStart(3, '0')}`;
            rings.push({ ring_id: ringId, member_accounts: [a, b, c, d], pattern_type: "shell", risk_score: 92 });
            [a, b, c, d].forEach(acc => this.addSuspicious(map, acc, ringId, "layered_shell", 92));
            
            this.markPattern(a, b, "shell");
            this.markPattern(b, c, "shell");
            this.markPattern(c, d, "shell");
          }
        }
      }
    }
    return counter;
  }

  private isStrictShell(account: string): boolean {
    const totalTxs = this.accountTransactions.get(account)?.length || 0;
    return totalTxs === 2 || totalTxs === 3; // Strict Prompt Requirement
  }

  // ==========================================
  // UTILS & ADVANCED HEURISTICS
  // ==========================================
  private applyPageRankBoost(map: Map<string, SuspiciousAccount>) {
    const nodes = Array.from(this.adjacencyList.keys());
    if (nodes.length === 0) return;
    
    const N = nodes.length;
    const pr = new Map<string, number>();
    nodes.forEach(n => pr.set(n, 1 / N));

    for (let i = 0; i < 15; i++) {
      const newPR = new Map<string, number>();
      nodes.forEach(n => newPR.set(n, 0.15 / N));

      for (const n of nodes) {
        const neighbors = this.adjacencyList.get(n) || new Set();
        const share = (pr.get(n)! * 0.85) / (neighbors.size || 1);
        neighbors.forEach(m => newPR.set(m, (newPR.get(m) || 0) + share));
      }
      nodes.forEach(n => pr.set(n, newPR.get(n)!));
    }

    const avgPR = Array.from(pr.values()).reduce((a, b) => a + b, 0) / N;
    for (const [acc, score] of pr.entries()) {
      if (score > avgPR * 3 && map.has(acc)) {
        map.get(acc)!.suspicion_score = Math.min(100, map.get(acc)!.suspicion_score + 10);
      }
    }
  }

  private hasLowVariance(txs: ParsedTx[]): boolean {
    const amounts = txs.map(t => t.amount);
    if (amounts.length < 5) return false;
    const mean = amounts.reduce((a, b) => a + b, 0) / amounts.length;
    const variance = amounts.reduce((a, b) => a + (b - mean) ** 2, 0) / amounts.length;
    return Math.sqrt(variance) < mean * 0.15; // Standard deviation < 15% of mean
  }

  private isLikelyMerchant(account: string): boolean {
    const inDeg = this.inDegree.get(account) || 0;
    const outDeg = this.outDegree.get(account) || 0;
    // Merchants receive a lot, but don't disperse immediately to distinct accounts
    return inDeg > 15 && outDeg < 3; 
  }

  private addSuspicious(map: Map<string, SuspiciousAccount>, account: string, ringId: string, pattern: string, baseScore: number) {
    if (!map.has(account)) {
      map.set(account, { account_id: account, suspicion_score: baseScore, detected_patterns: [pattern], ring_id: ringId });
    } else {
      const acc = map.get(account)!;
      acc.suspicion_score = Math.min(100, acc.suspicion_score + 5);
      if (!acc.detected_patterns.includes(pattern)) acc.detected_patterns.push(pattern);
    }
  }

  private markPattern(sender: string, receiver: string, pattern: "cycle" | "smurfing" | "shell") {
    const txs = this.accountTransactions.get(sender)?.filter(t => t.sender_id === sender && t.receiver_id === receiver) || [];
    txs.forEach(t => this.transactionPatterns.set(t.transaction_id, pattern));
  }
}