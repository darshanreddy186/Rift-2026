export interface Transaction {
  transaction_id: string;
  sender_id: string;
  receiver_id: string;
  amount: number;
  timestamp: string;
}

export interface AccountNode {
  id: string;
  isSuspicious: boolean;
  suspicionScore: number;
  patterns: string[];
  ringId?: string;
  patternType?: "cycle" | "smurfing" | "shell";
  txCount: number;
  totalVolume: number;
}

export interface TransactionEdge {
  id: string;
  source: string;
  target: string;
  amount: number;
  timestamp: string;
  isSuspicious: boolean;
  patternType?: "cycle" | "smurfing" | "shell";
}

export interface FraudRing {
  ring_id: string;
  member_accounts: string[];
  pattern_type: "cycle" | "smurfing" | "shell";
  risk_score: number;
}

export interface SuspiciousAccount {
  account_id: string;
  suspicion_score: number;
  detected_patterns: string[];
  ring_id: string;
}

export interface DetectionSummary {
  total_accounts_analyzed: number;
  suspicious_accounts_flagged: number;
  fraud_rings_detected: number;
  processing_time_seconds: number;
}

export interface DetectionResult {
  suspicious_accounts: SuspiciousAccount[];
  fraud_rings: FraudRing[];
  summary: DetectionSummary;
}
