# RIFT 2026: Money Muling Detection Engine

**Live Demo URL:** [INSERT RENDER URL HERE]
**Demo Video:** [INSERT LINKEDIN URL HERE]

## 📌 Project Overview
A high-performance, graph-based financial forensics engine built to detect sophisticated money muling networks. The system ingests raw transaction data and utilizes advanced graph theory to expose circular fund routing, temporal smurfing, and multi-hop layered shell networks.

## 🛠 Tech Stack
* **Frontend:** React 19, TypeScript, Tailwind CSS
* **Graph Visualization:** HTML5 Canvas API + D3-Force Physics (Optimized for 10K+ nodes)
* **Backend:** Node.js, Express
* **Data Processing:** PapaParse (CSV Streaming)

## 🧠 Algorithm Approach & Complexity Analysis
Our engine avoids naive $O(N^2)$ bottlenecks by utilizing pre-computed adjacency lists and temporal sorting:
1. **Cycle Detection (DFS):** Bounded Depth-First Search (max depth 5) starting from minimal lexicographical nodes to avoid duplicate cycle reporting. Time Complexity: $O(V \times E^4)$ bounded $\rightarrow$ practical $O(V+E)$.
2. **Temporal Smurfing (Sliding Window):** Transactions are chronologically sorted $O(N \log N)$. A Two-Pointer sliding window algorithm scans for 10+ transactions within a 72-hour constraint in $O(N)$ time.
3. **Shell Networks:** Strict out-degree/in-degree mapping combined with a constraint filter (total txs $\le$ 3) allows us to traverse candidate chains in $O(V \times d^3)$.
4. **False Positive Shielding:** Implements standard deviation variance checking ($\sigma < 0.15\mu$) to differentiate structured smurfing from organic payroll variance.

## ⚖️ Suspicion Score Methodology
Base risk scores are deterministically assigned based on the detected topology:
* **Cycles:** Base 95 (Highest confidence of laundering)
* **Shell Networks:** Base 92 (High confidence of layering)
* **Smurfing:** Base 85-88 (Fan-in/Fan-out detection)
* **PageRank Anomaly Boost:** We run 15 iterations of PageRank ($d=0.85$). Nodes with high centrality but balanced flow (in $\approx$ out) receive a +10 risk penalty, identifying "Super-Aggregator" nodes.

## 🚀 Installation & Setup
1. Clone the repository: `git clone https://github.com/YourUsername/rift-2026-mule-detection.git`
2. Install dependencies: `npm install`
3. Run the development server: `npm run dev`
4. Access the UI at `http://localhost:3000`

## 📖 Usage Instructions
1. Navigate to the web application.
2. Upload a valid transaction CSV file matching the schema: `transaction_id, sender_id, receiver_id, amount, timestamp`.
3. Wait for the engine to construct the graph and compute risks.
4. Interact with the Canvas-rendered graph to inspect specific nodes, or review the Fraud Rings table for summary data.
5. Click "Export JSON" to download the strict schema output.

## ⚠️ Known Limitations
* **Memory Limits:** The current Canvas + D3-force implementation is visually stable up to ~15,000 transactions. Beyond 20,000, WebGL rendering would be required to maintain 60 FPS.
* **Temporal Boundaries:** Transactions spanning exactly over the edge of a month boundaries require standardized ISO-8601 parsing; invalid date strings will bypass the sliding window.

## 👥 Team Members
* [Your Name] - Graph Architect & Full Stack Engineer
* [Teammate Name] (if applicable)
