# Aether NIDS: Comprehensive System & Feature Guide

This guide provides an end-to-end technical explanation of the **Aether AI-Powered Network Intrusion Detection System (NIDS)**. It details how the backend sniffer, machine learning models, database, and real-time frontend interact, followed by a walkthrough of every feature available in the analyst dashboard.

---

## 1. High-Level System Architecture & Flow

Aether NIDS is structured into four cooperative layers:

```text
  [ Network Traffic ]
          │
          ▼
┌──────────────────────────────────────────────┐
│  Data Ingestion Layer (sniffer.py)           │  <── Scapy Daemon / Traffic Simulator
└─────────────────────┬────────────────────────┘
                      │ Stream Packets
                      ▼
┌──────────────────────────────────────────────┐
│  Flow Aggregator & Feature Extractor         │  <── Compiles 15 network stats
└─────────────────────┬────────────────────────┘
                      │ Feature Vector
                      ▼
┌──────────────────────────────────────────────┐
│  ML Inference Engine (detection_engine.py)   │  <── Standardizes & Classifies (RF / XGBoost)
└─────────────────────┬────────────────────────┘
                      │ Prediction & Confidence
                      ▼
┌──────────────────────────────────────────────┐
│  Backend Core API (FastAPI + SQL DB)         │  <── Triggers DB, SMTP, & WebSocket Broadcast
└──────┬────────────────────────────────┬──────┘
       │                                │
       ▼ REST APIs                      ▼ WebSockets (/api/v1/ws/live)
┌───────────────────────────────────────┴──────┐
│  Operator Console Dashboard (React)          │  <── Glassmorphic UI & Live Recharts Charts
└──────────────────────────────────────────────┘
```

---

## 2. End-to-End Data Lifecycle

### A. Packet Ingestion & Capture
1. **Scapy Packet Sniffer**:
   - The sniffer daemon listens on the configured network interface (e.g. `eth0` or `wlan0`).
   - Packets are captured in promiscuous mode, filtering for IP-based protocols (TCP, UDP, ICMP).
2. **Simulation Traffic Generator**:
   - For environments lacking capture libraries (like Windows without Npcap/WinPcap), the system automatically launches a high-fidelity simulator thread.
   - This thread injects a mix of safe connection patterns (Benign) and periodic malicious traffic (DDoS, PortScan, BruteForce) to keep telemetry active.

### B. Flow Aggregation & Feature Extraction
Individual packet metrics are grouped into **bidirectional network flows** based on their **5-tuple key**:
$$\text{Flow Key} = (\text{Source IP}, \text{Source Port}, \text{Destination IP}, \text{Destination Port}, \text{Protocol})$$

Flows remain active in-memory and are updated with each incoming packet. A flow is flushed and sent for analysis when:
- It receives a TCP termination flag (`FIN` or `RST`).
- It has been idle for more than **5 seconds** (handled by a background cleanup thread).

Upon flushing, the compiler computes **15 numeric statistical features** required by the machine learning model:
1. `flow_duration`: Elapsed time of the flow in seconds.
2. `tot_fw_pkts`: Total packets sent in the forward direction.
3. `tot_bw_pkts`: Total packets sent in the backward direction.
4. `tot_l_fw_pkts`: Total volume of payload bytes sent forward.
5. `tot_l_bw_pkts`: Total volume of payload bytes sent backward.
6. `flow_byts_s`: Transmission rate (Total Bytes / Duration).
7. `flow_pkts_s`: Transmission rate (Total Packets / Duration).
8. `fwd_header_len`: Total header size of forward packets.
9. `bwd_header_len`: Total header size of backward packets.
10. `flags_fin`: Binary indicator if `FIN` flag was ever set.
11. `flags_syn`: Binary indicator if `SYN` flag was ever set.
12. `flags_rst`: Binary indicator if `RST` flag was ever set.
13. `flags_psh`: Binary indicator if `PSH` flag was ever set.
14. `flags_ack`: Binary indicator if `ACK` flag was ever set.
15. `protocol`: Numeric representation of protocol (6 for TCP, 17 for UDP, 1 for ICMP).

### C. ML Classification
- The feature vector is standardized using an `active_scaler.joblib` (StandardScaler) trained on the **CIC-IDS2017** dataset.
- The normalized vector is evaluated by the active classifier (`active_model.joblib`), classifying the flow into one of six categories:
  - `Benign`: Safe, normal traffic.
  - `DDoS`: Distributed Denial of Service flooding.
  - `PortScan`: Port sweeps and scanning.
  - `BruteForce`: Authentication cracking.
  - `Botnet`: Infected command & control traffic.
  - `WebAttack`: SQL Injections, Cross-Site Scripting, or vulnerability scanning.
- If model weights are missing or inference throws an error, the system automatically falls back on rule-based heuristics to ensure high availability.

### D. Threat Severity & Alarm Resolution
- Based on the classified attack label, a threat severity is assigned:
  - **CRITICAL**: DDoS, Botnet
  - **HIGH**: BruteForce
  - **MEDIUM**: PortScan, WebAttack
  - **LOW**: Benign / Normal
- Safe traffic is logged to the `traffic_logs` table.
- Malicious traffic is logged to `traffic_logs`, triggers a `model_predictions` record, creates a new entry in `alerts`, and appends an audit record to `alert_histories` marked as `UNRESOLVED`.

### E. Background Dispatch & Broadcasting
1. **SMTP Alerting**: If an alert is triggered, an HTML-formatted notification detailing the attack type, source IP, target IP, port numbers, protocol, and classification confidence is dispatched to SMTP mail servers in the background.
2. **WebSocket Broadcast**: A JSON payload is broadcasted over the `/api/v1/ws/live` WebSocket connection. Any connected React clients ingest the live data instantly.

---

## 3. Comprehensive Dashboard Feature Guide

The React-based frontend provides a glassmorphic dashboard divided into eight distinct sections:

### 1. User Authentication (Login / Sign-Up)
* **Incidents Analyst Authorization**: Secures access using standard username/password authentication.
* **Role Selection**: Supports `operator` (incident responder) and `admin` (SOC Lead) credentials.
* **Route Protection**: Implements React Router route guards. If a JWT token expires or is deleted, the operator is redirected back to the login page.

### 2. Main Dashboard (Overview Page)
* **Operational Readiness Cards**:
  - **System Status**: Monitors overall API and Sniffer loop readiness.
  - **Interface Binding**: Displays which ethernet interface Scapy is listening to.
  - **Database Size**: Track log counts written to disk.
* **Throughput Charts**: Visualizes live packets-per-second (PPS) and bytes throughput using smooth Recharts area lines.
* **Ingress Feed**: Scrolling visual ticker showing safe/unsafe network connection traffic as it arrives.

### 3. Real-Time Monitor (Real-Time Monitor Page)
A high-frequency dashboard updated exclusively by incoming WebSocket events:
* **Metric Cards**:
  - **Packets Per Second (PPS)**: Real-time traffic rate calculated over a sliding 1-second window.
  - **Active Concurrent Hosts**: Tracks the count of active unique source IPs seen over the last 10 seconds.
  - **Total Intrusions Blocked**: Sum of all historical database intrusions plus new live threats captured in the current session.
  - **Accumulated Packets**: Count of total logs captured since the dashboard was opened.
* **Ingress Flow Timeline**: Displays a historical area chart tracking PPS fluctuations over the last 20 seconds.
* **Attack Vector Proportions**: A pie chart showing the percentage breakdown of active threats (excluding benign traffic).
* **Threat Severity Stacked Timeline**: A stacked bar chart grouping threats by severity (Critical, High, Medium, Low) in 2-second buckets to visualize attack escalation.
* **Top Attacking Hosts**: A ranked list of the top 5 source IPs generating threat events, equipped with progress bars normalized against the highest attacker.
* **Alert Feed Queue**: Log listing of recent alerts streaming in, highlighted by severity.
* **Audio Alerts**: Playback of custom sine-wave sound chimes (high pitch for Critical/High threats) to alert operators even if they are looking at another screen.
* **Stream Controller**: A toggle to play/pause incoming WebSocket updates without disconnecting the socket, allowing an analyst to freeze the screen to investigate a sudden spike.

### 4. Live Traffic (Live Traffic Page)
* **Tabular Log Scroll**: Displays every packet flow indexed in the system.
* **Flow Diagnostics**: Inspects protocol header bytes, packet volume, connection durations, and raw ports.

### 5. Security Alerts Logs (Alerts Page)
* **Threat Incident Auditing**: The central hub for investigating flagged alerts.
* **Advanced Query Filters**: Filter logs by Source IP, Severity level, Attack Class, and Resolution status (`UNRESOLVED`, `INVESTIGATING`, `RESOLVED`).
* **Zoomed-In Detail Modal**: Clicking an alert opens a detailed overlay:
  - **Flow Details**: Basic network telemetry (Source/Dest ports and IPs, protocol, byte size).
  - **Machine Learning Stats**: The predicting model version, prediction label, and confidence score.
  - **Resolution Timeline**: Displays an audit history tracking who changed the alert status, when, and what notes were left.
* **Status Updates**: Allows operators to change status (e.g. from `UNRESOLVED` to `INVESTIGATING` to `RESOLVED`) and write resolution summaries.

### 6. Attack Analytics (Attack Analytics Page)
* **SOC Heatmaps**: Graphical breakdown of threat statistics.
* **Vulnerable Port Densities**: Recharts bar visualizations pointing out target ports under fire (e.g. port 22 for BruteForce, port 80 for DDoS) to locate ingress holes.

### 7. System Diagnostic Logs (System Logs Page)
* **Auditing Logs**: Lists error codes, warnings, and messages generated by backend modules (`SnifferDaemon`, `AlertService`, `DatabaseConnection`).
* **Debugging Center**: Alerts operators to connection drops with the SMTP server or network card sniffing failures.

### 8. System Settings (Settings Page)
* **Sniffer Configuration**: Bind packet sniffing to specific interfaces or select dummy modes.
* **Classifier Model Tuning**: Shows active model metadata (accuracy, F1-scores, file path, version) and allows toggling between RandomForest and XGBoost weights.
* **Firewall Banlist Manager**:
  - Lets operators manually ban or unban malicious source IPs.
  - Displays currently banned IPs. Arriving packets with matching source IPs are dropped before processing.
