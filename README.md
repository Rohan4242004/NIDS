# Aether NIDS: AI-Powered Network Intrusion Detection System

Aether NIDS is a production-ready, real-time Network Intrusion Detection System combining scapy-based packet capturing, machine learning classification engines, SMTP alert notifications, and a professional glassmorphic React dashboard monitor.

---

## 🚀 Key Features

* **Real-Time Packet Ingest & Sniffing**: Uses a background Scapy sniffer to capture ethernet frame flows, extract statistical network features, and predict cyber threats on the fly. Includes a high-fidelity **Simulation Engine** for instant dashboard telemetry during testing.
* **Dual Machine Learning Classifiers**: Features Random Forest and XGBoost classification models trained and optimized on the **CIC-IDS2017 dataset** to predict six traffic classes: `Benign`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`, and `WebAttack`.
* **Dynamic Threat Severity Engine**: Assigns incident severities based on threat categories:
  * **Critical**: `DDoS`, `Botnet`
  * **High**: `BruteForce`
  * **Medium**: `PortScan`, `WebAttack`
  * **Low**: `Benign` / `Normal`
* **Automated Alert Auditing & Notifications**: Saves detected threats, issues HTML security alerts via SMTP in the background, and logs complete operator action history (e.g. status changes from `UNRESOLVED` ➔ `INVESTIGATING` ➔ `RESOLVED`).
* **Interactive React Console Panel**: Modern responsive SPA containing:
  1. **Dashboard Overview**: Aggregated KPI metrics, connections throughput charts, and live flow scroll logs.
  2. **Real-Time Monitor**: WebSockets-driven view tracking Packets Per Second (PPS) accumulators, active concurrent connections count, attack type pie charts, and threat severity timeline buckets.
  3. **Alerts Log**: Investigator query search logs, alarm resolution triggers, and audit history logs.
  4. **Attack Analytics**: Detailed Pie and Bar visualizations detailing target ports and host densities.
  5. **System Log Audits**: Inspect backend event messages (INFO, WARNING, ERROR).
  6. **System Settings**: Configures capture bindings, active ML inference weights, and firewall banlists.

---

## 📁 Repository Directory Structure

```text
├── backend/                  # FastAPI Application Core
│   ├── app/
│   │   ├── api/              # API REST Routers (auth, logs, alerts, models, dashboard)
│   │   ├── auth/             # JWT Token authentication and Bcrypt hashing utilities
│   │   ├── database/         # SQLite/MySQL DB connection pooling and SessionLocal
│   │   ├── models/           # SQLAlchemy DB Models (User, Alert, BlockedIP, SystemLog, etc.)
│   │   ├── ml/               # Inference engine wrapper delegating classification runs
│   │   ├── packet_capture/   # Sniffer daemon thread capturing packets and broadcasting
│   │   └── services/         # AlertManagementService handling audits and SMTP sends
│   ├── main.py               # Application entrypoint starting Uvicorn server
│   ├── nids.db               # SQLite local database
│   └── requirements.txt      # Python backend dependencies
│
├── frontend/                 # React SPA Dashboard (Vite + Recharts + React Router)
│   ├── src/
│   │   ├── assets/           # UI media assets
│   │   ├── components/       # Layout structures and Navigation sidebars
│   │   ├── pages/            # 7 console views (Login, Overview, RealTime, Alerts, Analytics, Logs, Settings)
│   │   ├── services/         # Axios API clients (api.js) and WebSocket listeners (websocket.js)
│   │   ├── App.jsx           # Routing configuration & route protection (JWT)
│   │   └── index.css         # Glassmorphic custom CSS tokens
│   ├── package.json          # Node dependencies
│   └── vite.config.js        # Vite configurations
│
├── ml_pipeline/              # Machine Learning Training Suite
│   ├── src/
│   │   ├── preprocess.py     # CIC-IDS2017 Preprocessing, scaling, and balancing
│   │   └── train_engine.py   # Fits RF & XGBoost, compares F1 metrics, exports joblibs
│   └── models/               # Serialized active weights (scaler and best model)
│
├── sensor/                   # Remote Sniffing Sensor Probe
│   └── sensor.py             # Scapy probe script logging flows to target backend collector
│
└── DEPLOYMENT.md             # Containerized and bare-metal production deployment guide
```

---

## 🛠️ Installation & Getting Started

### 1. Backend Ingestion Core Setup
Navigate into the `/backend` folder and initialize a Python virtual environment:
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Configure local environment variables. Create a `.env` file in `/backend`:
```ini
DATABASE_URL=sqlite:///./nids.db
SECRET_KEY=yoursecretjwtkeyhere
ACCESS_TOKEN_EXPIRE_MINUTES=60

# SMTP settings for notification dispatches
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_USERNAME=mock_user
SMTP_PASSWORD=mock_pass
SMTP_SENDER=nids-alerts@domain.com
SMTP_RECEIVERS=soc-team@domain.com
```

Launch the FastAPI application server:
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
* The Swagger interactive REST docs will be available at: `http://localhost:8000/docs`

### 2. Frontend React Dashboard Setup
Navigate into the `/frontend` folder:
```bash
cd ../frontend
npm install
npm run dev
```
* Open your browser to: `http://localhost:5173/`

### 3. ML Model Training & Preprocessing
If you wish to re-train the Random Forest or XGBoost models using the CIC-IDS2017 datasets:
```bash
cd ../ml_pipeline
# Put raw CIC-IDS2017 CSV tables in dataset/
python src/preprocess.py
python src/train_engine.py
```
This fits both classifiers, prints test metrics, selects the best model, and serializes it to `/ml_pipeline/models/` for ingestion by the backend `/ml` module.

---

## 🌐 WebSockets Event Architecture

The system uses a persistent WebSocket connection `/api/v1/ws/live` to broadcast live classification flows and alerts to connected frontend consoles.

### 1. `new_flow` (Benign Telemetry)
Broadcaster event triggered on safe traffic:
```json
{
  "event": "new_flow",
  "timestamp": "2026-06-15T16:12:45.109Z",
  "data": {
    "log_id": 1824,
    "alert_id": null,
    "severity": "INFO",
    "attack_type": "Benign",
    "source": "192.168.1.15:52311",
    "destination": "8.8.8.8:53",
    "flow_details": {
      "protocol": "UDP",
      "duration_sec": 0.042,
      "total_bytes": 128,
      "total_packets": 2
    },
    "confidence": 0.998
  }
}
```

### 2. `alert_triggered` (Malicious Telemetry)
Broadcaster event triggered when an attack is classified:
```json
{
  "event": "alert_triggered",
  "timestamp": "2026-06-15T16:13:02.401Z",
  "data": {
    "log_id": 1825,
    "alert_id": 92,
    "severity": "CRITICAL",
    "attack_type": "DDoS",
    "source": "185.220.101.4:43210",
    "destination": "192.168.1.10:80",
    "flow_details": {
      "protocol": "TCP",
      "duration_sec": 0.125,
      "total_bytes": 451200,
      "total_packets": 850
    },
    "confidence": 0.985
  }
}
```

---

## 🔒 Firewall Banlist Rules

Banned hosts are queried on settings startup. When a security threat requires immediate isolation, operators enforce IP bans in settings. This commits firewall rules to the database. The NIDS packet processor checks all arriving flows against this banlist and discards matching connections. Banned IPs are visible in settings and can be revoked (unbanned) at any time.

---

## ⚖️ License
Distributed under the MIT License. See `LICENSE` for more information.
