# NIDS Production Container Deployment Guide

This document describes how to deploy, configure, and operate the Network Intrusion Detection System (NIDS) inside Docker container environments.

## 1. System Architecture

The NIDS architecture consists of three services connected via a virtual Docker network:
1. **Frontend**: React application bundled and served by Nginx on port `80`. Nginx acts as a reverse proxy, mapping `/api/v1` and WebSocket connections directly to the backend.
2. **Backend**: FastAPI web server running on port `8000`. Analyzes packets using Scapy and ML models, stores alerts and logs, and handles real-time streams.
3. **Database**: MySQL 8.0 instance running on port `3306`. Persists system schemas, user operators list, firewall blocked IPs, and captures.

---

## 2. Prerequisites

Ensure the following programs are installed on the deployment host:
- **Docker** (Engine v20.10.0 or higher)
- **Docker Compose** (Compose v2.0.0 or higher)

The following ports must be free and unbound:
- Port `80` (HTTP web interface access)
- Port `3306` (MySQL server binding - optional if database access is remote only)

---

## 3. Environment Parameters

Configure credentials and behaviors inside the root `docker-compose.yml` file under the `environment` keys of each service, or create a `.env` file at the root.

| Environment Variable | Service | Default Value | Description |
|---|---|---|---|
| `DATABASE_URL` | backend | `mysql+pymysql://...` | Connection URI pointing to the MySQL container node. |
| `SECRET_KEY` | backend | *Auto-generated* | Secret signing key for JWT authorization tokens. |
| `SNIFFER_INTERFACE` | backend | `""` | Interface card to sniff (e.g. `eth0`). Defaults to simulator mode if empty. |
| `MYSQL_DATABASE` | db | `nids` | Database schema name initialized on boot. |
| `MYSQL_USER` | db | `nids_user` | Non-root admin user credential. |
| `MYSQL_PASSWORD` | db | `nids_password_123` | Database access password. |

---

## 4. Run Instructions

### Build and Launch the Stack
Execute the following command at the root directory of the workspace:
```bash
docker compose up --build -d
```
*The `--build` flag compiles the multi-stage Vite assets, and `-d` runs the containers in detached (background) mode.*

### Verify Service Health
Ensure that all health checks have passed successfully:
```bash
docker compose ps
```
The console will display `(healthy)` next to the running containers after they pass database pings and Uvicorn checks.

### Inspect Live Log Output
To inspect container startup steps or trace real-time packet-sniffer updates:
```bash
docker compose logs -f
```
Or check logs of specific nodes:
```bash
docker compose logs -f backend
```

### Stopping the Stack
To safely shutdown services and stop container networks:
```bash
docker compose down
```
*Note: MySQL database data is persisted inside the named volume `mysql_data` and is not lost when containers are destroyed.*

---

## 5. Packet Sniffing Permissions (Linux Hosts)

For Scapy to capture raw host interface packets on Linux deployment machines, the backend container requires raw socket access.
The `docker-compose.yml` configuration includes:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
```
These capability flags grant raw networking controls to the container. If you wish to capture host interface traffic instead of container virtual interface traffic, you can bind the backend container directly to the host network by adding `network_mode: "host"` in the backend service configuration.

---

## 6. Troubleshooting

### Container stuck in pps / connection error
If the database takes longer than 60 seconds to fully initialize, the backend container might exhaust health check retries.
Restart the stack manually to re-trigger check cycles:
```bash
docker compose restart backend
```

### Purging Database Volume
To reset the system completely, including clearing out all user accounts and logs:
```bash
docker compose down -v
```
*(This deletes the persistent named volume `mysql_data`).*
