# AI SRE Reliability Console & Automation Engine

A self-healing, intelligent Site Reliability Engineering (SRE) automation platform and real-time reliability console. The system continuously monitors local processes, services, and system metrics, uses Gemini AI for anomaly diagnostics and remediation recommendations, and offers an interactive administrator command center.

---

## 🗺️ System Architecture

```text
                     +---------------------------------------+
                     |  Local Services & Telemetry Telemetry |
                     +-------------------+-------------------+
                                         | (every 60s)
                                         v
                     +-------------------+-------------------+
                     |      Background SRE Daemon (main.py)  |
                     +-------------------+-------------------+
                                         |
                       [Healthy State]   |   [Anomaly Detected]
                     +-------------------+-------------------+
                     | Bypass LLM Calls  | Invoke Gemini AI  |
                     +-------------------+-------------------+
                                         |
                                         v
                     +-------------------+-------------------+
                     | reports/incident_<timestamp>.json     |
                     +-------------------+-------------------+
                                         |
                                         v
                     +-------------------+-------------------+
                     |  Flask Reliability Server (sns.py)    |
                     +-------------------+-------------------+
                                         |
                  +----------------------+----------------------+
                  | (AJAX Fetch API)                            | (EventStream SSE)
                  v                                             v
       +----------+-----------+                     +-----------+-----------+
       |   Reliability UI     |                     | Live Container Stream |
       | (dashboard.html)     |                     |    (stream_logs)      |
       +----------------------+                     +-----------------------+
```

---

## 🚀 Key Features

### 1. Self-Healing Background SRE Daemon
* **Local Process & Metric Checks:** Monitors CPU, Memory, Disk utilization, and key systemd services (`nginx`, `mysql`, `ssh`, `docker`, `snapd`).
* **Auto-Recovery:** Automatically attempts a single-cycle recovery (e.g. `sudo systemctl restart nginx`) if a service enters a failed state.
* **API Quota Protection:** Background diagnostics bypasses LLM calls completely when all local metrics and services are operating normally, ensuring zero unnecessary API key consumption.

### 2. Administrator Reliability Console (Flask)
* **Incident History Inspector:** Lists historical diagnostics reports with chronological sorting. Features an asynchronous AJAX loading architecture with cache validation for load times under 40ms.
* **Service Log Explorer:** Fully interactive log viewer. Authenticated administrators can stream live container logs (SSE) or inspect static journal traces.
* **Centralized AI SRE Chatbot:** Interact with an intelligent agent to query incident contexts. Chatbot automatically detects commands and generates click-to-run buttons for whitelisted remediation operations.

### 3. Docker Infrastructure Explorer
* Displays resources under sub-tabs: **Containers**, **Images**, and **Volumes**.
* Supports real-time resource inspection (`docker inspect`) and one-click removal directly through chatbot recommendations.

### 4. Granular RBAC (Role-Based Access Control)
* Real-time MySQL-backed viewer access checking.
* **Service Keyword Fallback Matching:** Allows administrators to restrict viewers using generic service keywords (e.g. `nginx`, `docker`). The system dynamically maps this to related container logs (`docker:nginx`), K8s pods (`k8s:kube-system/nginx-xxx`), and system daemons (`systemd:nginx`) case-insensitively, resolving standard "Forbidden" log restrictions.
* Allowed log sources list clearly labels system-level processes (`System Service: docker`) vs namespace wildcards (`Docker (All Resources)`).

### 5. FinOps Cost Analysis
* AWS Billing dashboard showing historical trend lines and service breakdown charts.
* LLM-driven Automated Cost Comparison with rate limit protection (graceful 429 handlers).

---

## 🛠️ Tech Stack
* **Backend:** Flask (Python 3.10+), PyMySQL (MySQL connector)
* **Database:** MySQL / MariaDB (user credentials, viewer RBAC settings)
* **Frontend:** Vanilla CSS & HTML5, Vanilla JavaScript (SSE log streaming, AJAX asynchronous views)
* **AI Engine:** Google GenAI SDK (`google-genai>=0.5.0`)
* **Infrastructure Drivers:** Docker CLI, `kubectl` CLI, `systemctl` / `journalctl`

---

## 📋 Prerequisites
Ensure you have the following installed on your host system:
1. **Python 3.10+** (with virtual environment capability)
2. **MySQL / MariaDB Server**
3. **Docker Engine** (to use container log streaming and Docker resource tabs)
4. **Kubectl** (optional, for Kubernetes cluster integrations)

---

## ⚙️ Environment Configuration

Create a `.env` file or export the following environment variables:

```env
# Gemini API Key (Required for AI features)
GEMINI_API_KEY=your-api-key-here

# Flask Session Security Secret Key
# Generate a secure random token by running: 
# python -c "import secrets; print(secrets.token_hex(16))"
ADMIN_SECRET_KEY=your-generated-secret-key-here

# MySQL Configuration
MYSQL_HOST=localhost
MYSQL_USER=sre_admin
MYSQL_PASSWORD=your-mysql-password
MYSQL_DATABASE=sre_db

# AWS Configuration (Optional, falls back to local ~/.aws config or mock telemetry)
# AWS_ACCESS_KEY_ID=your-aws-access-key-id
# AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
# AWS_REGION=us-west-1
# SNS_TOPIC_ARN=arn:aws:sns:us-west-1:123456789012:sre-alerts-topic

# Local Host SRE Configuration
AUTO_RESTART_FAILED_SERVICE_ONCE=True
LOCAL_MONITOR_INTERVAL_SECONDS=60
```

---

## 🏃 Running the Application

### 1. Initialize Virtual Environment & Install Dependencies
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Unix:
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 2. Setup the Database & Admin User
Run the setup script to initialize MySQL tables and create your primary administrator user:
```bash
python create_admin.py
```

The database script initializes the following SQL schema:
```sql
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    allowed_log_sources TEXT, -- Comma-separated list of patterns (e.g. docker:*, nginx)
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 3. Start the Background SRE Monitoring Thread
Run the background daemon to begin local health checks and report writing:
```bash
python main.py
```

### 4. Run the Flask Web Application
Start the Reliability Console server:
```bash
python run_receiver.py
```
Open your browser and navigate to `http://localhost:5000/admin`.

---

## 📁 Project Structure

```text
├── admin/                     # Admin logic and helper modules
│   ├── auth.py                # Database connection and viewer RBAC checks
│   ├── reports.py             # Incident reports caching and loading
│   └── ai_features.py         # AI scanners and post-mortem RCA utilities
├── analyzer/                  # Local system diagnostics inspectors
│   ├── service_diagnostics.py # systemd services status check & auto-restart
│   ├── incident_classifier.py # Categorizes system anomalies
│   └── analyzer.py            # Diagnostic analyzer interface
├── collector/                 # Host metric and log collectors
│   ├── cpu.py, memory.py      # Resource telemetry collectors
│   ├── containers.py          # Docker container list & logs collector
│   └── logs.py                # system syslog/nginx log file readers
├── templates/                 # HTML templates
│   └── dashboard.html         # Main multi-view reliability admin dashboard
├── run_receiver.py            # Main entry point for Flask App
├── main.py                    # Main SRE monitoring loop daemon
├── requirements.txt           # Python application dependencies
└── README.md                  # Project documentation
```

---

## 🔒 Security & Remediation Commands Whitelist
The chatbot only permits executing specific system commands. The backend regex whitelists:
* **Docker:** `docker start/stop/restart/rm`, `docker rmi`, `docker volume rm`
* **Kubernetes:** `kubectl scale deployment`, `kubectl rollout restart`
* **Services:** `systemctl start/stop/restart`
