# 🛡️ Tremor - Early Warning Log Analyzer

A full-stack security tool that parses **SSH auth logs** and **Apache/Nginx access logs**, 
detects brute-force attacks using a sliding-window algorithm, and visualises results through 
a dark-themed web interface powered by matplotlib and seaborn.

---

## 🚀 Quick Start

### 1. Set up & start the backend
```powershell
# From the project root
.\start.ps1
```
Or manually:
```powershell
cd backend
pip install -r requirements.txt
python server.py
```

### 2. Open the frontend
Open `frontend/index.html` in your browser.  
Click **Load SSH Sample** or **Load Apache Sample**, then **Analyze Logs**.

---

## 📁 Project Structure
```
log-analyzer/
├── backend/
│   ├── analyzer.py          # Core engine: regex parsing, detection, chart generation
│   ├── server.py            # Flask REST API
│   ├── requirements.txt
│   └── sample_logs/
│       ├── ssh_auth.log     # Synthetic SSH auth log with brute-force patterns
│       └── apache_access.log
├── frontend/
│   ├── index.html           # Single-page UI
│   ├── style.css            # Dark purple/pink cybersecurity theme
│   └── app.js               # API calls, chart rendering, table generation
├── start.ps1                # One-click Windows startup script
└── README.md
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/health` | Liveness check |
| POST   | `/api/analyze` | Analyse user-supplied log text |
| GET    | `/api/sample/ssh` | Analyse bundled SSH sample |
| GET    | `/api/sample/apache` | Analyse bundled Apache sample |
| GET    | `/api/sample/<type>/raw` | Get raw sample log text |

### POST `/api/analyze` body
```json
{
  "log_text":       "…raw log content…",
  "log_type":       "auto",
  "threshold":      5,
  "window_seconds": 60
}
```

---

## 📊 Log Formats Supported

### SSH Auth Log (`/var/log/auth.log`)
```
Oct 29 02:00:01 server sshd[1234]: Failed password for root from 185.234.218.45 port 51201 ssh2
Oct 29 02:00:04 server sshd[1237]: Invalid user oracle from 185.234.218.45 port 51204
```

### Apache / Nginx Access Log
```
185.234.218.45 - - [29/Oct/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 512
```

---

## ⚙️ Detection Logic

**Sliding Window Algorithm**  
For each IP, the max number of failed logins within any `window_seconds` interval is computed in O(n).  
If that count ≥ `threshold`, the IP is flagged.

| Severity   | Condition                 |
|-----------|---------------------------|
| CRITICAL  | ≥ 20 events / window      |
| HIGH      | ≥ 10 events / window      |
| MEDIUM    | ≥ threshold events / window |

---

## 🎨 Charts Generated

1. **Timeline** — Area chart of failed logins in 5-minute buckets
2. **Top IPs** — Horizontal bar chart coloured by severity
3. **Heatmap** — Attack intensity by hour of day vs. date

---

## 🧪 CLI Testing
```powershell
cd backend
python analyzer.py ssh      # Test with SSH sample log
python analyzer.py apache   # Test with Apache sample log
```
