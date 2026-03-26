<div align="center">

```
██████╗ ██╗███████╗██╗  ██╗██████╗ ██╗███╗   ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝██║███████╗███████║██████╔╝██║██╔██╗ ██║    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██║╚════██║██╔══██║██╔══██╗██║██║╚██╗██║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ██║███████║██║  ██║██████╔╝██║██║ ╚████║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# PhishBIN Guard

**Unified Cyber Threat Analysis Platform**

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js-000000?style=flat-square&logo=next.js)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-4169E1?style=flat-square&logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Cache-Redis-DC382D?style=flat-square&logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED?style=flat-square&logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

*Detect phishing URLs. Dissect malicious binaries. All in one place.*

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [API Reference](#-api-reference)
- [Scoring Algorithm](#-scoring-algorithm)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Development (Docker)](#development-docker)
  - [Production (Docker)](#production-docker)
  - [Manual Setup](#manual-setup)
- [Environment Variables](#-environment-variables)
- [External API Integrations](#-external-api-integrations)
- [Development Rules](#-development-rules)
- [Testing](#-testing)
- [Monitoring](#-monitoring)

---

## 🧭 Overview

PhishBIN Guard is an open-source, browser-based cybersecurity analysis platform built for:

- **Cybersecurity students** learning threat analysis
- **Security analysts** who need a fast artifact inspector
- **Universities and academic institutions** teaching offensive/defensive security
- **Hackathons and demos** showcasing threat intelligence workflows

It combines **phishing URL heuristics**, **static binary analysis**, and **external threat intelligence APIs** into a single dashboard — no execution of files, no cloud upload risks, full transparency.

---

## ✨ Features

### 🎣 Phishing URL Detection

| Check | Description |
|---|---|
| **Punycode / IDN Homograph** | Detects `xn--` prefix used in IDN spoofing attacks |
| **IP Address in Hostname** | Flags direct IP URLs (e.g., `http://192.168.1.1/login`) |
| **Excessive Subdomain Depth** | Penalizes URLs with more than 2 subdomain levels |
| **Typosquatting Detection** | Levenshtein distance check against popular brands (Google, PayPal, etc.) |
| **Suspicious Keyword Matching** | Scans for keywords like `login`, `verify`, `reset`, `billing`, `confirm` |
| **Domain Entropy Analysis** | High Shannon entropy indicates randomly-generated domains |
| **Long Domain Penalty** | Flags domains exceeding 40 characters |
| **User-info Abuse** | Detects `@` symbol injection in URL authority (`user:pass@evil.com`) |
| **External API Consensus** | Cross-references VirusTotal, Google Safe Browsing, AbuseIPDB |

### 🔬 Binary / PE File Analysis

| Check | Description |
|---|---|
| **Shannon Entropy** | Detects packed or encrypted binaries (entropy > 7.2 flagged) |
| **PE Import Analysis** | Hunts for high-risk WinAPI calls (`CreateRemoteThread`, `VirtualAllocEx`, etc.) |
| **Suspicious DLL Detection** | Flags dangerous DLLs like `urlmon.dll`, `wininet.dll`, `mshtml.dll` |
| **Section Entropy** | Per-section entropy scoring to detect obfuscated code segments |
| **Export Table Analysis** | No-export pattern common in droppers and injectors |
| **String Extraction** | ASCII and UTF-16LE string hunting from raw binary |
| **Embedded IP & URL Extraction** | Regex-based C2 indicator extraction from strings |
| **Malware String Matching** | Detects known strings like `mimikatz`, `meterpreter`, `cobaltstrike`, `shellcode` |

### 📊 Unified Threat Scoring

- **Adaptive weighting algorithm** — automatically adjusts based on available data sources
- **Risk classification**: `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`
- **Verdict + mitigation steps** with every result
- **Full evidence JSON** — local heuristics, API results, raw score components

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────┐
│                  User Browser                    │
└────────────────────┬─────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────┐
│           Frontend — Next.js / React             │
│           Neo Brutalist UI (TailwindCSS)         │
│           Chart.js for visual risk breakdown     │
└────────────────────┬─────────────────────────────┘
                     │  HTTP / REST
┌────────────────────▼─────────────────────────────┐
│           Backend — FastAPI (Python)             │
│  ┌─────────────────────────────────────────────┐ │
│  │         /api/v1/analyze/url                │ │
│  │         /api/v1/analyze/file               │ │
│  │         /api/v1/reports                    │ │
│  └──────────┬──────────────────────┬──────────┘ │
│             │                      │             │
│  ┌──────────▼──────────┐ ┌────────▼───────────┐ │
│  │ URL Analysis Engine │ │ Binary Analysis    │ │
│  │  - Local Heuristics │ │  Engine            │ │
│  │  - External APIs    │ │  - pefile          │ │
│  │  - Scoring          │ │  - Entropy/Strings │ │
│  └─────────────────────┘ └────────────────────┘ │
│             │                                    │
│  ┌──────────▼──────────┐ ┌────────────────────┐ │
│  │  PostgreSQL (Async) │ │  Redis             │ │
│  │  (Analysis Reports) │ │  (Rate Limiting)   │ │
│  └─────────────────────┘ └────────────────────┘ │
│                                                  │
│  ┌──────────────────────────────────────────────┐ │
│  │  Celery Workers (Async heavy tasks)         │ │
│  └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────┐
│     Prometheus + Grafana (Production Metrics)    │
└──────────────────────────────────────────────────┘
```

> **Graceful degradation:** The backend handles missing databases, Redis, and API keys gracefully. When PostgreSQL is unavailable, an in-memory mock DB is used. When Redis is absent, rate limiting is disabled. When no API keys are set, local heuristics carry 100% of the scoring weight.

---

## 🛠 Tech Stack

### Backend
| Component | Technology |
|---|---|
| Framework | [FastAPI](https://fastapi.tiangolo.com/) 0.104 |
| Runtime | Python 3.10 |
| Database ORM | SQLAlchemy 2.0 (async) |
| Database | PostgreSQL 15 |
| Cache / Rate Limiting | Redis 7 + `fastapi-limiter` |
| Task Queue | Celery |
| HTTP Client | `aiohttp` (async) |
| PE Analysis | `pefile` |
| URL Parsing | `tldextract` |
| WHOIS | `python-whois` |
| Metrics | Prometheus + `prometheus-fastapi-instrumentator` |

### Frontend
| Component | Technology |
|---|---|
| Framework | Next.js |
| UI Library | React |
| Styling | TailwindCSS (Neo Brutalist theme) |
| Charts | Chart.js |
| Fonts | IBM Plex Mono, Space Mono |

### Infrastructure
| Component | Technology |
|---|---|
| Containerization | Docker + Docker Compose |
| Monitoring | Prometheus + Grafana |
| Production Server | Uvicorn (4 workers) |

---

## 📡 API Reference

Base URL: `http://localhost:8000/api/v1`

### `POST /analyze/url`

Analyze a URL for phishing indicators.

**Request body:**
```json
{
  "url": "http://login-secure-verify.xn--paypa1.com/update"
}
```

**Response:**
```json
{
  "id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "risk_score": 95.0,
  "risk_level": "CRITICAL",
  "verdict": "PHISHING / MALWARE",
  "sources": ["VT:72/90", "Google:Blocked", "Local:85.0/100"],
  "indicators": [
    "Punycode (Homograph attack)",
    "Suspicious keywords: login, verify, update",
    "Possible typosquatting of paypal"
  ],
  "mitigations": ["BLOCK IMMEDIATELY", "Report to PhishTank", "Isolate endpoint if clicked"],
  "evidence": {
    "local_data": { ... },
    "api_results": [ ... ],
    "scoring_components": { ... }
  }
}
```

---

### `POST /analyze/file`

Upload a binary file for static PE analysis. (Max: **25 MB**)

**Request:** `multipart/form-data` with a `file` field.

```bash
curl -X POST http://localhost:8000/api/v1/analyze/file \
  -F "file=@suspicious.exe"
```

**Response:**
```json
{
  "id": "a1b2c3d4-...",
  "risk_score": 75.0,
  "risk_level": "HIGH",
  "verdict": "HIGHLY SUSPICIOUS",
  "sources": ["Local:75.0/100", "⚠️ External APIs: Not Configured (local-only mode)"],
  "indicators": [
    "High Shannon Entropy (7.63) - packed/encrypted",
    "Section .text is highly obfuscated (7.81)",
    "No exports (common in droppers/malware)",
    "Embedded IP addresses found (3)"
  ],
  "mitigations": ["BLOCK", "Manual SOC Review"],
  "evidence": {
    "local_data": {
      "suspicious_imports": ["kernel32.dll!virtualAllocEx"],
      "embedded_ips": ["192.168.1.100"],
      "embedded_urls": ["http://evil.c2server.net/beacon"]
    }
  }
}
```

---

### `GET /reports`

Retrieve the last 50 analysis reports.

```bash
curl http://localhost:8000/api/v1/reports
```

---

### `GET /`

Health check endpoint.

```json
{ "status": "ok", "version": "v2.ultimate" }
```

> **Rate limit:** 10 requests per 60 seconds per client (when Redis is configured).

---

## 🧮 Scoring Algorithm

PhishBIN Guard uses an **adaptive weighted scoring** system:

### When external APIs are configured:
```
Final Score = (0.4 × Local Heuristics)
            + (0.3 × API Consensus)    ← average of top 2 API scores
            + (0.2 × Reputation Score)
            + (0.1 × Behavior Score)
```

### When running in offline / demo mode (no API keys):
```
Final Score = Local Heuristics (100% weight)
```

This ensures the platform is fully functional without any API keys — useful for demos, offline environments, and academic use.

### Risk Thresholds

| Score | Risk Level | Verdict | Mitigations |
|---|---|---|---|
| ≥ 80 | 🔴 CRITICAL | PHISHING / MALWARE | Block immediately, report, isolate endpoint |
| ≥ 55 | 🟠 HIGH | HIGHLY SUSPICIOUS | Block, escalate to SOC |
| ≥ 30 | 🟡 MEDIUM | SUSPICIOUS | Warn user, monitor |
| < 30 | 🟢 LOW | CLEAN | Allow |

---

## 📁 Project Structure

```
PishBIN-Guard/
│
├── backend/
│   ├── main.py                   # FastAPI app entry point
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── init_db.py                # DB initializer script
│   │
│   ├── api/
│   │   └── routes/
│   │       └── analyzer.py       # URL & binary analysis endpoints
│   │
│   ├── services/
│   │   ├── local_url.py          # Local URL heuristics engine
│   │   ├── local_binary.py       # Local PE static analysis engine
│   │   ├── external_apis.py      # VirusTotal, GSB, AbuseIPDB integrations
│   │   ├── scoring.py            # Adaptive scoring algorithm
│   │   ├── url_service.py        # Full URL analysis service (alt heuristics)
│   │   ├── binary_service.py     # Full binary analysis service
│   │   └── file_tasks.py         # File upload handling utilities
│   │
│   ├── core/
│   │   ├── database.py           # Async SQLAlchemy engine & session
│   │   └── tasks.py              # Celery task definitions
│   │
│   └── models/
│       └── report.py             # AnalysisReport SQLAlchemy model
│
├── frontend/                     # Next.js / React application
│
├── docker-compose.yml            # Development stack (MongoDB)
├── docker-compose.prod.yml       # Production stack (PostgreSQL, Redis, Celery, Monitoring)
│
├── test_ultimate.py              # Async API integration tests
├── test_services.py              # Service-level tests
├── verify_api.py                 # Quick verification script
├── demo_malware.bin              # Sample binary for testing
│
├── PRD.md                        # Product Requirements Document
└── rules.md                      # Development rules & constraints
```

---

## 🚀 Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)
- OR: Python 3.10+, Node.js 18+, PostgreSQL 15, Redis 7

---

### Development (Docker)

The development stack spins up the backend, frontend, and a MongoDB instance:

```bash
git clone https://github.com/hx010207/PishBIN-Gaurd.git
cd PishBIN-Gaurd
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| MongoDB | mongodb://localhost:27017 |

---

### Production (Docker)

The production stack adds PostgreSQL, Redis, Celery workers, Prometheus, and Grafana:

```bash
# 1. Create your environment file
cp .env.example .env
# Edit .env and fill in your API keys and secrets

# 2. Launch production stack
docker compose -f docker-compose.prod.yml up --build -d
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3001 (admin / admin) |

---

### Manual Setup

#### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql+asyncpg://postgres:password@localhost:5432/phishbin"
export REDIS_URL="redis://localhost:6379/1"

# Initialize database
python init_db.py

# Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 🔑 Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# ─── Database ────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://postgres:phishbin_secure@postgres:5432/phishbin

# ─── Redis ───────────────────────────────────────────────────
REDIS_URL=redis://redis:6379/1

# ─── Frontend ────────────────────────────────────────────────
NEXT_PUBLIC_API_URL=http://localhost:8000

# ─── Threat Intelligence API Keys (all optional) ─────────────
VT_API_KEY=           # VirusTotal API key
GSB_API_KEY=          # Google Safe Browsing API key
ABUSEIPDB_API_KEY=    # AbuseIPDB API key
URLSCAN_API_KEY=      # URLScan.io API key
PHISHTANK_API_KEY=    # PhishTank API key (optional, often keyless)
OTX_API_KEY=          # AlienVault OTX API key
HYBRID_ANALYSIS_API_KEY=  # Hybrid Analysis API key
```

> **No API keys? No problem.** The platform runs fully in local-only mode — external API checks are skipped and the scoring engine falls back to 100% local heuristics. This is ideal for offline use and demos.

---

## 🌐 External API Integrations

| Service | Purpose | Free Tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/) | URL & file scan consensus | 4 req/min, 500/day |
| [Google Safe Browsing](https://developers.google.com/safe-browsing) | Malware/phishing URL detection | Free (via GCP key) |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation scoring | 1000/day |
| [URLScan.io](https://urlscan.io/) | URL screenshot & behavior analysis | Free tier available |
| [PhishTank](https://www.phishtank.com/) | Community phishing database | Free |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat pulse indicators | Free |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Sandbox behavior reports | Free (limited) |

All API calls are made **asynchronously** using `asyncio.gather` to stay within the 3-second response target.

---

## 📐 Development Rules

All contributions must adhere to these constraints (see [`rules.md`](rules.md)):

1. The project must be fully open-source
2. Backend must use Python FastAPI
3. Frontend must use Next.js and React
4. UI theme must follow Neo Brutalist design (black background, white text, hard borders, monospace fonts)
5. All analysis must be **static** — binaries are never executed
6. File uploads must be sandboxed
7. Maximum file upload size: **25 MB**
8. All outputs must include explanations for educational purposes
9. All APIs must return **structured JSON**
10. Use modular architecture

---

## 🧪 Testing

### Quick API verification (requires running backend):

```bash
python verify_api.py
```

### Async integration tests:

```bash
# Requires: pip install aiohttp
python test_ultimate.py
```

### Service-level tests:

```bash
python test_services.py
```

### Test with the included demo malware sample:

```bash
curl -X POST http://localhost:8000/api/v1/analyze/file \
  -F "file=@demo_malware.bin"
```

### Benchmark URLs:

| URL | Expected Result |
|---|---|
| `http://login-secure-verify.xn--test.com/update` | **CRITICAL** (multiple indicators fire) |
| `https://google.com` | **LOW / CLEAN** |

---

## 📈 Monitoring

The production stack ships with **Prometheus** metrics (via `prometheus-fastapi-instrumentator`) and a **Grafana** dashboard.

- **Prometheus** scrapes metrics from the FastAPI backend at `/metrics`
- **Grafana** connects to Prometheus at `http://prometheus:9090`
- Default Grafana credentials: `admin` / `admin`

Custom monitoring config can be placed in `monitoring/prometheus.yml`.

---

## 🎨 UI Design

PhishBIN Guard uses a **Neo Brutalist** visual design language:

- ⬛ Black background
- ⬜ White text
- 🔳 Hard, solid borders — no shadows, no gradients
- 📦 Blocky, grid-based layout
- 🔤 Monospace typography: **IBM Plex Mono** + **Space Mono**

---

<div align="center">

© 2026 PhishBIN Guard — Open Source Cyber Threat Analysis Platform

*Built for education. Deployed for security.*

</div>
