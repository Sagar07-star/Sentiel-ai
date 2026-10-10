#  Sentinel AI

**Email threat detection and digital forensics platform.**

Sentinel AI ingests a suspicious email (`.eml`), preserves it as forensic evidence with a SHA-256 hash and a chain-of-custody trail, runs a multi-layer analysis (authentication, identity, URLs, attachments, behavior, local ML), and produces an **explainable risk verdict** with a timeline, an evidence graph and counterfactual reasoning.

> Sentinel AI is an **investigation aid**, not a guarantee of maliciousness. Scores and verdicts should support, not replace, analyst judgment.

---

##  Features

### Forensic evidence handling
- **Evidence acquisition** with size limits and filename validation
- **SHA-256 hashing** of every uploaded email
- **Append-only chain of custody** (acquired → hash verified → stored → analysis started → completed/failed → report generated)
- **Structured audit logging** (via `structlog`) that never records email bodies, attachment contents or secrets
- Raw email is **not persisted by default** (`PERSIST_RAW_EMAIL=false`)

### Multi-layer threat analysis
| Layer | What it checks |
|-------|----------------|
| **Authentication** | SPF, DKIM and DMARC results from `Authentication-Results` headers |
| **Identity** | Sender vs. Reply-To vs. Return-Path vs. SPF/DKIM/DMARC domain mismatches |
| **Headers & MIME** | Header analysis, `Received` chain, MIME structure forensics |
| **URLs** | IP-based URLs, shorteners, non-HTTPS, long URLs, deep subdomains, suspicious keywords |
| **Attachments** | Executable/script extensions, macro-capable documents, double extensions, content-type mismatch, embedded binary objects |
| **Behavior** | Credential requests, payment requests, threat language, urgency |
| **Infrastructure** | DNS intelligence for domains and IPs (optional external providers) |
| **Local ML** | TF-IDF + Logistic Regression phishing classifier combined with structural URL features, with no external network dependency |

### Explainable output
- **Risk score (0–100)** with weighted, sorted risk factors
- **Verdict:** `minimal` · `low` · `medium` · `high` · `critical`
- **Confidence** estimate
- **Correlated findings** linking multiple indicators into higher-level threats
- **Reconstructed timeline** of events from the email
- **Evidence graph** (email → sender / domains / URLs / IPs / findings)
- **Counterfactual analysis** ("what would the score be if this indicator were absent?")
- **Forensic report** with executive summary and evidence-integrity statement

### Design principles
- Weak signals (long URL, urgency, etc.) **never** create a threat on their own
- ML evidence is **bounded**; it supports but never solely decides a verdict
- Analysis keeps working if external providers fail (bounded timeouts, retries and caching)
- External intelligence (VirusTotal, urlscan.io) is **opt-in**

---

##  Architecture

```
          ┌────────────────────────────┐
          │  Web Dashboard (web/)      │  upload .eml → results, graph, timeline
          └─────────────┬──────────────┘
                        │ HTTP
          ┌─────────────▼──────────────┐
          │  FastAPI  (main.py)        │  /health  /api  /api/investigations/*
          └─────────────┬──────────────┘
                        │
   ┌────────────────────▼─────────────────────┐
   │ Ingestion → Evidence store → Custody log │
   └────────────────────┬─────────────────────┘
                        │
   ┌────────────────────▼─────────────────────────────────────┐
   │ Analysis Pipeline                                        │
   │ parse → headers → auth → identity → indicators → URLs    │
   │ → attachments → behavior → ML → infrastructure           │
   │ → correlation → attack graph → risk → counterfactual     │
   │ → timeline → forensic report                             │
   └────────────────────┬─────────────────────────────────────┘
                        │
          ┌─────────────▼──────────────┐
          │ SQLAlchemy + Alembic       │  SQLite (dev) / PostgreSQL (prod)
          └────────────────────────────┘
```

---

##  Project Structure

```
Sentiel-ai/
├── main.py                    # FastAPI entry point + static dashboard routes
├── app/
│   ├── config.py              # Environment-driven settings (pydantic-settings)
│   ├── api/                   # health.py, investigations.py
│   ├── parsers/               # email, header, MIME and attachment forensics
│   ├── detectors/             # authentication, identity, url_risk, behavior, ml_phishing
│   ├── extraction/            # indicator extraction (URLs, domains, IPs)
│   ├── intelligence/          # dns, ip, infrastructure
│   ├── services/              # pipeline, risk engine, correlation, timeline,
│   │                          # attack graph, counterfactual, reports,
│   │                          # chain of custody, evidence store, DB, models
│   └── security/              # audit logging, evidence hashing, request IDs
├── providers/                 # external intelligence provider package
├── web/                       # index.html, app.js, style.css dashboard
├── alembic/                   # database migrations
├── tests/                     # pytest suite
├── Dockerfile
├── docker-compose.yml         # app + PostgreSQL 17
└── pyproject.toml
```

---

##  Prerequisites

- **Python 3.14** (`requires-python = ">=3.14,<3.15"`)
- Docker & Docker Compose *(optional, for containerized run)*
- PostgreSQL 17 *(optional, SQLite is used by default for local development)*

---

##  Getting Started (Local)

```bash
# 1. Clone
git clone https://github.com/Sagar07-star/Sentiel-ai.git
cd Sentiel-ai

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install (the ML extra is required: the pipeline imports scikit-learn)
pip install -e ".[ml,dev]"

# 4. Configure
cp .env.example .env

# 5. Create the database schema
mkdir -p runtime
alembic upgrade head

# 6. Run
uvicorn main:app --reload
```

Open:
- Dashboard: <http://127.0.0.1:8000>
- Interactive API docs: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

---

##  Docker

```bash
docker compose up --build
```

This starts the app on port `8000` plus a PostgreSQL 17 container. The compose file hardens both containers with `no-new-privileges` and `cap_drop: ALL`.

> **Before using in any real environment**, change the default PostgreSQL credentials (`sentinel` / `sentinel`) in `docker-compose.yml`.

---

##  Configuration

Settings are read from environment variables or a `.env` file (see `.env.example`).

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./runtime/sentinel.db` | SQLAlchemy database URL |
| `ENVIRONMENT` | `development` | Runtime environment name |
| `LOG_LEVEL` | `INFO` | Logging level |
| `MAX_EMAIL_SIZE_MB` | `25` | Maximum uploaded email size |
| `MAX_ATTACHMENT_SIZE_MB` | `15` | Maximum single attachment size |
| `MAX_ATTACHMENT_COUNT` | `25` | Maximum attachments per email |
| `ANALYSIS_TIMEOUT_SECONDS` | `30` | Overall analysis timeout |
| `PROVIDER_TIMEOUT_SECONDS` | `4` | External provider timeout |
| `DNS_TIMEOUT_SECONDS` | `3` | DNS lookup timeout |
| `MAX_PROVIDER_RETRIES` | `1` | Provider retry count |
| `ENABLE_DNS_INTELLIGENCE` | `true` | DNS-based infrastructure intelligence |
| `ENABLE_EXTERNAL_INTELLIGENCE` | `false` | Master switch for external providers |
| `ENABLE_VIRUSTOTAL` / `VIRUSTOTAL_API_KEY` | `false` / empty | VirusTotal lookups |
| `ENABLE_URLSCAN` / `URLSCAN_API_KEY` | `false` / empty | urlscan.io lookups |
| `ENABLE_GEOIP` | `false` | IP geolocation |
| `INTELLIGENCE_CACHE_TTL_SECONDS` | `3600` | Provider result cache TTL |
| `PRESERVE_EVIDENCE_HASH` | `true` | Hash all acquired evidence |
| `HASH_ALGORITHM` | `sha256` | Evidence hash algorithm |
| `PERSIST_RAW_EMAIL` | `false` | Store the raw email bytes |
| `AUDIT_LOG_ENABLED` | `true` | Structured audit logging |
| `CORS_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | Allowed CORS origins |

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Service health and version |
| `GET` | `/api` | API status |
| `POST` | `/api/investigations/analyze` | Upload an email (multipart `file`) and run a full investigation |
| `GET` | `/api/investigations` | List investigations, newest first |
| `GET` | `/api/investigations/{investigation_id}` | Full persisted investigation, analysis, report and custody trail |
| `GET` | `/api/investigations/{investigation_id}/custody` | Chain-of-custody history |

### Example

```bash
curl -X POST http://127.0.0.1:8000/api/investigations/analyze \
  -F "file=@suspicious.eml"
```

Abridged response (`201 Created`):

```json
{
  "investigation_id": "...",
  "evidence_id": "...",
  "filename": "suspicious.eml",
  "sha256": "9f86d081...",
  "status": "completed",
  "verdict": "high",
  "risk_score": 72.0,
  "confidence": 0.85,
  "executive_summary": "...",
  "evidence_integrity": "...",
  "threat_findings": ["..."],
  "indicators": ["spf_fail", "reply_to_domain_mismatch"],
  "urls": ["..."],
  "domains": ["..."],
  "ip_addresses": ["..."],
  "timeline": [],
  "correlated_findings": [],
  "evidence_graph": [{ "nodes": [], "edges": [] }],
  "counterfactual_scenarios": [],
  "custody": []
}
```

Error responses: `400` (missing filename / empty file / ingestion failure), `413` (file exceeds size limit), `404` (unknown investigation), `500` (analysis failure).

---

##  Risk Scoring

| Score | Verdict |
|-------|---------|
| ≥ 80 | `critical` |
| ≥ 60 | `high` |
| ≥ 35 | `medium` |
| ≥ 15 | `low` |
| < 15, or no risk-bearing evidence | `minimal` |

Strong indicators carry heavy weights (e.g. `dmarc_fail` 22, `executable_or_script_extension` 30, `double_extension` 25). Contextual observations (`long_url`, `url_shortener`, `non_https`, and so on) never raise the score by themselves.

---

## 🧪Testing & Code Quality

```bash
pytest                       # run the test suite
pytest --cov=app             # with coverage
ruff check .                 # lint
mypy app                     # type checking
```

The suite covers authentication, identity, URL risk, attachments, MIME, behavior, ML, correlation, timeline, counterfactuals, the risk engine, the report generator, ingestion, the API and end-to-end flows.

---
---




## 👤 Author

**Sagar**, [@Sagar07-star](https://github.com/Sagar07-star)
