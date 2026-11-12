# AI ThreatModel Studio

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%20%7C%203.13-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.129.0-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com)
[![Methodologies](https://img.shields.io/badge/Methodologies-STRIDE%20%7C%20PASTA%20%7C%20MAESTRO%20%7C%20TARA-purple.svg)](#threat-modeling-methodologies)

**AI ThreatModel Studio** is an enterprise-grade, web-based, LLM-powered cybersecurity threat modeling platform. It enables security architects, engineers, and developers to assess software architectures, enterprise networks, agentic AI pipelines, and connected automotive systems across four established methodologies: **STRIDE**, **PASTA**, **MAESTRO**, and **ISO/SAE 21434 TARA**.

---

## 🌟 Core Features

- **Multi-Methodology Engine**:
  - **STRIDE**: Six-category technical threat analysis (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
  - **PASTA**: Seven-stage risk-centric threat analysis correlating threat actors, attack trees, and quantifiable business impact.
  - **MAESTRO**: Dedicated 7-layer framework for Agentic AI (Foundation Models, Autonomous Agents, Tools, Context/Memory, Transport, Swarms, Human-in-the-Loop).
  - **ISO/SAE 21434 TARA**: Automotive cybersecurity engineering evaluating Item boundaries, SFOP damage scenarios, and 5-factor Attack Feasibility ratings.
- **LLM Abstraction & Prompt Guard**:
  - Connect to cloud providers (**OpenAI API**) or run air-gapped with locally hosted models (**Ollama**).
  - Built-in **Deterministic High-Fidelity Simulation Engine** for offline development and instant CI/CD threat evaluation.
  - Untrusted architecture document sanitization to neutralize prompt injection attacks.
- **Deterministic Risk Engine**:
  - $L \times I$ inherent risk scoring (1–25) and residual risk calculation.
  - Automotive TARA Feasibility vs. SFOP Impact matrix mapping to Cybersecurity Risk Values (1–5).
- **Interactive Threat Register & Review Workflow**:
  - Filter by category, severity, status, or component.
  - Human review gates: Approve, Reject, Edit, Assign Owners, and Add Custom Countermeasures.
- **Multi-Format Audit Dossier Exports**:
  - Export complete threat models in **Printable HTML/PDF**, **Microsoft Excel (.xlsx)**, **Microsoft Word (.docx)**, and **Structured JSON**.
- **Docker-First Containerization**:
  - Full Docker Compose topology (Nginx reverse proxy, React frontend, FastAPI backend, PostgreSQL, Redis, Celery worker).

---

## 🏗️ System Architecture

The platform cleanly decouples the **Methodology Engine** from the **LLM Orchestration Layer**, ensuring models can be swapped without altering risk formulas or regulatory schemas.

```
                            +-----------------------------+
                            |   Security Architect / Eng  |
                            +--------------+--------------+
                                           |
                                           v
                            +-----------------------------+
                            |     Nginx Reverse Proxy     |
                            +--------------+--------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
    +-----------------------------+                 +-----------------------------+
    |   Frontend Web UI (React)   |                 |    Backend API (FastAPI)    |
    +-----------------------------+                 +--------------+--------------+
                                                                   |
          +-----------------------+--------------------------------+-----------------------+
          |                       |                                |                       |
          v                       v                                v                       v
+-------------------+   +--------------------+           +-------------------+   +--------------------+
|  Project Service  |   | Methodology Engine |           |  Document Parser  |   |  Risk Eval Engine  |
| (Postgres/SQLite) |   | (STRIDE/PASTA/AI)  |           | (PyMuPDF/DOCX/XLS)|   | (L x I, TARA SFOP) |
+-------------------+   +---------+----------+           +-------------------+   +--------------------+
                                  |
                                  v
                        +--------------------+
                        |  LLM Orchestration |
                        |   & Prompt Guard   |
                        +---------+----------+
                                  |
                  +---------------+---------------+
                  |                               |
                  v                               v
    +---------------------------+   +---------------------------+
    |  Cloud LLM (OpenAI API)   |   |   Local Inference (Ollama)|
    +---------------------------+   +---------------------------+
```

---

## 📊 Threat Modeling Methodologies

| Methodology | Application Behavior | Target Domain | Risk Scoring Model |
| :--- | :--- | :--- | :--- |
| **STRIDE** | Classify threats into 6 technical categories | Software, Web, Cloud & Embedded | Inherent Risk = $L \times I$ (1–25) |
| **PASTA** | 7-stage risk-centric threat simulation | Enterprise Applications & Portals | Exploitability $\times$ Business Impact |
| **MAESTRO** | 7-layer Agentic AI security analysis | Autonomous Agents, RAG & LLMs | AI Autonomy $\times$ Failure Severity |
| **ISO/SAE 21434 TARA** | Item boundary, SFOP impact, attack feasibility | Automotive ECUs & Connected Vehicles | Feasibility $\times$ SFOP Impact (1–5) |

---

## 🚀 Quickstart

### Option 1: Run with Docker Compose (Recommended)

1. **Clone and enter the directory**:
   ```bash
   cd Stride_pasta_meastro
   ```

2. **Configure environment variables (optional)**:
   ```bash
   cp .env.example .env
   # Add your OPENAI_API_KEY if using Cloud LLM; otherwise defaults to High-Fidelity Simulation
   ```

3. **Start all services**:
   ```bash
   docker compose up -d --build
   ```

4. **Access the application**:
   - Web UI Dashboard: **http://localhost**
   - Interactive OpenAPI Docs: **http://localhost/docs**
   - API Health Check: **http://localhost/health**

---

### Option 2: Run Standalone with Python (Zero-Docker Mode)

The backend features an automatic SQLite fallback and built-in static UI serving for instant local development:

1. **Install dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. **Run the backend**:
   ```bash
   cd backend
   python main.py
   ```

3. **Open the platform**:
   - Open your browser to **http://localhost:8000**
   - The interactive dashboard, 5-step wizard, threat register, and report exporters are ready to use immediately!

---

### Option 3: Enable Local LLM with Ollama

To run completely private, air-gapped threat modeling with Ollama:

```bash
docker compose --profile local-ai up -d
```
Then pull your model of choice:
```bash
docker exec -it threatmodel_ollama ollama pull llama3.1
```

---

## 🧪 Automated Test Suite

Run the full end-to-end API test suite covering all four methodology engines, risk calculation, threat editing, and report generation:

```bash
python -m pytest backend/tests/test_api.py -v
```

---

## 📁 Repository Structure

```
Stride_pasta_meastro/
├── docker-compose.yml              # Multi-container orchestration (FastAPI, Nginx, Postgres, Redis)
├── .env.example                    # Environment variable configuration template
├── README.md                       # Platform documentation and architecture guide
├── nginx/
│   ├── nginx.conf                  # Nginx core configuration
│   └── default.conf                # API routing & reverse proxy
├── backend/
│   ├── Dockerfile                  # Production container definition
│   ├── requirements.txt            # Python dependencies
│   ├── main.py                     # FastAPI application entrypoint & table auto-seeder
│   ├── app/
│   │   ├── config.py               # Pydantic environment configuration
│   │   ├── database.py             # SQLAlchemy session & pooling
│   │   ├── models/                 # 16 Core Database Entities
│   │   ├── schemas/                # Pydantic Request/Response schemas
│   │   ├── methodologies/          # STRIDE, PASTA, MAESTRO, TARA Engines
│   │   ├── services/               # LLM Orchestrator, Doc Parser, Risk & Report Services
│   │   └── api/                    # REST API Endpoints (Auth, Projects, Threats, Reports)
│   ├── tests/
│   │   └── test_api.py             # Pytest automated test suite
│   └── static/
│       └── index.html              # High-performance, modern Web UI Dashboard
└── frontend/
    ├── Dockerfile                  # Frontend container
    └── package.json                # React 18, TypeScript dependencies
```

---

## 🔒 Security & AI Safeguards

1. **Untrusted Architecture Context**: Uploaded architecture documents are sandboxed within `<untrusted_architecture_context>` blocks to guard against indirect prompt injection.
2. **Deterministic Risk Calculation**: AI models generate threat hypotheses, but likelihood, impact, inherent risk, and TARA feasibility values are verified by deterministic code.
3. **Human-in-the-Loop (HITL)**: All AI-generated threats are flagged as `draft` and require explicit human security engineer review and approval.
4. **Auditability**: Every AI run records its provider, model name, prompt tokens, completion tokens, execution latency, and prompt template version.

