# AI-Assisted Nmap Scanner

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Nmap](https://img.shields.io/badge/Nmap-7.x%2B-green)](https://nmap.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

An intelligent network scanning tool that combines the power of Nmap with AI-driven analysis for automated security assessments, risk scoring, and actionable recommendations.

## Features

- **AI-Powered Analysis** — Rule-based and OpenAI-powered scan interpretation
- **Web Dashboard** — Real-time scan monitoring with WebSocket updates
- **CLI Interface** — Full-featured command-line tool
- **REST API** — Complete API for automation and integration
- **Role-Based Access Control** — Admin, Operator, and Viewer roles
- **Export Formats** — JSON, CSV, XML, and plain text reports
- **Scan Comparison** — Diff between scans to identify new/removed hosts and ports
- **Scheduling** — Time-based and recurring scan jobs
- **Docker Support** — Containerized deployment

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Web UI (Frontend)                     │
└──────────────────────────┬──────────────────────────────────┘
                            │ HTTP/WS
┌──────────────────────────▼──────────────────────────────────┐
│                     FastAPI Backend                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │
│  │ Auth/RBAC│ │ REST API │ │ Scheduler│ │  AI Service    │   │
│  └─────┬────┘ └────┬─────┘ └────┬─────┘ └───────┬───────┘   │
│        │           │            │                │           │
│  ┌─────▼───────────▼────────────▼────────────────▼───────┐   │
│  │                  Engine Layer                           │   │
│  │  Target Parser  |  Nmap Scanner  |  Result Parser     │   │
│  └────────────────────────┬──────────────────────────────┘   │
│                           │                                   │
│  ┌────────────────────────▼──────────────────────────────┐   │
│  │                   Database (SQLite/Postgres)            │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                     ┌──────▼──────┐
                     │    Nmap     │
                     └─────────────┘
```

## Quick Start

```bash
# Prerequisites: Python 3.10+, nmap installed

git clone <repo-url>
cd ai-based-nmap-tool

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env if needed

uvicorn backend.main:app --reload --port 8000
```

Open http://localhost:8000 in your browser.

Default login: `admin` / `admin`

## Prerequisites

- **Python 3.10+**
- **Nmap** — Install via your package manager:
  - macOS: `brew install nmap`
  - Ubuntu/Debian: `sudo apt-get install nmap`
  - CentOS/RHEL: `sudo yum install nmap`
  - Windows: Download from https://nmap.org/download.html

## Installation

```bash
git clone <repo-url>
cd ai-based-nmap-tool
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Configuration is managed through environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `development-secret-key-...` | JWT signing key (change in production) |
| `DATABASE_URL` | `sqlite:///./data/scanner.db` | Database connection string |
| `AI_PROVIDER` | `rule` | AI backend (`rule` or `openai`) |
| `OPENAI_API_KEY` | | OpenAI API key (for AI_PROVIDER=openai) |
| `AI_MODEL` | `gpt-4o-mini` | OpenAI model name |
| `SCAN_TIMEOUT` | `600` | Nmap scan timeout in seconds |
| `MAX_CONCURRENT_SCANS` | `3` | Maximum parallel scans |
| `RATE_LIMIT_PER_MINUTE` | `100` | API rate limit per user |
| `LOG_LEVEL` | `INFO` | Logging level |

## Usage

### CLI

```bash
# Validate a target
python -m backend.cli.main target validate 192.168.1.1
python -m backend.cli.main target validate 10.0.0.0/24

# Run a scan
python -m backend.cli.main scan run 192.168.1.1 --ports "22,80,443"

# List available scan profiles
python -m backend.cli.main scan profiles

# View scan results
python -m backend.cli.main scan results <scan-id>
```

### API Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `GET` | `/api/v1/health` | Health check | No |
| `POST` | `/api/v1/auth/login` | Login | No |
| `POST` | `/api/v1/auth/register` | Register user | Admin |
| `GET` | `/api/v1/auth/me` | Current user info | Yes |
| `POST` | `/api/v1/auth/refresh` | Refresh token | Yes |
| `GET` | `/api/v1/targets` | List targets | Yes |
| `POST` | `/api/v1/targets` | Create target | Yes |
| `DELETE` | `/api/v1/targets/{id}` | Delete target | Yes |
| `GET` | `/api/v1/targets/groups` | List target groups | Yes |
| `POST` | `/api/v1/targets/groups` | Create group | Yes |
| `POST` | `/api/v1/scans` | Launch scan | Yes |
| `GET` | `/api/v1/scans` | List scans | Yes |
| `GET` | `/api/v1/scans/{id}` | Get scan status | Yes |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel scan | Yes |
| `GET` | `/api/v1/scans/{id}/results` | Get scan results | Yes |
| `GET` | `/api/v1/scans/{id}/export/json` | Export JSON | Yes |
| `GET` | `/api/v1/scans/{id}/export/csv` | Export CSV | Yes |
| `POST` | `/api/v1/scans/compare` | Compare scans | Yes |
| `POST` | `/api/v1/scans/{id}/ai/query` | AI question | Yes |
| `GET` | `/api/v1/scans/profiles` | List profiles | Yes |

### API Examples

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Create a target (use token from login)
curl -X POST http://localhost:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "web-server", "target_value": "192.168.1.100", "target_type": "ip"}'

# Launch a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "quick-scan", "target_id": 1, "profile_id": 1}'

# Ask AI about results
curl -X POST http://localhost:8000/api/v1/scans/1/ai/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query": "what ports are open", "scan_job_id": 1}'
```

### Web UI

Access the web interface at http://localhost:8000. The UI provides:

- **Dashboard** — Scan history and statistics
- **Target Management** — Add, edit, and group targets
- **Profile-based Scan Configuration** — Quick templates for common scans
- **Real-time Scan Progress** — WebSocket-powered live updates
- **AI Insights** — Natural language questions about scan results
- **Export** — Download results in JSON, CSV, and report formats

## AI Features

### Rule-Based Provider (Default)

The built-in rule-based engine provides:

- **Summarization** — Concise overview of scan results
- **Risk Scoring** — Port-based risk assessment (e.g., Telnet=critical, HTTP=medium)
- **Comparison** — Diff between two scans (new/removed hosts and ports)
- **Recommendations** — Actionable security suggestions (e.g., "Disable Telnet", "Enable HTTPS")
- **Q&A** — Natural language queries:
  - "What ports are open?"
  - "How many hosts were found?"
  - "List the services"
  - "Are there any risks?"

### OpenAI Provider

Set `AI_PROVIDER=openai` and provide `OPENAI_API_KEY` to use GPT models for more sophisticated analysis. The LLM can interpret complex questions and provide contextual security insights.

## Safety and Authorization

- **Role-Based Access Control**: Admin, Operator, Viewer roles
- **Rate Limiting**: Configurable per-user rate limit
- **Audit Logging**: All actions are logged for compliance
- **Input Validation**: Targets are validated before scanning
- **CIDR Restrictions**: Maximum prefix /24 (256 hosts) to prevent network abuse
- **Timeout Controls**: Scan timeout prevents runaway scans
- **Concurrency Limits**: Configurable maximum concurrent scans

## Testing

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=backend tests/

# Run specific test file
pytest tests/test_engine.py -v

# Run specific test
pytest tests/test_engine.py::TestTargetParser::test_target_parse_ip -v
```

Test pass status is not a reliable indicator of functionality.

## Docker Deployment

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down

# Rebuild after changes
docker compose up -d --build
```

The Docker image includes:

- Python 3.10 runtime
- Nmap installed in the container
- Multi-stage build for smaller image size
- Persistent data volume at `./data`

## Troubleshooting

### Common Issues

| Problem | Solution |
|---|---|
| `nmap not found` | Install nmap: `brew install nmap` or `apt-get install nmap` |
| Port 8000 already in use | Set `PORT=8001` in `.env` or use `--port 8001` |
| `401 Unauthorized` | Ensure you include `Authorization: Bearer <token>` header |
| Scan times out | Increase `SCAN_TIMEOUT` in `.env` |
| AI returns generic answers | Switch to `AI_PROVIDER=openai` with a valid API key |
| Rate limit errors | Increase `RATE_LIMIT_PER_MINUTE` in `.env` |
| Dashboard shows no data | Ensure scans have completed and results exist |

### Debug Mode

```bash
LOG_LEVEL=DEBUG uvicorn backend.main:app --reload --port 8000
```

## Project Structure

```
ai-based-nmap-tool/
├── backend/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entry point
│   ├── config.py            # Configuration management
│   ├── database.py          # SQLAlchemy setup
│   ├── api/
│   │   ├── __init__.py
│   │   └── auth.py          # Authentication endpoints
│   ├── engine/
│   │   ├── target_parser.py # Target input parsing & validation
│   │   ├── scanner.py       # Nmap scanner wrapper
│   │   ├── parser.py        # Scan result normalization
│   │   └── discovery.py     # Host discovery (ping sweep)
│   ├── models/              # SQLAlchemy ORM models
│   ├── schemas/             # Pydantic request/response schemas
│   ├── auth/
│   │   ├── jwt.py           # JWT token handling
│   │   ├── rbac.py          # Role-based access control
│   │   └── audit.py         # Audit event logging
│   ├── ai_service/          # AI analysis logic
│   ├── cli/                 # Click command-line interface
│   ├── exporters/
│   │   ├── base.py          # Abstract exporter
│   │   ├── csv_exporter.py  # CSV export
│   │   ├── json_exporter.py # JSON export
│   │   ├── xml_exporter.py  # XML export
│   │   └── report_exporter.py # Plain text report
│   └── scheduler/
│       ├── job_queue.py     # Thread-safe scan job queue
│       └── worker.py        # Background scan worker
├── frontend/
│   └── static/              # Web UI assets
├── tests/                   # Test suite
├── docs/                    # Documentation
│   └── USER_GUIDE.md        # Comprehensive user guide
├── data/                    # Runtime data (SQLite DB)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests before submitting
pytest --cov=backend tests/
```

### Code Style

- Follow PEP 8
- Use type hints
- Write tests for new functionality
- Update documentation as needed

