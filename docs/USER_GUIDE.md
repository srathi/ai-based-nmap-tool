# User Guide — AI-Assisted Nmap Scanner

This guide walks you through every feature of the AI-Assisted Nmap Scanner, from installation to advanced workflows.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Web UI Walkthrough](#web-ui-walkthrough)
3. [Command-Line Interface](#command-line-interface)
4. [API Quick Reference](#api-quick-reference)
5. [AI Analysis Features](#ai-analysis-features)
6. [Exporting Results](#exporting-results)
7. [Scheduling Scans](#scheduling-scans)
8. [Managing Targets](#managing-targets)
9. [Scan Profiles](#scan-profiles)
10. [Security Best Practices](#security-best-practices)
11. [FAQ](#faq)

---

## Getting Started

### 1. Install Prerequisites

```bash
# Python 3.10 or newer
python --version

# Nmap
# macOS:
brew install nmap

# Ubuntu/Debian:
sudo apt-get install nmap

# CentOS/RHEL:
sudo yum install nmap
```

### 2. Set Up the Project

```bash
git clone <repo-url>
cd ai-based-nmap-tool
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 3. Configure

Edit `.env` with your settings. The most important variables:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Change from the default for production |
| `AI_PROVIDER` | `rule` for built-in AI, `openai` for GPT-powered analysis |
| `OPENAI_API_KEY` | Required only if using OpenAI provider |
| `SCAN_TIMEOUT` | Maximum seconds a single scan can run |
| `RATE_LIMIT_PER_MINUTE` | API request limit per user per minute |

### 4. Start the Server

```bash
uvicorn backend.main:app --reload --port 8000
```

Open http://localhost:8000 in your browser.

### 5. Log In

The default accounts are:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | Administrator |

The first user with admin privileges is created automatically on first run.

---

## Web UI Walkthrough

### Dashboard

The dashboard is your landing page. It shows:

- **Scan Statistics** — Total scans run, successes, failures
- **Recent Scans** — Latest scan results at a glance
- **Target Overview** — Number of registered targets
- **Quick Actions** — Buttons to create a target, launch a scan, or ask the AI

### Target Management

**Add a Target:**

1. Navigate to **Targets** in the sidebar
2. Click **New Target**
3. Fill in the form:
   - **Name** — A human-readable identifier (e.g., "Web Server")
   - **Target Value** — IP address, hostname, or CIDR range (e.g., `192.168.1.100`, `10.0.0.0/24`)
   - **Type** — `ip`, `hostname`, `cidr`, or `range`
4. Click **Save**

> **Note:** CIDR ranges are limited to `/24` (maximum 256 hosts) to prevent accidental network abuse.

**Edit/Delete Targets:** Use the action buttons on each target row. Deleting a target does not delete associated scan results.

**Target Groups:** Organize targets into groups (e.g., "Production", "Staging", "Development") for easier batch scanning.

### Scan Configuration

**Using Profiles:**

The system provides pre-built scan profiles:

- **Quick Scan** — Common ports (22, 80, 443, 3306, 8080)
- **Full Scan** — All 65,535 TCP ports
- ** Stealth Scan** — SYN scan with evasion techniques (-sS)
- **UDP Scan** — Common UDP ports (53, 67, 68, 123, 161)
- **Custom** — Define your own port lists and scan options

**Launching a Scan:**

1. Go to **Scans** → **New Scan**
2. Select a target from the dropdown
3. Choose a scan profile
4. Optionally provide a name for the scan job
5. Click **Start Scan**

You can also override profile defaults in the "Advanced Options" section:
- Port list
- Scan timing (T0–T5)
- Service version detection (`-sV`)
- OS detection (`-O`)
- Script engine (`-sC`)

### Monitoring Scans

Once a scan is launched, the **Scan Progress** panel shows:

- Real-time status (Queued → Running → Completed / Failed)
- Elapsed time
- Hosts discovered
- Ports found
- Live log output via WebSocket

When the scan completes, results appear in your scan history.

### AI Insights

Each completed scan has an **AI** tab where you can ask natural-language questions:

- *"What ports are open?"*
- *"Are there any insecure services?"*
- *"What is the overall risk score?"*
- *"Compare this scan to the previous one"*
- *"What should I do about the open Telnet service?"*

The AI also provides:
- **Risk Score** — A numerical assessment of the scan's security posture
- **Recommendations** — Prioritized action items with severity ratings
- **Comparison** — Side-by-side diff of two scans showing new/removed hosts and ports

### Asking the AI Questions

The Q&A system understands these categories:

| Category | Example Queries |
|---|---|
| Ports | "What ports are open?", "Which ports are closed?" |
| Services | "List the services", "What service runs on port 80?" |
| Hosts | "How many hosts were found?", "Show me the hosts" |
| Risk | "What is the risk score?", "Are there critical services?" |
| Count | "How many open ports?", "How many high-risk services?" |
| Details | "Show me the details of host 192.168.1.1" |
| Summary | "Summarize the scan", "Give me an overview" |
| Compare | "Compare scan 5 and scan 10" |
| Recommendations | "What should I fix first?", "Recommendations" |

> **Important:** AI responses are advisory only. The AI does not invent findings — everything it reports is based on actual scan data.

### Exporting Results

From any scan's results page:

- **JSON** — Machine-readable full result set
- **CSV** — Spreadsheet-friendly flat format
- **Report** — Human-readable plain text summary
- **XML** — Structured data for integration

Click the export button on the scan results page to download.

---

## Command-Line Interface

### Target Commands

```bash
# Validate a single IP
python -m backend.cli.main target validate 192.168.1.1

# Validate a CIDR range
python -m backend.cli.main target validate 10.0.0.0/24

# Validate a hostname
python -m backend.cli.main target validate scanme.nmap.org
```

### Scan Commands

```bash
# Run a quick scan against an IP
python -m backend.cli.main scan run 192.168.1.1

# Scan specific ports
python -m backend.cli.main scan run 192.168.1.1 --ports "22,80,443,8080"

# Run a full scan with service detection
python -m backend.cli.main scan run 192.168.1.1 --profile full --service-detect

# List available profiles
python -m backend.cli.main scan profiles

# View results of a completed scan
python -m backend.cli.main scan results <scan-id>

# Cancel a running scan
python -m backend.cli.main scan cancel <scan-id>
```

### Scan Profiles

```bash
# List all profiles
python -m backend.cli.main scan profiles
```

Available profiles: `quick`, `full`, `stealth`, `udp`, `custom`

---

## API Quick Reference

### Authentication

All API requests (except `/health` and `/auth/login`) require a Bearer token obtained from the login endpoint.

```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Response includes a JWT token
# Use it in subsequent requests:
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/targets
```

### Targets

```bash
# List all targets
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/targets

# Create a target
curl -X POST http://localhost:8000/api/v1/targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "my-server", "target_value": "192.168.1.50", "target_type": "ip"}'

# Delete a target
curl -X DELETE http://localhost:8000/api/v1/targets/1 \
  -H "Authorization: Bearer <token>"
```

### Scans

```bash
# Launch a scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"name": "web-scan", "target_id": 1, "profile_id": 1}'

# Get scan results
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/scans/1/results

# Cancel a scan
curl -X POST http://localhost:8000/api/v1/scans/1/cancel \
  -H "Authorization: Bearer <token>"

# Compare two scans
curl -X POST http://localhost:8000/api/v1/scans/compare \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"scan_id_1": 1, "scan_id_2": 2}'
```

### AI Features

```bash
# Summarize scan results
curl -X POST http://localhost:8000/api/v1/scans/1/ai/summarize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"scan_job_id": 1}'

# Get risk score
curl -X POST http://localhost:8000/api/v1/scans/1/ai/risk-score \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"scan_job_id": 1}'

# Compare two scans
curl -X POST http://localhost:8000/api/v1/scans/1/ai/compare \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"scan_job_id": 1, "other_scan_job_id": 2}'

# Ask a natural language question
curl -X POST http://localhost:8000/api/v1/scans/1/ai/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query": "what ports are open", "scan_job_id": 1}'

# Get recommendations
curl -X POST http://localhost:8000/api/v1/scans/1/ai/recommend \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"scan_job_id": 1}'
```

### Export

```bash
# Export as JSON
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/scans/1/export/json \
  -o scan-1.json

# Export as CSV
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/scans/1/export/csv \
  -o scan-1.csv
```

---

## AI Analysis Features

### Rule-Based AI (Default)

The built-in AI engine analyzes scan results using rule-based logic. It categorizes findings into four risk levels:

| Risk Level | Condition | Example Ports |
|---|---|---|
| **Critical** | Telnet, SNMP, FTP with anonymous login, default credentials | 23, 161, 21 |
| **High** | Unencrypted protocols, known vulnerable services | 21 (FTP), 23 (Telnet) |
| **Medium** | HTTP without TLS, exposed management interfaces | 80, 8080, 443 (HTTP) |
| **Low** | Standard secure services, informational findings | 443 (HTTPS), 22 (SSH) |

The AI also generates natural-language recommendations such as:

- "Disable Telnet and use SSH instead"
- "Enable HTTPS on port 8080"
- "Restrict SNMP access to trusted hosts only"
- "Update service X — known vulnerability CVE-XXXX-XXXX"

### OpenAI-Powered AI

To use GPT-based analysis:

1. Set `AI_PROVIDER=openai` in `.env`
2. Add your `OPENAI_API_KEY`
3. Optionally set `AI_MODEL=gpt-4o-mini` (default) or another model

The OpenAI provider can handle more complex queries and provide contextual security analysis beyond simple pattern matching.

---

## Exporting Results

Scan results can be exported in multiple formats from both the Web UI and the API:

| Format | Use Case |
|---|---|
| JSON | Integration with other tools, CI/CD pipelines |
| CSV | Spreadsheet analysis, sharing with non-technical teams |
| XML | Compliance reporting, tool interoperability |
| Report | Human-readable summary for presentations |

From the Web UI, click the export button on any scan results page. From the API, use the export endpoints documented in the API Quick Reference.

---

## Managing Targets

### Target Types

| Type | Example | Description |
|---|---|---|
| IP | `192.168.1.1` | Single IPv4 address |
| Hostname | `scanme.nmap.org` | DNS name |
| CIDR | `10.0.0.0/24` | Network range (max /24) |
| Range | `192.168.1.1-100` | IP range |

### Validation

Always validate targets before scanning. Invalid targets (e.g., malformed IPs, unreachable hostnames) will cause scans to fail. Use the CLI validation command or the Web UI target form — both validate input automatically.

### Best Practices for Target Management

1. **Use descriptive names** — "Production Web Server" rather than "Target 1"
2. **Organize into groups** — Group targets by environment, purpose, or department
3. **Document ownership** — Add notes in the target description
4. **Review regularly** — Remove stale targets that are no longer in scope

---

## Scan Profiles

Scan profiles define the scan parameters. Each profile has a name, description, default ports, and recommended nmap flags.

| Profile | Ports | Flags | Best For |
|---|---|---|---|
| Quick | 22, 80, 443, 3306, 8080 | `-T4` | Fast checks on common services |
| Full | All 65535 TCP | `-T3 -sV` | Comprehensive security assessment |
| Stealth | All TCP | `-sS -T2` | Evasion-sensitive environments |
| UDP | 53, 67, 68, 123, 161 | `-sU` | UDP service discovery |
| Custom | User-defined | User-defined | Specialized requirements |

You can override any profile's ports and flags when launching a scan.

---

## Scheduling Scans

The built-in scheduler allows you to run scans automatically:

1. Navigate to **Scans** → **Schedule**
2. Configure the schedule parameters:
   - **Target** — Which target to scan
   - **Profile** — Scan profile to use
   - **Frequency** — Once, hourly, daily, weekly, or monthly
   - **Start Time** — When to begin the first run
3. Click **Create Schedule**

Scheduled scans appear in the scan history with a "Scheduled" tag. You can cancel or modify schedules from the same view.

---

## Security Best Practices

### Access Control

- **Never share credentials** — Each user should have their own account
- **Use the Principle of Least Privilege** — Grant Viewer or Operator roles when Admin is unnecessary
- **Change default passwords** — The `admin/admin` default is for development only

### Network Safety

- **Only scan networks you own or have authorization to scan**
- **Respect CIDR limits** — Never scan beyond /24 without explicit authorization
- **Use timeouts** — Prevent scans from running indefinitely
- **Rate limit** — Avoid overwhelming the API during automated use

### Data Protection

- **Keep `.env` out of version control** — Add it to `.gitignore`
- **Rotate `SECRET_KEY`** periodically in production
- **Back up your database** — The SQLite file is in `./data/`
- **Audit logs** — All actions are logged for compliance

---

## FAQ

### Q: The scan never completes. What should I do?

A: Check the scan timeout in `.env`. Increase `SCAN_TIMEOUT` if scanning a large network. Also verify that the target is reachable from the scanner host.

### Q: The AI says "no findings" but I know there are open ports.

A: Ensure the scan actually completed — check the scan status. The AI only analyzes results from completed scans. If the scan is still running, wait for it to finish.

### Q: I get a 401 error on API calls.

A: Make sure you are including the `Authorization: Bearer <token>` header. The token is returned from the `/api/v1/auth/login` endpoint and may need to be refreshed periodically.

### Q: Can I scan my own IP?

A: Yes. You can scan any target within your authorized scope. The only restriction is the CIDR prefix limit (/24 maximum).

### Q: How do I change the default admin password?

A: Use the API to update your user profile, or modify the user directly in the database. See the `/api/v1/auth/me` endpoint for updating your user info.

### Q: What happens if I delete a target that has scan results?

A: Deleting a target does not delete associated scan results. The scan data is preserved with the target ID set to null.

### Q: Can I use this tool for penetration testing?

A: Yes, but only with explicit written authorization from the network owner. Unauthorized scanning may be illegal in your jurisdiction.

### Q: How accurate is the risk scoring?

A: The rule-based AI scores risks based on well-known security patterns for common services. It is advisory — always validate findings manually. For more detailed analysis, use the OpenAI provider or consult a security professional.

### Q: Can I run the Web UI on a different port?

A: Yes — the backend serves the API on the configured port (default 8000). The Web UI is served from the same origin. Change the port via the `--port` flag or the `PORT` environment variable.