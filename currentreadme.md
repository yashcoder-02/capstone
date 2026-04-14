# MemSuite — Memory Forensics Automation Suite

A web-based automation suite for analyzing malware artifacts in volatile memory dumps. Built with Python (Flask + Volatility 3), automated via a Jenkins CI/CD pipeline, and version-controlled on Git.

---

## Overview

MemSuite automates the post-acquisition forensic analysis of memory dump files (`.mem`, `.raw`, `.lime`). Rather than running Volatility plugins manually, MemSuite chains them into a structured pipeline — with integrity verification, cross-plugin correlation, severity scoring, and report generation — triggered automatically through Jenkins.

**This project follows the cold forensics model.** Analysis is performed on pre-acquired memory dumps, which is standard practice in post-incident investigations and avoids the evidence contamination risks associated with live acquisition.

---

## Features

- **Integrity Verification** — SHA-256 hash of dump file at intake; chain-of-custody logging
- **Process Analysis** — `pslist` vs `psscan` diff to detect hidden/unlinked processes
- **Network Forensics** — Active and recently closed connection extraction via `netscan`
- **Code Injection Detection** — Executable non-file-backed memory regions via `malfind`
- **Cross-Plugin Correlation** — Flags PIDs suspicious across multiple analysis modules
- **Severity Scoring** — Automated Low / Medium / High classification per finding
- **Report Generation** — HTML + PDF report with summary, findings table, and IOCs
- **Web Dashboard** — Flask UI to upload dumps, track cases, and view results
- **Jenkins Pipeline** — Each analysis stage runs as a discrete, auditable Jenkins job

---

## Tech Stack

| Layer | Technology | Justification |
|---|---|---|
| Web Framework | Flask (Python) | Same language as forensics engine — direct integration, no subprocess overhead |
| Forensics Engine | Volatility 3 | Industry-standard memory forensics framework, Python API |
| Automation | Jenkins | CI/CD pipeline with per-stage auditability |
| Database | SQLite | Zero-config, file-based, sufficient for case management at this scope |
| Reporting | Jinja2 + WeasyPrint | Python-native templating, clean PDF output |
| Version Control | Git / GitHub | Full change history, documentation, pipeline config |

---

## Project Structure

```
memsuite/
├── Jenkinsfile                  # Pipeline definition
├── requirements.txt
├── README.md
│
├── engine/
│   ├── integrity.py             # Hash verification + metadata logging
│   ├── correlate.py             # Cross-plugin anomaly detection + severity scoring
│   ├── report.py                # HTML/PDF report generator
│   └── plugins/
│       ├── process_scan.py      # pslist vs psscan diff
│       ├── network_scan.py      # netscan — active/closed connections
│       └── malfind.py           # Code injection detection
│
├── webapp/
│   ├── app.py                   # Flask app + routes
│   ├── templates/
│   │   ├── index.html           # Upload page
│   │   ├── cases.html           # Case list
│   │   └── results.html         # Results dashboard
│   └── static/
│       └── style.css
│
├── reports/                     # Auto-generated JSON + PDF reports
├── dumps/                       # Memory dump files (not committed to Git)
├── tests/                       # Unit tests per module
└── docs/
    ├── architecture.md          # System design + diagrams
    ├── plugins.md               # Plugin descriptions + what each detects
    └── pipeline.md              # Jenkins stage breakdown
```

---

## Pipeline (Jenkins)

Each Jenkins stage corresponds to one analysis module. Stages run sequentially; failure in any stage stops the pipeline and logs the error.

```
Setup → Integrity Check → Process Analysis → Network Analysis → Malfind → Correlate → Report
```

The full `Jenkinsfile` is in the root of this repo.

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- Jenkins (local or server)
- Git

### Install Dependencies

```bash
git clone https://github.com/<your-username>/memsuite.git
cd memsuite
pip install -r requirements.txt
```

### Run Web Dashboard

```bash
cd webapp
python app.py
# Open http://localhost:5000
```

### Run Analysis Manually (without Jenkins)

```bash
python engine/integrity.py dumps/sample.mem
python engine/plugins/process_scan.py dumps/sample.mem
python engine/plugins/network_scan.py dumps/sample.mem
python engine/plugins/malfind.py dumps/sample.mem
python engine/correlate.py
python engine/report.py
```

### Trigger via Jenkins

1. Configure Jenkins to point at this repo
2. Create a Pipeline job using the `Jenkinsfile`
3. Pass the dump file path as a build parameter
4. Monitor each stage in the Jenkins UI

---

## Sample Output

> *(Screenshots and sample report will be added after first successful pipeline run)*

---

## Test Dumps

Sample memory dumps for testing are sourced from [MemLabs](https://github.com/stuxnet999/MemLabs) — a set of CTF-style forensics challenges with real memory images. These are **not committed to this repo** due to file size; download separately and place in `dumps/`.

---

## Forensic Methodology

| Stage | Tool/Method | What it detects |
|---|---|---|
| Integrity | SHA-256 hash | Tampering, corruption |
| Process Analysis | pslist + psscan diff | Hidden / unlinked processes |
| Network Analysis | netscan | C2 connections, suspicious ports |
| Code Injection | malfind | Injected shellcode, hollowed processes |
| Correlation | Custom scoring | Multi-indicator suspicious PIDs |

---

## Documentation

Full documentation is in the [`docs/`](./docs/) folder:
- [`architecture.md`](./docs/architecture.md) — System design
- [`plugins.md`](./docs/plugins.md) — Volatility plugin breakdown
- [`pipeline.md`](./docs/pipeline.md) — Jenkins pipeline stages

---

## Team

> *(Add team member names and roles here)*

---

## License

MIT
