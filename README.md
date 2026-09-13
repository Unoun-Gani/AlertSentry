# AlertSentry

**Automated alert monitoring, phishing/attachment triage, and case-report generation for SOC L1 analysts.**

AlertSentry watches your incoming SIEM/EDR alerts and suspicious emails, runs
them through rule-based detection, scores severity (Low → Critical), and
writes a clean Markdown case report for each one — plus a master index —
so an L1 analyst (or their team) can triage and hand off findings fast
instead of writing reports by hand.

## Features

- **Log/alert analysis** — ingests JSON (JSONL) or CSV alert exports from a
  SIEM/EDR/firewall; flags malware, brute-force, and lateral-movement patterns.
- **Email & attachment analysis** — parses `.eml` files for phishing keywords,
  sender/reply-to spoofing, malicious link domains, and risky attachment
  types (`.exe`, `.js`, macro-enabled Office docs, etc.).
- **Severity scoring** — Low / Medium / High / Critical, fully configurable.
- **Case reports** — one Markdown file per alert/email in `reports/`, complete
  with indicators found and recommended next steps.
- **Master index** — `reports/_index.md` links every case for shift handoff.
- **Watch mode** — polls input folders and processes new files as they land,
  for near real-time monitoring.
- **Zero external dependencies** — pure Python standard library.

## Requirements

- Python 3.8 or newer (developed and tested on Python 3.12)
- No third-party packages required (see `requirements.txt`)

## Installation

### macOS / Linux

```bash

git clone https://github.com/Unoun-Gani/AlertSentry.git
cd AlertSentry

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies (currently none — future-proofs the project)
pip install -r requirements.txt

# 4. Verify it runs
python3 soc_monitor.py --help
```

### Windows (PowerShell)

```powershell
# 1. Clone the repo, then move into it
git clone https://github.com/Unoun-Gani/AlertSentry.git
cd AlertSentry

# 2. (Recommended) create a virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 3. Install dependencies (currently none — future-proofs the project)
pip install -r requirements.txt

# 4. Verify it runs
python soc_monitor.py --help
```

> **Note for Windows users:** use `python`, not `python3` — Windows installs
> Python under the `python` command by default. If any command fails, see
> [Troubleshooting (Windows)](#troubleshooting-windows) below.

## Quick start

macOS/Linux: use `python3`. Windows: use `python`. Otherwise identical:

```bash
# Process everything currently sitting in sample_logs/ and sample_emails/, once
python3 soc_monitor.py --scan

# Keep running and pick up new files as they arrive (polls every 5s by default)
python3 soc_monitor.py --watch --interval 5

# Catch up on existing files, then keep watching
python3 soc_monitor.py --scan --watch
```

Open `reports/_index.md` first — it links to every individual case report.

## Feeding it real data

- Drop SIEM/EDR alert exports (JSONL or CSV) into `sample_logs/`.
  Expected fields: `alert_id, timestamp, source, src_ip, dst_ip, user,
  event_type, description, severity`. Missing fields are fine — the tool
  marks them N/A rather than failing.
- Drop `.eml` files (export from Outlook/Gmail/most mail clients as
  "Save as .eml" or "Download message") into `sample_emails/`.
- Already-processed files are tracked in `.processed/` so re-running
  `--scan` won't duplicate reports.

## Tuning detection

All rule-based detection lives in `config.py`:

| Setting | Purpose |
|---|---|
| `SUSPICIOUS_ATTACHMENT_EXTENSIONS` | File types to flag as high risk |
| `PHISHING_KEYWORDS` | Subject/body phrases to flag |
| `BLACKLISTED_IPS` / `BLACKLISTED_DOMAINS` | Plug in your threat-intel feed |
| `SUSPICIOUS_SENDER_DOMAINS` | Domains to treat with extra scrutiny |

Detection logic itself is in `analyzers.py` — add new rules there (e.g.
impossible-travel logins, DGA domain detection, YARA integration).

## Project structure

```
soc_tool/
├── soc_monitor.py     # CLI entry point (--scan / --watch)
├── analyzers.py        # detection rules for logs and emails
├── reporter.py          # Markdown case report + index generation
├── config.py             # all tunable thresholds and lists
├── requirements.txt
├── LICENSE
├── sample_logs/         # drop JSON/CSV alerts here
├── sample_emails/       # drop .eml files here
└── reports/               # generated case reports + _index.md
```

## Troubleshooting (Windows)

**`Python was not found; run without arguments to install from the
Microsoft Store...`**
This means either Python isn't installed, or Windows' fake "Store alias" is
intercepting the command.
1. Run `python --version` in PowerShell. If it prints a version number,
   Python is already installed — just use `python`, not `python3`, in every
   command.
2. If it still shows the Microsoft Store message, install Python properly
   from [python.org/downloads](https://www.python.org/downloads/) — **not**
   the Microsoft Store — and make sure you tick **"Add python.exe to PATH"**
   during setup.
3. If Python is installed but the Store message still appears, go to
   **Settings → Apps → Advanced app settings → App execution aliases** and
   turn **off** the toggles for `python.exe` and `python3.exe`.

**`source : The term 'source' is not recognized...`**
`source` is a Linux/Mac shell command and doesn't exist in PowerShell. To
activate a virtual environment on Windows, use:
```powershell
venv\Scripts\Activate.ps1
```

**`... cannot be loaded because running scripts is disabled on this
system`** (when activating the venv)
PowerShell blocks script execution by default. Run this once per user (not
as Administrator), then try activating again:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
Type `Y` to confirm when prompted.

## Roadmap / extension ideas

- Pull alerts directly from a SIEM API (Splunk, Elastic) instead of files
- Real threat-intel lookups (VirusTotal / AbuseIPDB API enrichment)
- Auto-file a ticket in your case-management system for Critical/High cases
- Event-driven watching via `watchdog` instead of polling
- Daily shift-handoff summary export (PDF/HTML)

## License

Released under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

AlertSentry provides rule-based **triage assistance**, not a replacement for
analyst judgment. Always validate findings before escalation or containment
action.
