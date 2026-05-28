# 🛡️ Incident Response Playbook Generator

A Python CLI tool that automates incident response documentation — a core GRC and SOC analyst workflow. Scans real log files for attack indicators, dynamically calculates incident severity, generates NIST SP 800-61 and MITRE ATT&CK aligned playbooks, and exports professional PDF reports.

**Validated against a real-world Apache web server log dataset (Kaggle) — correctly identified 186 SQL injection and UNION SELECT attacks from live traffic with a 100/100 risk score.**

---

## 🎯 What It Does

Security teams spend hours manually writing IR playbooks in spreadsheets. This tool automates that process — taking an incident type and log file as input, and producing a structured, audit-ready response plan in seconds.

---

## ⚙️ Features

- **9 incident types** — each with a complete 5-phase response playbook
- **20 IOC detection patterns** across 6 categories (Email, Web, Endpoint, Network, Authentication, Data)
- **URL-decoded log scanning** — catches real-world web server attacks encoded as `%27`, `%20UNION%20SELECT` etc.
- **Smart sampler** — extracts a balanced attack/normal sample from large log files (handles 10M+ line files)
- **Interactive severity calculator** — 8-factor weighted scoring model (score 0–100 → Low/Medium/High/Critical)
- **NIST SP 800-61** control mapping for every response phase
- **MITRE ATT&CK** tactic tagging per incident type
- **Escalation matrix** by severity level
- **SLA targets** per incident type
- **Professional PDF reports** — color-coded, paginated, audit-ready
- Supports **CSV, TXT, and JSON** log file formats

---

## 📋 Supported Incident Types

| Incident | Severity | Phases | Steps | MITRE Tactics |
|---|---|---|---|---|
| `phishing` | High | 5 | 28 | Initial Access, Credential Access |
| `ransomware` | Critical | 5 | 31 | Execution, Lateral Movement, Impact |
| `data_breach` | Critical | 5 | 29 | Collection, Exfiltration |
| `insider_threat` | High | 5 | 27 | Collection, Exfiltration, Defense Evasion |
| `ddos` | High | 5 | 27 | Impact (T1498) |
| `bec` | Critical | 5 | 27 | Phishing, Collection, Exfiltration |
| `sql_injection` | Critical | 5 | 24 | Initial Access, Collection, Exfiltration |
| `privilege_escalation` | High | 5 | 24 | Privilege Escalation, Lateral Movement, Persistence |
| `supply_chain` | Critical | 5 | 24 | Initial Access, Execution, Persistence |

---

## 🔍 IOC Detection Patterns (20 total)

| Category | Patterns |
|---|---|
| Web | SQL injection, UNION SELECT, web scanners (sqlmap, nikto, masscan) |
| Endpoint | Ransomware extensions, ransom notes, C2 beacons, privilege escalation tools |
| Authentication | Brute force / failed logins, off-hours admin access |
| Network | DDoS floods, port scans, Tor exit nodes |
| Data | Bulk downloads, cloud exfiltration, PII exposure |
| Email | Disposable addresses, phishing language, BEC fraud patterns |

---

## 🚀 Quick Start

**1. Clone the repository:**
```bash
git clone https://github.com/kavyasrimanda03/ir-playbook-generator.git
cd ir-playbook-generator
```

**2. Install dependencies:**
```bash
pip install reportlab
```

**3. Run your first playbook:**
```bash
python main.py --incident phishing --org "Acme Corp" --analyst "Jane Doe" --pdf
```

---

## 📖 All Usage Examples

```bash
# Basic playbook — text output only
python main.py --incident phishing --org "Acme Corp" --analyst "Jane Doe"

# With interactive severity calculator + PDF
python main.py --incident ransomware --org "Acme Corp" --analyst "Jane Doe" --assess --pdf

# Generate built-in synthetic sample logs, then scan them
python main.py --incident ransomware --sample-logs
python main.py --incident ransomware --scan sample_logs.csv --pdf

# Scan your own log file directly
python main.py --incident sql_injection --scan /path/to/your/logs.txt --pdf

# Use a large real dataset (auto-extracts smart 1000-line balanced sample)
python main.py --incident sql_injection --sample-from access.log --severity Critical --pdf

# List all available incident types
python main.py --list
```

---

## 📊 Real Dataset Validation

The log scanner was validated against a real Apache web server access log dataset
(source: [Kaggle — Web Server Access Logs](https://www.kaggle.com/datasets/eliasdabbas/web-server-access-logs)):

| Metric | Result |
|---|---|
| Lines scanned | 1,000 (balanced sample from 10M+ line file) |
| IOCs detected | 186 |
| Risk score | 100 / 100 |
| Risk level | CRITICAL |
| Attack correctly identified | SQL Injection (UNION SELECT, blind injection) |
| Attacker IP flagged | 5.101.40.234 |

Sample output report: [`sample_report_sql_injection.pdf`](sample_report_sql_injection.pdf)

---

## 📁 Project Structure

```
ir-playbook-generator/
├── main.py                      # CLI entry point — run this
├── incident_data.py             # 9 incident definitions, NIST mappings, IOCs, SLAs
├── playbook_generator.py        # Builds structured playbook from incident data
├── severity_calculator.py       # Interactive 8-factor severity scoring engine
├── log_scanner.py               # IOC pattern scanner + smart sampler for large files
├── report_generator.py          # PDF report generation (reportlab)
├── requirements.txt             # reportlab
├── sample_report_sql_injection.pdf   # Example output — real dataset scan
└── README.md
```

---

## 🗂️ Playbook Structure

Each generated playbook contains:

```
Playbook
├── Metadata          (org, analyst, timestamp, severity, version)
├── Log Scan Results  (IOC findings, risk score, attack types detected)
├── Severity Assessment (8-factor score if --assess used)
├── Incident Overview (description, MITRE tactics, NIST functions)
├── IOC Checklist
├── SLA Targets
├── Escalation Matrix (Low / High / Critical paths)
└── Response Phases
    ├── Identification  [timeframe + NIST control + tools + steps]
    ├── Containment     [timeframe + NIST control + tools + steps]
    ├── Eradication     [timeframe + NIST control + tools + steps]
    ├── Recovery        [timeframe + NIST control + tools + steps]
    └── Lessons Learned [timeframe + NIST control + tools + steps]
```

---

## 🔢 Severity Calculator

The `--assess` flag triggers an interactive 8-question severity assessment:

| Factor | Max Points |
|---|---|
| Is the attack currently active? | 20 |
| Is the system internet-facing? | 15 |
| Is sensitive data involved? | 20 |
| How many systems affected? | 20 |
| Is a privileged account compromised? | 15 |
| Is there business disruption? | 10 |
| Has data been exfiltrated? | 15 |
| How was the incident detected? | 8 |

Score → Severity: 0–24 Low | 25–49 Medium | 50–74 High | 75+ Critical

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | Core language |
| reportlab | PDF generation |
| re (regex) | IOC pattern matching |
| urllib.parse | URL-decoding web server logs |
| argparse | CLI interface |
| NIST SP 800-61 | IR framework reference |
| MITRE ATT&CK | Tactic tagging reference |

---

## 🔗 Framework References

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 👩‍💻 Author

**Manda Kavya Sri Reddy**
M.S. Cybersecurity — University of Delaware
[LinkedIn](https://www.linkedin.com/in/kavyasrireddymanda/) | [GitHub](https://github.com/kavyasrimanda03)
