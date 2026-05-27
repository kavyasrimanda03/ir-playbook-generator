# 🛡️ Incident Response Playbook Generator

A Python CLI tool that generates structured, audit-ready **Incident Response playbooks** mapped to **NIST SP 800-61** and **MITRE ATT&CK** frameworks. Takes an incident type as input and outputs a step-by-step response plan with escalation paths, IOCs, SLA targets, and a professional PDF report.

---

## 🎯 Why This Tool Exists

Security teams spend hours manually writing IR playbooks in Word documents. This tool automates that process — producing consistent, framework-aligned playbooks in seconds. It mirrors real GRC deliverables used by SOC teams and compliance analysts.

---

## 📋 Supported Incident Types

| Incident | Default Severity | MITRE Tactics |
|---|---|---|
| `phishing` | High | Initial Access, Credential Access |
| `ransomware` | Critical | Execution, Lateral Movement, Impact |
| `data_breach` | Critical | Collection, Exfiltration |
| `insider_threat` | High | Collection, Exfiltration, Defense Evasion |
| `ddos` | High | Impact (T1498) |

---

## ⚙️ Features

- **5 incident types** with full response playbooks
- **5 response phases** per incident: Identification → Containment → Eradication → Recovery → Lessons Learned
- **NIST SP 800-61** control mapping for every phase
- **MITRE ATT&CK** tactic tagging
- **Escalation matrix** by severity (Low / High / Critical)
- **SLA targets** for containment and full resolution
- **IOC checklists** for each incident type
- **Professional PDF report** generation (color-coded, paginated)
- **CLI interface** for flexible usage

---

## 🚀 Quick Start

**1. Clone the repository:**
```bash
git clone https://github.com/kavyasrimanda03/ir-playbook-generator.git
cd ir-playbook-generator
```

**2. Install dependencies:**
```bash
pip install -r requirements.txt
```

**3. Generate a playbook:**
```bash
# Text output to console
python main.py --incident phishing --org "Acme Corp" --analyst "Jane Doe"

# Generate PDF report
python main.py --incident ransomware --org "Acme Corp" --analyst "Jane Doe" --pdf

# Override severity
python main.py --incident phishing --severity Critical --pdf

# List available incident types
python main.py --list
```

---

## 📄 Sample Output

The tool produces a console playbook and an optional PDF report:

```
======================================================================
  INCIDENT RESPONSE PLAYBOOK — PHISHING ATTACK
  Organization : University of Delaware
  Analyst      : Kavya Sri Reddy
  Severity     : High
======================================================================

📋 INCIDENT OVERVIEW
----------------------------------------------------------------------
Description  : A social engineering attack where adversaries send
               fraudulent emails to trick users into revealing
               credentials or installing malware.
MITRE Tactics: Initial Access (TA0001), Credential Access (TA0006)

⏱️  SLA TARGETS
  Detection → Containment : 4 hours
  Full Resolution         : 72 hours

▶  PHASE: IDENTIFICATION  [0–1 hour]
   NIST Control: DE.AE-2 — Detected events are analyzed...
   Steps:
     1. Receive and triage phishing report from user or email gateway
     2. Collect the suspicious email (headers, body, attachments)
     ...
```

PDF reports are included in this repository:
- [`playbook_phishing_20260527_154829.pdf`](playbook_phishing_20260527_154829.pdf)
- [`playbook_ransomware_20260527_154838.pdf`](playbook_ransomware_20260527_154838.pdf)

---

## 📁 Project Structure

```
ir-playbook-generator/
├── main.py                        # CLI entry point
├── playbook_generator.py          # Core playbook generation logic
├── incident_data.py               # Incident definitions, NIST mappings, IOCs
├── report_generator.py            # PDF report generation (reportlab)
├── requirements.txt
├── playbook_phishing_20260527_154829.pdf   # Example output — Phishing
├── playbook_ransomware_20260527_154838.pdf # Example output — Ransomware
└── README.md
```

---

## 🗂️ Playbook Structure (per incident)

Each generated playbook includes:

```
Playbook
├── Metadata (org, analyst, timestamp, severity, version)
├── Incident Overview
│   ├── Description
│   ├── MITRE ATT&CK tactics
│   ├── NIST CSF functions
│   └── IOC checklist
├── SLA Targets
├── Escalation Matrix (by severity level)
└── Response Phases
    ├── Identification  [timeframe + NIST control + tools + steps]
    ├── Containment     [timeframe + NIST control + tools + steps]
    ├── Eradication     [timeframe + NIST control + tools + steps]
    ├── Recovery        [timeframe + NIST control + tools + steps]
    └── Lessons Learned [timeframe + NIST control + tools + steps]
```

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | Core language |
| reportlab | PDF generation |
| argparse | CLI interface |
| NIST SP 800-61 | IR framework reference |
| MITRE ATT&CK | Tactic tagging reference |

---

## 🔗 Framework References

- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 👩‍💻 Author

**Manda Kavya Sri Reddy**  
M.S. Cybersecurity — University of Delaware  
[LinkedIn](https://www.linkedin.com/in/kavyasrireddymanda/) | [GitHub](https://github.com/kavyasrimanda03)
