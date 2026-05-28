"""
Incident Response Playbook Generator
log_scanner.py — Scans log files for IOC patterns mapped to incident types
Supports: CSV, TXT, JSON log formats
Can scan full large files OR extract a smart sample first
"""

import csv
import json
import re
import os
from datetime import datetime
from urllib.parse import unquote

# ── IOC PATTERN LIBRARY ───────────────────────────────────────────────────────
IOC_PATTERNS = [
    # Phishing / BEC
    {
        "id": "suspicious_sender",
        "pattern": r"(from|sender|reply.to)[=:\s]+[\w.\-]+@(temp-mail|guerrillamail|mailinator|yopmail|10minutemail|throwam|fakeinbox)\.[\w]+",
        "description": "Disposable/throwaway email address detected",
        "severity": "High", "weight": 15,
        "incident_types": ["phishing", "bec"], "category": "Email"
    },
    {
        "id": "phishing_keywords",
        "pattern": r"\b(urgent.{0,20}(action|verify|confirm|update)|password.{0,20}(expire|reset|click)|account.{0,20}(suspend|locked|compromised)|verify.{0,20}identity)\b",
        "description": "Phishing language pattern in email content",
        "severity": "Medium", "weight": 10,
        "incident_types": ["phishing", "bec"], "category": "Email"
    },
    {
        "id": "bec_finance_keywords",
        "pattern": r"\b(wire.{0,10}transfer|change.{0,20}bank|update.{0,20}payment|new.{0,20}account.{0,20}details|urgent.{0,20}invoice|ceo.{0,20}request)\b",
        "description": "Business Email Compromise financial fraud pattern",
        "severity": "Critical", "weight": 20,
        "incident_types": ["bec", "phishing"], "category": "Email"
    },

    # Credential / Brute Force
    {
        "id": "failed_logins",
        "pattern": r"(failed.login|authentication.failure|invalid.password|login.attempt|bad.password|logon.failure)[^\n]{0,80}(\b([5-9]\d{1}|[1-9]\d{2,})\b)",
        "description": "Multiple failed login attempts — possible brute force",
        "severity": "High", "weight": 15,
        "incident_types": ["privilege_escalation", "phishing"], "category": "Authentication"
    },
    {
        "id": "admin_login_offhours",
        "pattern": r"(admin|administrator|root|sysadmin).{0,40}(login|logon|authenticated).{0,40}(0[0-4]:\d{2}|2[2-3]:\d{2})",
        "description": "Admin account login during off-hours (10PM-4AM)",
        "severity": "High", "weight": 15,
        "incident_types": ["insider_threat", "privilege_escalation"], "category": "Authentication"
    },
    {
        "id": "privilege_escalation_keywords",
        "pattern": r"\b(sudo.{0,20}(su|bash|sh|root)|privilege.{0,20}escalat|runas.{0,20}admin|lateral.movement|pass.the.hash|mimikatz|psexec|token.impersonat)\b",
        "description": "Privilege escalation tool or technique detected",
        "severity": "Critical", "weight": 25,
        "incident_types": ["privilege_escalation", "ransomware"], "category": "Endpoint"
    },

    # Malware / Ransomware
    {
        "id": "ransomware_extensions",
        "pattern": r"\.(locked|encrypted|enc|crypt|ryk|wncry|zepto|locky|cerber|petya|dharma|stop|maze|ryuk|conti|revil|lockbit)\b",
        "description": "Ransomware file extension detected",
        "severity": "Critical", "weight": 30,
        "incident_types": ["ransomware"], "category": "Endpoint"
    },
    {
        "id": "ransom_note_files",
        "pattern": r"(README_FOR_DECRYPT|HOW_TO_DECRYPT|DECRYPT_INSTRUCTION|YOUR_FILES_ARE_ENCRYPTED|RANSOM_NOTE|HOW_TO_RESTORE)\.(txt|html|hta)",
        "description": "Ransomware note file name detected",
        "severity": "Critical", "weight": 30,
        "incident_types": ["ransomware"], "category": "Endpoint"
    },
    {
        "id": "c2_beacon_pattern",
        "pattern": r"(beacon|c2|command.and.control|callback).{0,40}(http|https|tcp|udp).{0,60}(:\d{4,5})",
        "description": "Possible C2 beacon or callback traffic detected",
        "severity": "Critical", "weight": 25,
        "incident_types": ["ransomware", "phishing", "supply_chain"], "category": "Network"
    },

    # SQL Injection
    {
        "id": "sql_injection_basic",
        "pattern": r"((\%27)|(\')|(\-\-)|(\%23)|(#)).*(select|union|insert|drop|delete|update|exec|cast|convert|char|nchar|varchar)",
        "description": "SQL injection attempt pattern detected in request",
        "severity": "Critical", "weight": 25,
        "incident_types": ["sql_injection"], "category": "Web"
    },
    {
        "id": "sql_injection_union",
        "pattern": r"(union.{0,10}(all.{0,10})?select|select.{0,30}from.{0,30}(information_schema|sys\.|sysobjects)|1=1|or\s+1\s*=\s*1|'\s*or\s*')",
        "description": "SQL UNION-based or boolean injection detected",
        "severity": "Critical", "weight": 25,
        "incident_types": ["sql_injection"], "category": "Web"
    },
    {
        "id": "web_scanner",
        "pattern": r"(sqlmap|nikto|nessus|openvas|burpsuite|nmap|masscan|dirbuster|gobuster|hydra|medusa).{0,30}(scan|probe|crawl|fuzz)?",
        "description": "Known web/network scanning tool detected in logs",
        "severity": "High", "weight": 15,
        "incident_types": ["sql_injection", "privilege_escalation"], "category": "Web"
    },

    # Data Exfiltration / Insider Threat
    {
        "id": "bulk_download",
        "pattern": r"(download|export|transfer|copy).{0,40}(\d{3,}\.?\d*\s*(mb|gb|tb|megabyte|gigabyte))",
        "description": "Large bulk data download or transfer detected",
        "severity": "High", "weight": 20,
        "incident_types": ["insider_threat", "data_breach"], "category": "Data"
    },
    {
        "id": "data_exfil_destinations",
        "pattern": r"(dropbox|googledrive|drive\.google|onedrive|wetransfer|pastebin|mega\.nz|sendspace|filebin).{0,60}(upload|put|post|transfer)",
        "description": "Data upload to external cloud storage detected",
        "severity": "High", "weight": 20,
        "incident_types": ["insider_threat", "data_breach"], "category": "Data"
    },
    {
        "id": "pii_in_logs",
        "pattern": r"(\b\d{3}-\d{2}-\d{4}\b|\b\d{16}\b)",
        "description": "Potential PII (SSN/credit card number) found in logs",
        "severity": "Critical", "weight": 25,
        "incident_types": ["data_breach", "insider_threat"], "category": "Data"
    },

    # Network / DDoS
    {
        "id": "ddos_flood",
        "pattern": r"(syn.flood|udp.flood|icmp.flood|http.flood|amplification.attack|rate.limit.exceeded|connection.limit|bandwidth.exceeded)",
        "description": "DDoS flood pattern or rate limit exceeded",
        "severity": "High", "weight": 20,
        "incident_types": ["ddos"], "category": "Network"
    },
    {
        "id": "port_scan",
        "pattern": r"(port.scan|portscan|sweep).{0,80}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "description": "Port scanning activity detected",
        "severity": "Medium", "weight": 10,
        "incident_types": ["privilege_escalation", "ddos"], "category": "Network"
    },
    {
        "id": "tor_exit_node",
        "pattern": r"(tor.exit|torproject\.org|\.onion|tor.browser|anonymous.proxy).{0,40}(connect|access|request)",
        "description": "Tor exit node or anonymous proxy connection detected",
        "severity": "High", "weight": 15,
        "incident_types": ["data_breach", "insider_threat", "ransomware"], "category": "Network"
    },
    {
        "id": "masscan_tool",
        "pattern": r"masscan",
        "description": "Masscan port scanner detected in user agent or logs",
        "severity": "High", "weight": 15,
        "incident_types": ["ddos", "privilege_escalation"], "category": "Network"
    },

    # Supply Chain
    {
        "id": "supply_chain_update",
        "pattern": r"(software.update|auto.update|package.install|npm.install|pip.install|apt.install).{0,60}(outside.business.hours|unauthorized|unexpected|anomalous|not.scheduled)",
        "description": "Unexpected software update or package installation detected",
        "severity": "High", "weight": 15,
        "incident_types": ["supply_chain"], "category": "Endpoint"
    },
]

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


# ── SMART SAMPLER ─────────────────────────────────────────────────────────────

def extract_smart_sample(input_path: str, output_path: str,
                          normal_lines: int = 800, attack_lines: int = 200) -> str:
    """
    Extract a balanced sample from a large log file.
    Picks attack lines (containing known attack keywords) + normal lines.
    Much faster than scanning millions of lines.

    Args:
        input_path:   Path to the large log file
        output_path:  Where to save the sample
        normal_lines: How many normal (clean) lines to include
        attack_lines: How many attack lines to include

    Returns:
        Path to the created sample file
    """
    import random

    ATTACK_KEYWORDS = [
        "sqlmap", "nikto", "masscan", "nmap", "dirbuster", "gobuster",
        "union%20", "union+", "union all select",
        "%27%20and", "%27%20or", "%27%3b",
        "select%20from", "information_schema",
        "exec%28", "exec(", "<script>", "%3cscript",
        "etc/passwd", "etc/shadow",
        "mimikatz", ".locked", "readme_for_decrypt",
        "bitcoin", "ransom", "decrypt_instruction",
        "wget http", "curl http",
        "base64_decode", "/bin/sh", "/bin/bash",
        "wetransfer", "pastebin.com",
        "or%201%3d1", "or 1=1", "' or '",
    ]

    print(f"\n  Extracting smart sample from: {os.path.basename(input_path)}")
    print(f"  Target: {normal_lines} normal lines + {attack_lines} attack lines")

    found_attacks = []
    found_normal  = []
    total_read    = 0

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_read += 1
            line_lower = line.lower()
            is_attack = any(kw in line_lower for kw in ATTACK_KEYWORDS)

            if is_attack and len(found_attacks) < attack_lines * 5:
                found_attacks.append(line)
            elif not is_attack and len(found_normal) < normal_lines * 5:
                found_normal.append(line)

            # Stop early once we have enough candidates
            if len(found_attacks) >= attack_lines * 5 and len(found_normal) >= normal_lines * 5:
                break

    # Sample down to requested sizes
    sampled_attacks = random.sample(found_attacks, min(attack_lines, len(found_attacks)))
    sampled_normal  = random.sample(found_normal,  min(normal_lines,  len(found_normal)))
    combined        = sampled_attacks + sampled_normal
    random.shuffle(combined)

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(combined)

    print(f"  Sample created: {len(combined)} lines "
          f"({len(sampled_attacks)} attack + {len(sampled_normal)} normal)")
    print(f"  Saved to: {output_path}\n")
    return output_path


# ── SAMPLE LOG GENERATOR (for demo when no real file available) ───────────────

def generate_sample_logs(incident_type: str, output_path: str = "sample_logs.csv"):
    """Generate synthetic sample log CSV for testing a given incident type."""

    samples = {
        "phishing": [
            ["2026-05-01 08:12:33","email_gateway","INFO", "Message received from: john@temp-mail.org subject: Urgent: Verify your account now"],
            ["2026-05-01 08:12:45","email_gateway","WARN", "URL scan flagged: http://acme-verify-login.ru/secure phishing suspected"],
            ["2026-05-01 08:15:01","auth_server",  "WARN", "Failed login attempt user jsmith invalid password attempt 7"],
            ["2026-05-01 08:16:22","email_gateway","INFO", "Message from: cfo@acme-corp.co subject: urgent action required wire transfer to new vendor"],
            ["2026-05-01 09:01:10","auth_server",  "INFO", "User jsmith authenticated successfully from IP 185.220.101.45"],
            ["2026-05-01 09:05:44","web_proxy",    "INFO", "User jsmith accessed dropbox.com upload transferred 45 MB"],
            ["2026-05-01 09:10:00","endpoint",     "INFO", "Normal user activity"],
        ],
        "ransomware": [
            ["2026-05-02 02:14:10","endpoint",   "WARN",  "Process mimikatz.exe detected on host WORKSTATION-04"],
            ["2026-05-02 02:15:33","endpoint",   "ERROR", "Mass file rename detected 847 files renamed to .locked extension in 60 seconds"],
            ["2026-05-02 02:15:45","endpoint",   "ERROR", "File created C:/Users/Public/README_FOR_DECRYPT.txt"],
            ["2026-05-02 02:16:01","network",    "WARN",  "C2 beacon detected callback to 185.220.101.45:4444 via https"],
            ["2026-05-02 02:16:20","endpoint",   "ERROR", "SMB lateral movement attempt from WORKSTATION-04 to 10 additional hosts"],
            ["2026-05-02 02:20:00","auth_server","WARN",  "Admin login at 02:20 from WORKSTATION-04 off-hours access"],
        ],
        "sql_injection": [
            ["2026-05-03 14:22:01","web_app","WARN",  "GET /search?q=' OR 1=1-- from 203.0.113.55"],
            ["2026-05-03 14:22:05","web_app","ERROR", "GET /login?user=admin'-- SQL error returned"],
            ["2026-05-03 14:22:10","web_app","ERROR", "GET /items?id=1 UNION ALL SELECT username,password FROM users--"],
            ["2026-05-03 14:22:15","web_app","WARN",  "sqlmap scan detected from 203.0.113.55 automated injection probe"],
            ["2026-05-03 14:23:00","web_app","ERROR", "SELECT from information_schema.tables unauthorized DB query"],
        ],
        "insider_threat": [
            ["2026-05-04 22:47:10","auth_server","WARN",  "Admin login at 22:47 off-hours by user mwilson"],
            ["2026-05-04 22:48:30","dlp",        "WARN",  "Bulk download detected user mwilson exported 2.4 GB from HR database"],
            ["2026-05-04 22:51:00","web_proxy",  "WARN",  "User mwilson upload to wetransfer.com 2.1 GB transfer"],
            ["2026-05-04 22:55:10","dlp",        "ERROR", "PII detected in outbound transfer SSN pattern 123-45-6789 found in export"],
        ],
        "ddos": [
            ["2026-05-05 16:01:00","firewall",  "WARN",  "SYN flood detected from 192.0.2.0/24 rate limit exceeded 50000 pps"],
            ["2026-05-05 16:01:05","firewall",  "ERROR", "UDP flood amplification attack bandwidth exceeded 9.8 Gbps"],
            ["2026-05-05 16:01:10","web_server","ERROR", "HTTP flood 85000 requests per sec to /login endpoint connection limit hit"],
            ["2026-05-05 16:02:00","noc",       "WARN",  "Port scan detected masscan sweep from 198.51.100.0/24"],
        ],
    }

    rows = samples.get(incident_type, samples["phishing"])
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "source", "level", "message"])
        writer.writerows(rows)

    print(f"  Sample log file created: {output_path}")
    return output_path


# ── CORE SCANNER ──────────────────────────────────────────────────────────────

def scan_logs(file_path: str, incident_type: str = None,
              max_lines: int = None) -> dict:
    """
    Scan a log file for IOC patterns.

    Args:
        file_path:     Path to log file (.csv, .txt, or .json)
        incident_type: Optional filter — only patterns for this incident type
        max_lines:     Optional line limit (useful for huge files)

    Returns:
        dict with findings, risk score, matched incident types, recommendations
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    ext   = os.path.splitext(file_path)[1].lower()
    lines = _read_log_file(file_path, ext, max_lines)

    print(f"\n{'='*60}")
    print(f"  LOG SCANNER")
    print(f"  File   : {os.path.basename(file_path)}")
    print(f"  Lines  : {len(lines)}")
    print(f"  Filter : {incident_type or 'All incident types'}")
    print(f"{'='*60}\n")

    findings = []
    patterns_to_check = IOC_PATTERNS
    if incident_type:
        patterns_to_check = [p for p in IOC_PATTERNS
                              if incident_type in p["incident_types"]]

    for line_num, line in enumerate(lines, 1):
        # URL-decode the line so %27 → ' and %20 → space etc
        # This catches real web server log attacks that are URL-encoded
        try:
            decoded_line = unquote(line)
        except Exception:
            decoded_line = line
        line_lower = decoded_line.lower()
        for pattern in patterns_to_check:
            try:
                match = re.search(pattern["pattern"], line_lower, re.IGNORECASE)
                if match:
                    findings.append({
                        "line_number":    line_num,
                        "line_content":   decoded_line.strip()[:120] + ("..." if len(decoded_line) > 120 else ""),
                        "ioc_id":         pattern["id"],
                        "description":    pattern["description"],
                        "severity":       pattern["severity"],
                        "weight":         pattern["weight"],
                        "category":       pattern["category"],
                        "incident_types": pattern["incident_types"],
                        "matched_text":   match.group(0)[:60]
                    })
            except re.error:
                continue

    # Deduplicate same pattern on same line
    seen = set()
    unique = []
    for f in findings:
        key = (f["line_number"], f["ioc_id"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    total_weight  = sum(f["weight"] for f in unique)
    risk_score    = min(total_weight, 100)
    risk_level    = _score_to_level(risk_score)
    matched_types = list({t for f in unique for t in f["incident_types"]})

    result = {
        "file":                  file_path,
        "lines_scanned":         len(lines),
        "total_findings":        len(unique),
        "risk_score":            risk_score,
        "risk_level":            risk_level,
        "findings":              unique,
        "matched_incident_types": matched_types,
        "categories_hit":        list({f["category"] for f in unique}),
        "scanned_at":            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "recommendations":       _scan_recommendations(unique, risk_level)
    }

    _print_scan_result(result)
    return result


def _read_log_file(file_path: str, ext: str, max_lines: int = None) -> list:
    lines = []
    try:
        if ext == ".csv":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if max_lines and i >= max_lines:
                        break
                    lines.append(" ".join(str(v) for v in row.values()))
        elif ext == ".json":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                items = data if isinstance(data, list) else [data]
                for i, entry in enumerate(items):
                    if max_lines and i >= max_lines:
                        break
                    lines.append(json.dumps(entry))
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if max_lines and i >= max_lines:
                        break
                    lines.append(line)
    except Exception as e:
        print(f"  Warning reading file: {e}")
    return lines


def _score_to_level(score: int) -> str:
    if score >= 60: return "Critical"
    if score >= 40: return "High"
    if score >= 20: return "Medium"
    return "Low"


def _scan_recommendations(findings: list, risk_level: str) -> list:
    recs       = []
    categories = {f["category"] for f in findings}
    severities = {f["severity"] for f in findings}

    if "Critical" in severities:
        recs.append("IMMEDIATE: Critical IOCs detected — activate IR team now")
    if "Authentication" in categories:
        recs.append("Investigate failed logins and reset potentially compromised credentials")
    if "Data" in categories:
        recs.append("Review data access logs — potential exfiltration detected")
    if "Endpoint" in categories:
        recs.append("Isolate affected endpoints and run full EDR scan")
    if "Web" in categories:
        recs.append("Block attacking IP at WAF and review web app for SQLi vulnerabilities")
    if "Network" in categories:
        recs.append("Engage DDoS mitigation and review firewall ACLs")
    if "Email" in categories:
        recs.append("Quarantine suspicious emails and reset credentials for affected users")
    if risk_level in ["Critical", "High"]:
        recs.append("Preserve all logs — do not clear or rotate until IR is complete")

    return recs if recs else ["No immediate actions required — continue monitoring"]


def _print_scan_result(result: dict):
    COLORS = {"Critical": "\033[91m", "High": "\033[93m",
               "Medium": "\033[94m", "Low": "\033[92m"}
    RESET  = "\033[0m"
    div    = "-" * 60
    color  = COLORS.get(result["risk_level"], "")

    print(f"{div}")
    print(f"  SCAN COMPLETE")
    print(div)
    print(f"  Lines Scanned  : {result['lines_scanned']}")
    print(f"  IOCs Found     : {result['total_findings']}")
    print(f"  Risk Score     : {result['risk_score']} / 100")
    print(f"  Risk Level     : {color}{result['risk_level'].upper()}{RESET}")
    if result["matched_incident_types"]:
        print(f"  Likely Attacks : {', '.join(result['matched_incident_types'])}")
    print(div)

    if result["findings"]:
        print(f"\n  TOP IOC FINDINGS (showing first 10 of {result['total_findings']}):\n")
        for i, f in enumerate(result["findings"][:10], 1):
            fc = COLORS.get(f["severity"], "")
            print(f"  [{i}] {fc}{f['severity'].upper()}{RESET} — {f['description']}")
            print(f"       Line {f['line_number']}: {f['line_content'][:80]}...")
            print(f"       Category: {f['category']}  |  Match: {f['matched_text']}")
            print()

    if result["recommendations"]:
        print(f"  RECOMMENDATIONS:")
        for rec in result["recommendations"]:
            print(f"    > {rec}")
    print(f"\n{div}\n")
