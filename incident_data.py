"""
Incident Response Playbook Generator
incident_data.py — Incident type definitions, NIST mappings, and playbook templates
"""

INCIDENTS = {
    "phishing": {
        "name": "Phishing Attack",
        "severity_default": "High",
        "description": "A social engineering attack where adversaries send fraudulent emails to trick users into revealing credentials or installing malware.",
        "mitre_tactics": ["Initial Access (TA0001)", "Credential Access (TA0006)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0–1 hour",
                "steps": [
                    "Receive and triage phishing report from user or email gateway alert",
                    "Collect the suspicious email (headers, body, attachments, links)",
                    "Search mail logs for all recipients of the same email",
                    "Check URLs and attachments against threat intelligence (VirusTotal, URLScan)",
                    "Determine if any user clicked links or opened attachments",
                    "Assign severity: Low (no clicks), High (credentials entered), Critical (malware executed)"
                ],
                "tools": ["Email gateway logs", "VirusTotal", "URLScan.io", "SIEM"],
                "nist_control": "DE.AE-2 — Detected events are analyzed to understand attack targets and methods"
            },
            "Containment": {
                "timeframe": "1–4 hours",
                "steps": [
                    "Block sender domain and IP at email gateway",
                    "Quarantine or delete the phishing email from all mailboxes",
                    "Reset credentials for any users who submitted passwords",
                    "Enable MFA immediately for affected accounts",
                    "Isolate any endpoint that executed an attachment",
                    "Block malicious URLs at web proxy / firewall"
                ],
                "tools": ["Email admin console", "Active Directory", "Firewall/Proxy", "EDR"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "4–24 hours",
                "steps": [
                    "Remove malware from affected endpoints using EDR tooling",
                    "Audit OAuth app permissions granted during the attack window",
                    "Review forwarding rules added to compromised mailboxes",
                    "Revoke and reissue any exposed API keys or tokens",
                    "Conduct full AV/EDR scan across all endpoints"
                ],
                "tools": ["EDR platform", "Microsoft 365 Admin", "AD Audit logs"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "24–72 hours",
                "steps": [
                    "Restore affected systems from clean backups if needed",
                    "Re-enable user accounts after credential reset is confirmed",
                    "Monitor affected accounts for 72 hours post-incident",
                    "Validate that all malicious artifacts are removed",
                    "Communicate resolution to affected users"
                ],
                "tools": ["Backup systems", "SIEM monitoring", "Email gateway"],
                "nist_control": "RC.RP-1 — Recovery plan is executed during or after a cybersecurity incident"
            },
            "Lessons Learned": {
                "timeframe": "Within 1 week",
                "steps": [
                    "Conduct post-incident review with all stakeholders",
                    "Document timeline, root cause, and impact",
                    "Identify gaps in email filtering rules",
                    "Schedule phishing awareness training for affected users",
                    "Update detection rules based on observed indicators",
                    "File formal incident report (NIST SP 800-61 format)"
                ],
                "tools": ["ITSM/ticketing system", "Training platform", "SIEM rule editor"],
                "nist_control": "RC.IM-1 — Recovery plans incorporate lessons learned"
            }
        },
        "iocs": ["Sender email/domain", "Malicious URLs", "File hashes of attachments", "IP addresses in headers"],
        "escalation": {
            "Low": "SOC Tier 1 analyst",
            "High": "SOC Tier 2 + IT Security Manager",
            "Critical": "CISO + Legal + HR (if data exfiltration suspected)"
        },
        "sla": {"detection_to_containment": "4 hours", "full_resolution": "72 hours"}
    },

    "ransomware": {
        "name": "Ransomware Attack",
        "severity_default": "Critical",
        "description": "Malware that encrypts victim files and demands payment for decryption keys. Can spread laterally across networks causing widespread business disruption.",
        "mitre_tactics": ["Execution (TA0002)", "Lateral Movement (TA0008)", "Impact (TA0040)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0–30 minutes",
                "steps": [
                    "Detect via EDR alert, user report, or file integrity monitoring",
                    "Identify the affected host(s) and user accounts",
                    "Determine ransomware variant if possible (ransom note, file extension)",
                    "Check if encryption is still active or has completed",
                    "Identify patient zero — the initial infected system",
                    "Assess scope: number of systems affected, data encrypted"
                ],
                "tools": ["EDR", "SIEM", "File integrity monitor", "Network traffic analysis"],
                "nist_control": "DE.CM-4 — Malicious code is detected"
            },
            "Containment": {
                "timeframe": "30 min – 2 hours",
                "steps": [
                    "IMMEDIATELY isolate affected systems from network (disable NIC or VLAN)",
                    "Disable shared drives and network file shares enterprise-wide",
                    "Block C2 IP addresses and domains at firewall",
                    "Disable affected user accounts in Active Directory",
                    "Preserve memory dumps and disk images before shutdown for forensics",
                    "Notify IT leadership and activate IR team",
                    "Do NOT pay ransom without executive and legal approval"
                ],
                "tools": ["Network switch/VLAN controls", "Firewall", "AD", "Forensic imaging tools"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "2–48 hours",
                "steps": [
                    "Identify the initial attack vector (phishing, RDP brute force, vulnerability)",
                    "Remove ransomware binary from all affected systems",
                    "Patch or remediate the exploited vulnerability immediately",
                    "Audit and rotate ALL privileged credentials enterprise-wide",
                    "Check for persistence mechanisms (scheduled tasks, registry keys, startup items)",
                    "Rebuild systems from scratch if encryption was extensive"
                ],
                "tools": ["EDR", "Vulnerability scanner", "AD", "Patch management"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "48 hours – 2 weeks",
                "steps": [
                    "Restore data from last known clean backup",
                    "Verify backup integrity BEFORE restoring to production",
                    "Restore systems in priority order (critical business systems first)",
                    "Monitor restored systems closely for 7 days",
                    "Notify regulatory bodies if PII/PHI was exposed (GDPR/HIPAA requirements)",
                    "Communicate status to business stakeholders daily"
                ],
                "tools": ["Backup and recovery platform", "SIEM", "Compliance management"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 2 weeks",
                "steps": [
                    "Conduct full post-mortem with C-suite, IT, legal, and HR",
                    "Document complete attack timeline from initial access to containment",
                    "Review backup frequency and offsite/offline backup strategy",
                    "Assess network segmentation gaps that allowed lateral movement",
                    "Update IR plan and runbooks based on gaps identified",
                    "Consider cyber insurance claim if applicable"
                ],
                "tools": ["Documentation platform", "Network architecture review", "Insurance portal"],
                "nist_control": "RC.IM-2 — Recovery strategies are updated"
            }
        },
        "iocs": ["Encrypted file extensions", "Ransom note filenames", "C2 IP/domains", "Malware hashes", "Anomalous SMB traffic"],
        "escalation": {
            "Low": "N/A — Ransomware is always High or Critical",
            "High": "CISO + IT Director + Legal",
            "Critical": "CEO + Board notification + Law enforcement (FBI IC3) + Cyber insurance carrier"
        },
        "sla": {"detection_to_containment": "2 hours", "full_resolution": "2 weeks"}
    },

    "data_breach": {
        "name": "Data Breach",
        "severity_default": "Critical",
        "description": "Unauthorized access, acquisition, or disclosure of sensitive, protected, or confidential data including PII, PHI, financial records, or intellectual property.",
        "mitre_tactics": ["Collection (TA0009)", "Exfiltration (TA0010)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0–2 hours",
                "steps": [
                    "Confirm that a breach occurred (vs. false positive)",
                    "Identify what data was accessed or exfiltrated",
                    "Classify data type: PII, PHI, financial, IP, credentials",
                    "Identify affected systems, databases, and storage locations",
                    "Determine the attack vector (insider, external, misconfiguration)",
                    "Establish timeline: when did breach begin? When was it discovered?"
                ],
                "tools": ["DLP tools", "SIEM", "Database activity monitoring", "Cloud access logs"],
                "nist_control": "DE.AE-3 — Event data are collected and correlated from multiple sources"
            },
            "Containment": {
                "timeframe": "2–6 hours",
                "steps": [
                    "Revoke access credentials for compromised accounts immediately",
                    "Block exfiltration channels (external email, USB, cloud uploads)",
                    "Isolate affected databases and storage systems",
                    "Preserve all logs — do not alter or delete any evidence",
                    "Engage legal counsel immediately",
                    "Assess notification obligations under GDPR (72 hours), HIPAA (60 days), state laws"
                ],
                "tools": ["IAM platform", "DLP", "Network controls", "Legal hold tools"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "6–72 hours",
                "steps": [
                    "Remove unauthorized access points and backdoors",
                    "Remediate the root cause vulnerability",
                    "Rotate all potentially exposed credentials and API keys",
                    "Audit access controls and permissions on affected systems",
                    "Engage forensics firm for evidence preservation if needed"
                ],
                "tools": ["Vulnerability scanner", "PAM solution", "Forensic tools"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "72 hours – 30 days",
                "steps": [
                    "Restore systems to secure state",
                    "Send breach notification letters to affected individuals",
                    "File regulatory notifications (GDPR supervisory authority, HHS for HIPAA)",
                    "Offer credit monitoring to affected individuals if financial data exposed",
                    "Engage PR team for external communications if public disclosure needed",
                    "Document all remediation steps for regulatory audit trail"
                ],
                "tools": ["Notification management platform", "Regulatory portals", "PR/comms tools"],
                "nist_control": "RC.CO-3 — Recovery activities are communicated to stakeholders"
            },
            "Lessons Learned": {
                "timeframe": "Within 30 days",
                "steps": [
                    "Complete full root cause analysis",
                    "Review data classification and access control policies",
                    "Assess DLP tool coverage gaps",
                    "Update privacy policy and data handling procedures",
                    "Conduct mandatory security awareness training company-wide",
                    "Prepare regulatory compliance documentation"
                ],
                "tools": ["GRC platform", "Training platform", "Policy management"],
                "nist_control": "RC.IM-1 — Recovery plans incorporate lessons learned"
            }
        },
        "iocs": ["Large outbound data transfers", "Access to unusual data repositories", "Credential stuffing patterns", "After-hours access logs"],
        "escalation": {
            "Low": "IT Security team",
            "High": "CISO + Legal + Compliance Officer",
            "Critical": "CEO + Board + Regulatory bodies + Law enforcement"
        },
        "sla": {"detection_to_containment": "6 hours", "full_resolution": "30 days"}
    },

    "insider_threat": {
        "name": "Insider Threat",
        "severity_default": "High",
        "description": "A security risk originating from current or former employees, contractors, or business partners who misuse authorized access to harm the organization.",
        "mitre_tactics": ["Collection (TA0009)", "Exfiltration (TA0010)", "Defense Evasion (TA0005)"],
        "nist_functions": ["Identify", "Detect", "Respond"],
        "phases": {
            "Identification": {
                "timeframe": "0–4 hours",
                "steps": [
                    "Receive alert from DLP, UEBA, or HR tip",
                    "Identify the individual and their access level",
                    "Collect evidence without alerting the suspect",
                    "Review recent data access, downloads, and email activity",
                    "Check for bulk downloads, after-hours access, or policy violations",
                    "Engage HR and Legal before taking any action"
                ],
                "tools": ["UEBA", "DLP", "SIEM", "HR management system"],
                "nist_control": "DE.CM-3 — Personnel activity is monitored to detect potential cybersecurity events"
            },
            "Containment": {
                "timeframe": "4–8 hours (coordinated with HR/Legal)",
                "steps": [
                    "Work with HR and Legal on timing of access revocation",
                    "Preserve all digital evidence before revoking access",
                    "Disable accounts simultaneously across all systems",
                    "Revoke VPN, email, cloud, and physical access badges",
                    "Place legal hold on all data associated with the individual",
                    "Do NOT confront the individual without HR and Legal present"
                ],
                "tools": ["IAM platform", "Physical security system", "Legal hold tools"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "24–72 hours",
                "steps": [
                    "Audit all data accessed and potentially exfiltrated",
                    "Remove any backdoors or unauthorized accounts created",
                    "Review and tighten access controls for similar roles",
                    "Assess if any sensitive data was shared externally",
                    "Coordinate with legal on potential criminal referral"
                ],
                "tools": ["DLP", "SIEM forensics", "Legal"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "1–2 weeks",
                "steps": [
                    "Redistribute critical duties covered by the individual",
                    "Implement need-to-know access review for the affected team",
                    "Notify affected parties if data was shared externally",
                    "Update offboarding procedures to prevent recurrence",
                    "Assess if regulatory notification is required"
                ],
                "tools": ["IAM review", "Compliance platform", "HR systems"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 2 weeks",
                "steps": [
                    "Review effectiveness of UEBA/DLP detection rules",
                    "Assess least-privilege implementation across the organization",
                    "Update insider threat policy and employee agreements",
                    "Improve offboarding checklist and access revocation SLAs",
                    "Brief leadership on insider threat risk posture"
                ],
                "tools": ["GRC platform", "HR policy management", "UEBA tuning"],
                "nist_control": "RC.IM-1 — Recovery plans incorporate lessons learned"
            }
        },
        "iocs": ["Bulk data downloads", "After-hours access", "Access to unrelated systems", "USB usage", "Mass email forwarding"],
        "escalation": {
            "Low": "IT Security + HR",
            "High": "CISO + HR Director + Legal",
            "Critical": "CEO + Legal + Law enforcement"
        },
        "sla": {"detection_to_containment": "8 hours", "full_resolution": "2 weeks"}
    },

    "ddos": {
        "name": "DDoS Attack",
        "severity_default": "High",
        "description": "A Distributed Denial-of-Service attack that floods systems, servers, or networks with traffic to exhaust resources and disrupt legitimate user access.",
        "mitre_tactics": ["Impact (TA0040) — Network Denial of Service (T1498)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0–15 minutes",
                "steps": [
                    "Detect via network monitoring alert or user-reported service outage",
                    "Confirm DDoS vs. legitimate traffic spike or system failure",
                    "Identify attack type: volumetric, protocol, or application-layer",
                    "Identify targeted IP addresses, ports, and services",
                    "Measure attack volume (Gbps/Mpps) and geographic source distribution",
                    "Notify NOC, ISP, and CDN/DDoS mitigation provider"
                ],
                "tools": ["NetFlow analysis", "IDS/IPS", "ISP dashboard", "CDN analytics"],
                "nist_control": "DE.AE-1 — A baseline of network operations is established"
            },
            "Containment": {
                "timeframe": "15 min – 2 hours",
                "steps": [
                    "Engage DDoS mitigation provider (Cloudflare, Akamai, AWS Shield)",
                    "Implement rate limiting at edge routers and load balancers",
                    "Block source IP ranges at upstream ISP level",
                    "Enable anycast traffic scrubbing if available",
                    "Failover to backup infrastructure or CDN if primary is overwhelmed",
                    "Implement CAPTCHA challenges for application-layer attacks"
                ],
                "tools": ["DDoS mitigation service", "WAF", "Load balancer", "ISP BGP controls"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "2–6 hours",
                "steps": [
                    "Fine-tune mitigation rules to reduce false positives on legitimate traffic",
                    "Identify and null-route persistent attacking IPs",
                    "Coordinate with ISP for upstream filtering",
                    "Review and update ACLs on network perimeter devices",
                    "Assess if DDoS was a smokescreen for another attack vector"
                ],
                "tools": ["Network ACLs", "BGP blackholing", "SIEM correlation"],
                "nist_control": "RS.AN-1 — Notifications from detection systems are investigated"
            },
            "Recovery": {
                "timeframe": "6–24 hours",
                "steps": [
                    "Gradually restore traffic once attack subsides",
                    "Verify all services are fully operational",
                    "Monitor for attack resumption for 24 hours",
                    "Communicate service restoration to customers/stakeholders",
                    "Document business impact: downtime duration, affected users, revenue loss"
                ],
                "tools": ["Monitoring dashboard", "Status page", "Customer comms platform"],
                "nist_control": "RC.CO-2 — Reputation is repaired after an incident"
            },
            "Lessons Learned": {
                "timeframe": "Within 1 week",
                "steps": [
                    "Review DDoS protection capacity and thresholds",
                    "Assess infrastructure resilience and redundancy",
                    "Evaluate DDoS mitigation provider SLA performance",
                    "Update network architecture for better attack absorption",
                    "Document attack signatures for future detection tuning"
                ],
                "tools": ["Network architecture review", "SLA review", "Documentation"],
                "nist_control": "RC.IM-2 — Recovery strategies are updated"
            }
        },
        "iocs": ["Abnormal traffic volume spikes", "Traffic from single geographic region", "SYN flood patterns", "HTTP request floods to single endpoint"],
        "escalation": {
            "Low": "NOC team",
            "High": "IT Director + NOC + ISP contact",
            "Critical": "CTO + CISO + ISP escalation + DDoS mitigation vendor"
        },
        "sla": {"detection_to_containment": "2 hours", "full_resolution": "24 hours"}
    },

    "bec": {
        "name": "Business Email Compromise (BEC)",
        "severity_default": "Critical",
        "description": "A sophisticated scam where attackers impersonate executives or vendors via email to trick employees into transferring funds or revealing sensitive information.",
        "mitre_tactics": ["Initial Access (TA0001)", "Collection (TA0009)", "Impact (TA0040) — Financial Theft"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0-2 hours",
                "steps": [
                    "Receive alert or employee report of suspicious executive/vendor email",
                    "Verify whether a fraudulent wire transfer or payment has already been made",
                    "Examine email headers to confirm spoofed domain or lookalike address",
                    "Identify all employees who received or acted on the suspicious email",
                    "Determine if attacker had actual mailbox access or only spoofed the address",
                    "Assess total financial exposure — amount requested or transferred"
                ],
                "tools": ["Email gateway logs", "SIEM", "Email header analyzer", "Finance system logs"],
                "nist_control": "DE.AE-2 — Detected events are analyzed to understand attack targets and methods"
            },
            "Containment": {
                "timeframe": "2-4 hours",
                "steps": [
                    "IMMEDIATELY contact the bank to recall or freeze any fraudulent wire transfer",
                    "Block the spoofed sender domain at the email gateway",
                    "Reset credentials for any compromised accounts",
                    "Enable MFA on all email accounts if not already enforced",
                    "Quarantine all emails from the attacker domain across all mailboxes",
                    "Notify finance and accounting teams to halt pending transactions"
                ],
                "tools": ["Email admin console", "Banking portal", "Active Directory", "MFA platform"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "4-24 hours",
                "steps": [
                    "Audit all email forwarding rules added to compromised mailboxes",
                    "Remove any malicious inbox rules created by the attacker",
                    "Review OAuth application permissions granted to third-party apps",
                    "Check for lookalike domains registered by attacker",
                    "Implement DMARC, DKIM, and SPF records if not already in place",
                    "Review and tighten wire transfer approval procedures"
                ],
                "tools": ["Email admin console", "DNS management", "DMARC analyzer"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "24 hours - 2 weeks",
                "steps": [
                    "Work with bank and FBI IC3 to attempt fund recovery",
                    "File a complaint with FBI Internet Crime Complaint Center (IC3)",
                    "Notify cyber insurance carrier to initiate financial fraud claim",
                    "Implement dual-approval process for all wire transfers above threshold",
                    "Deploy anti-spoofing email controls (DMARC enforcement)"
                ],
                "tools": ["FBI IC3 portal", "Cyber insurance portal", "Email security platform"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 1 week",
                "steps": [
                    "Implement mandatory out-of-band verification for wire transfer requests",
                    "Run targeted BEC awareness training for finance and executive assistants",
                    "Review vendor payment change request procedures",
                    "Assess DMARC/DKIM/SPF implementation across all company domains"
                ],
                "tools": ["GRC platform", "Security awareness training", "Email security tools"],
                "nist_control": "RC.IM-1 — Recovery plans incorporate lessons learned"
            }
        },
        "iocs": ["Lookalike or spoofed executive email domain", "Urgent wire transfer requests via email", "Requests to change vendor payment bank details", "Emails asking to keep transaction confidential", "Email forwarding rules to external addresses"],
        "escalation": {
            "Low": "IT Security + Finance Manager",
            "High": "CISO + CFO + Legal",
            "Critical": "CEO + CFO + Legal + FBI IC3 + Cyber Insurance Carrier"
        },
        "sla": {"detection_to_containment": "4 hours", "full_resolution": "2 weeks"}
    },

    "sql_injection": {
        "name": "SQL Injection Attack",
        "severity_default": "High",
        "description": "An attack where malicious SQL code is inserted into input fields to manipulate backend databases, enabling unauthorized data access, modification, or deletion.",
        "mitre_tactics": ["Initial Access (TA0001) — Exploit Public-Facing Application (T1190)", "Collection (TA0009)", "Exfiltration (TA0010)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0-2 hours",
                "steps": [
                    "Detect via WAF alert, IDS alert, or anomalous database query logs",
                    "Identify the affected web application and vulnerable parameter(s)",
                    "Review web server and database logs for malicious SQL patterns",
                    "Determine attack type: in-band, blind, or out-of-band SQL injection",
                    "Assess what data may have been accessed or exfiltrated",
                    "Identify whether attacker achieved database admin (DBA) privileges"
                ],
                "tools": ["WAF logs", "Web server logs", "Database activity monitor", "SIEM"],
                "nist_control": "DE.CM-7 — Monitoring for unauthorized connections and software is performed"
            },
            "Containment": {
                "timeframe": "2-6 hours",
                "steps": [
                    "Block attacker IP addresses at WAF and firewall immediately",
                    "Take the vulnerable application offline if data exfiltration is confirmed",
                    "Enable WAF blocking rules for SQL injection patterns",
                    "Disable the vulnerable database account or restrict its permissions",
                    "Preserve all web server, application, and database logs as evidence"
                ],
                "tools": ["WAF", "Firewall", "Database admin console"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "6-72 hours",
                "steps": [
                    "Identify all vulnerable input parameters using DAST scanning tools",
                    "Patch vulnerable code — implement parameterized queries / prepared statements",
                    "Remove any web shells or backdoors planted during the attack",
                    "Audit database for unauthorized stored procedures or triggers",
                    "Review and rotate all database credentials"
                ],
                "tools": ["OWASP ZAP", "Burp Suite", "Code review tools", "Database auditing"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "72 hours - 1 week",
                "steps": [
                    "Restore database from last known clean backup if data was modified",
                    "Redeploy patched application with parameterized queries enforced",
                    "Enable enhanced database auditing and query logging going forward",
                    "Notify affected users if their personal data was compromised"
                ],
                "tools": ["Database backup system", "Application deployment pipeline"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 1 week",
                "steps": [
                    "Conduct full code review of all web application input handling",
                    "Implement mandatory input validation and output encoding standards",
                    "Integrate SAST/DAST scanning into CI/CD pipeline",
                    "Schedule developer secure coding training (OWASP Top 10)"
                ],
                "tools": ["SAST tools", "DAST tools", "Developer training platform"],
                "nist_control": "RC.IM-1 — Recovery plans incorporate lessons learned"
            }
        },
        "iocs": ["SQL keywords in URL parameters (SELECT, UNION, DROP)", "Unusual database error messages in HTTP responses", "Abnormally large database query volumes from single IP", "WAF alerts for SQL injection patterns", "Unexpected outbound data transfers from database server"],
        "escalation": {
            "Low": "Application Security team",
            "High": "CISO + Development Lead + Database Admin",
            "Critical": "CISO + Legal + Compliance Officer (if PII exposed)"
        },
        "sla": {"detection_to_containment": "6 hours", "full_resolution": "1 week"}
    },

    "privilege_escalation": {
        "name": "Privilege Escalation",
        "severity_default": "High",
        "description": "An attack where a threat actor gains higher-level permissions than granted, moving from standard user to admin or domain admin, enabling broader system compromise.",
        "mitre_tactics": ["Privilege Escalation (TA0004)", "Defense Evasion (TA0005)", "Lateral Movement (TA0008)"],
        "nist_functions": ["Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0-2 hours",
                "steps": [
                    "Detect via SIEM alert on privileged account anomaly or EDR behavioral alert",
                    "Identify the affected account and originating system",
                    "Determine escalation path: local admin, domain admin, or service account",
                    "Review authentication logs for unusual privilege use or sudo/runas events",
                    "Identify the technique used (kernel exploit, misconfiguration, token impersonation)",
                    "Assess how long the attacker has had elevated privileges"
                ],
                "tools": ["SIEM", "EDR", "Active Directory audit logs", "PAM solution"],
                "nist_control": "DE.AE-2 — Detected events are analyzed to understand attack targets"
            },
            "Containment": {
                "timeframe": "2-6 hours",
                "steps": [
                    "Immediately revoke elevated privileges from the compromised account",
                    "Disable the affected account pending investigation",
                    "Isolate affected endpoints from the network",
                    "Invalidate all active sessions and Kerberos tickets for compromised accounts",
                    "Notify Active Directory / IAM team for enterprise-wide credential audit"
                ],
                "tools": ["Active Directory", "PAM solution", "EDR", "Network access controls"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "6-48 hours",
                "steps": [
                    "Patch the vulnerability or misconfiguration that enabled the escalation",
                    "Remove any persistence mechanisms (scheduled tasks, registry keys, new admin accounts)",
                    "Rotate credentials for ALL privileged accounts enterprise-wide",
                    "Audit group memberships — remove unauthorized additions to privileged groups",
                    "Run EDR full scan on affected systems to detect secondary payloads"
                ],
                "tools": ["Patch management", "EDR", "Active Directory", "Vulnerability scanner"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "48 hours - 1 week",
                "steps": [
                    "Rebuild compromised systems from clean images if persistence is suspected",
                    "Re-enable accounts with correct privilege levels after credential reset",
                    "Implement just-in-time (JIT) privileged access if not already in place",
                    "Monitor all privileged accounts intensively for 14 days post-incident"
                ],
                "tools": ["System imaging tools", "PAM solution", "SIEM monitoring"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 2 weeks",
                "steps": [
                    "Conduct privileged access audit across entire environment",
                    "Implement principle of least privilege review for all accounts",
                    "Deploy or tune PAM (Privileged Access Management) solution",
                    "Update detection rules for common techniques (Pass-the-Hash, Kerberoasting)"
                ],
                "tools": ["PAM platform", "Vulnerability management", "SIEM rule editor"],
                "nist_control": "RC.IM-2 — Recovery strategies are updated"
            }
        },
        "iocs": ["Unexpected admin group membership changes in Active Directory", "Privileged process spawned from unprivileged parent", "Unusual use of runas or sudo", "New local administrator accounts created", "Kerberoasting or Pass-the-Hash patterns in authentication logs"],
        "escalation": {
            "Low": "IT Security team",
            "High": "CISO + Active Directory team + SOC Lead",
            "Critical": "CISO + CTO + Legal (if domain admin compromised)"
        },
        "sla": {"detection_to_containment": "6 hours", "full_resolution": "1 week"}
    },

    "supply_chain": {
        "name": "Supply Chain Attack",
        "severity_default": "Critical",
        "description": "An attack targeting software vendors or third-party libraries to compromise downstream organizations. Notable examples: SolarWinds (2020), XZ Utils backdoor (2024).",
        "mitre_tactics": ["Initial Access (TA0001) — Trusted Relationship (T1199)", "Execution (TA0002)", "Persistence (TA0003)"],
        "nist_functions": ["Identify", "Detect", "Respond", "Recover"],
        "phases": {
            "Identification": {
                "timeframe": "0-4 hours",
                "steps": [
                    "Receive threat intelligence alert or vendor breach notification",
                    "Identify all instances of the compromised software in your environment",
                    "Determine the version range affected and whether your version is impacted",
                    "Review network traffic from systems running the compromised software",
                    "Check for known IOCs published by threat intel sources",
                    "Assess the blast radius — how many systems and services are potentially affected"
                ],
                "tools": ["Asset inventory / CMDB", "Threat intel platform", "SIEM", "Vulnerability scanner"],
                "nist_control": "ID.SC-4 — Suppliers and third-party partners are routinely assessed"
            },
            "Containment": {
                "timeframe": "4-24 hours",
                "steps": [
                    "Isolate or take offline all systems running the compromised software version",
                    "Block known malicious C2 IP addresses and domains at firewall",
                    "Revoke API keys and credentials that the compromised software had access to",
                    "Restrict network egress from affected systems to prevent data exfiltration",
                    "Do not update to vendor patch until it has been verified as clean"
                ],
                "tools": ["Firewall", "Network controls", "IAM platform", "EDR"],
                "nist_control": "RS.MI-1 — Incidents are contained"
            },
            "Eradication": {
                "timeframe": "24-72 hours",
                "steps": [
                    "Remove or replace the compromised software with a verified clean version",
                    "Conduct forensic analysis to determine if backdoor was activated",
                    "Hunt for persistence mechanisms installed by the compromised software",
                    "Rotate all credentials, API keys, and certificates on affected systems",
                    "Scan all systems for additional IOCs from threat intelligence feeds"
                ],
                "tools": ["EDR", "Forensic tools", "Threat intel platform", "Credential management"],
                "nist_control": "RS.MI-2 — Incidents are mitigated"
            },
            "Recovery": {
                "timeframe": "72 hours - 4 weeks",
                "steps": [
                    "Rebuild affected systems from pre-compromise clean images",
                    "Verify integrity of all software using hash validation",
                    "Assess regulatory notification requirements if customer data was exposed",
                    "Implement software composition analysis (SCA) scanning in build pipeline"
                ],
                "tools": ["System imaging", "SCA tools", "Compliance platform", "SIEM"],
                "nist_control": "RC.RP-1 — Recovery plan is executed"
            },
            "Lessons Learned": {
                "timeframe": "Within 4 weeks",
                "steps": [
                    "Conduct full third-party vendor risk assessment",
                    "Implement software bill of materials (SBOM) tracking",
                    "Add supply chain scenarios to IR tabletop exercise program",
                    "Implement network segmentation to limit vendor software blast radius"
                ],
                "tools": ["GRC platform", "SBOM tools", "Vendor risk management platform"],
                "nist_control": "RC.IM-2 — Recovery strategies are updated"
            }
        },
        "iocs": ["Anomalous outbound connections from trusted software processes", "Known malicious C2 domains in network logs", "Unexpected software update activity outside change windows", "File hashes matching known compromised library versions"],
        "escalation": {
            "Low": "IT Security + Vendor Management team",
            "High": "CISO + CTO + Legal + Vendor escalation",
            "Critical": "CEO + Board + Legal + Regulatory bodies + Law enforcement"
        },
        "sla": {"detection_to_containment": "24 hours", "full_resolution": "4 weeks"}
    }
}
