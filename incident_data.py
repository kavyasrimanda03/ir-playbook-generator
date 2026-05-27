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
    }
}
