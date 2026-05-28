"""
Incident Response Playbook Generator
playbook_generator.py — Core logic for generating structured IR playbooks
"""

from datetime import datetime
from incident_data import INCIDENTS


def get_available_incidents():
    return list(INCIDENTS.keys())


def generate_playbook(incident_type: str, org_name: str, analyst_name: str,
                      severity: str = None, calc_result: dict = None,
                      scan_result: dict = None) -> dict:
    if incident_type not in INCIDENTS:
        raise ValueError(f"Unknown incident type: '{incident_type}'. "
                         f"Available: {', '.join(get_available_incidents())}")

    incident = INCIDENTS[incident_type]
    severity = severity or incident["severity_default"]

    playbook = {
        "metadata": {
            "title": f"Incident Response Playbook — {incident['name']}",
            "org_name": org_name,
            "analyst": analyst_name,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "incident_type": incident_type,
            "severity": severity,
            "version": "1.0"
        },
        "incident": {
            "name": incident["name"],
            "description": incident["description"],
            "severity": severity,
            "mitre_tactics": incident["mitre_tactics"],
            "nist_functions": incident["nist_functions"],
            "iocs": incident["iocs"],
            "sla": incident["sla"],
            "escalation": incident["escalation"]
        },
        "phases": incident["phases"],
        "summary": _build_summary(incident, severity),
        "severity_assessment": calc_result,
        "scan_result": scan_result
    }

    return playbook


def _build_summary(incident: dict, severity: str) -> dict:
    total_steps = sum(len(p["steps"]) for p in incident["phases"].values())
    return {
        "total_phases": len(incident["phases"]),
        "total_steps": total_steps,
        "severity": severity,
        "escalation_path": incident["escalation"].get(severity, incident["escalation"].get("High")),
        "sla_containment": incident["sla"]["detection_to_containment"],
        "sla_resolution": incident["sla"]["full_resolution"]
    }


def print_playbook_text(playbook: dict):
    meta = playbook["metadata"]
    inc = playbook["incident"]
    summary = playbook["summary"]
    assessment = playbook.get("severity_assessment")

    divider = "=" * 70
    thin = "-" * 70

    print(f"\n{divider}")
    print(f"  {meta['title'].upper()}")
    print(f"  Organization : {meta['org_name']}")
    print(f"  Analyst      : {meta['analyst']}")
    print(f"  Generated    : {meta['generated_at']}")
    print(f"  Severity     : {inc['severity']}")
    print(divider)

    # Show calculator result if used
    if assessment:
        print(f"\n📊 SEVERITY ASSESSMENT SUMMARY")
        print(thin)
        print(f"  Score    : {assessment['score']} / {assessment['max_score']} ({assessment['percentage']}%)")
        print(f"  Result   : {assessment['severity']}")
        print(f"  Top Risk Factors:")
        for r in assessment["top_risk_factors"]:
            print(f"    • {r}")

    print(f"\n📋 INCIDENT OVERVIEW")
    print(thin)
    print(f"Description   : {inc['description']}")
    print(f"MITRE Tactics : {', '.join(inc['mitre_tactics'])}")
    print(f"NIST Functions: {', '.join(inc['nist_functions'])}")

    print(f"\n⏱️  SLA TARGETS")
    print(f"  Detection → Containment : {inc['sla']['detection_to_containment']}")
    print(f"  Full Resolution         : {inc['sla']['full_resolution']}")

    print(f"\n🚨 ESCALATION PATH ({inc['severity']} Severity)")
    print(f"  {summary['escalation_path']}")

    print(f"\n🔍 INDICATORS OF COMPROMISE (IOCs)")
    for ioc in inc["iocs"]:
        print(f"  • {ioc}")

    # Log scan results
    scan = playbook.get("scan_result")
    if scan:
        print(f"\n🔎 LOG SCAN SUMMARY")
        print(thin)
        print(f"  File          : {scan['file']}")
        print(f"  Lines Scanned : {scan['lines_scanned']}")
        print(f"  IOCs Found    : {scan['total_findings']}")
        print(f"  Risk Score    : {scan['risk_score']} / 100  ({scan['risk_level']})")
        if scan["matched_incident_types"]:
            print(f"  Attack Types  : {', '.join(scan['matched_incident_types'])}")
        if scan["findings"]:
            print(f"\n  Top Findings:")
            for f in scan["findings"][:5]:
                print(f"    [{f['severity']}] {f['description']} (Line {f['line_number']})")

    print(f"\n📌 RESPONSE PHASES ({summary['total_phases']} phases | {summary['total_steps']} total steps)")
    print(thin)

    for phase_name, phase_data in playbook["phases"].items():
        print(f"\n▶  PHASE: {phase_name.upper()}  [{phase_data['timeframe']}]")
        print(f"   NIST Control: {phase_data['nist_control']}")
        print(f"   Tools: {', '.join(phase_data['tools'])}")
        print(f"   Steps:")
        for i, step in enumerate(phase_data["steps"], 1):
            print(f"     {i}. {step}")

    print(f"\n{divider}")
    print(f"  END OF PLAYBOOK — {meta['title']}")
    print(f"{divider}\n")
