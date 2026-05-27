"""
Incident Response Playbook Generator
playbook_generator.py — Core logic for generating structured IR playbooks
"""

from datetime import datetime
from incident_data import INCIDENTS


def get_available_incidents():
    """Return list of available incident types."""
    return list(INCIDENTS.keys())


def generate_playbook(incident_type: str, org_name: str, analyst_name: str, severity: str = None) -> dict:
    """
    Generate a full IR playbook for a given incident type.

    Args:
        incident_type: Key from INCIDENTS dict (e.g. 'phishing')
        org_name: Organization name for the report header
        analyst_name: Analyst generating the playbook
        severity: Override default severity (Low/Medium/High/Critical)

    Returns:
        dict: Structured playbook data
    """
    if incident_type not in INCIDENTS:
        raise ValueError(f"Unknown incident type: '{incident_type}'. "
                         f"Available types: {', '.join(get_available_incidents())}")

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
        "summary": _build_summary(incident, severity)
    }

    return playbook


def _build_summary(incident: dict, severity: str) -> dict:
    """Build executive summary section."""
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
    """Print a formatted text version of the playbook to console."""
    meta = playbook["metadata"]
    inc = playbook["incident"]
    summary = playbook["summary"]

    divider = "=" * 70
    thin = "-" * 70

    print(f"\n{divider}")
    print(f"  {meta['title'].upper()}")
    print(f"  Organization : {meta['org_name']}")
    print(f"  Analyst      : {meta['analyst']}")
    print(f"  Generated    : {meta['generated_at']}")
    print(f"  Severity     : {inc['severity']}")
    print(divider)

    print(f"\n📋 INCIDENT OVERVIEW")
    print(thin)
    print(f"Description  : {inc['description']}")
    print(f"MITRE Tactics: {', '.join(inc['mitre_tactics'])}")
    print(f"NIST Functions: {', '.join(inc['nist_functions'])}")

    print(f"\n⏱️  SLA TARGETS")
    print(f"  Detection → Containment : {inc['sla']['detection_to_containment']}")
    print(f"  Full Resolution         : {inc['sla']['full_resolution']}")

    print(f"\n🚨 ESCALATION PATH ({inc['severity']} Severity)")
    print(f"  {summary['escalation_path']}")

    print(f"\n🔍 INDICATORS OF COMPROMISE (IOCs)")
    for ioc in inc["iocs"]:
        print(f"  • {ioc}")

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
