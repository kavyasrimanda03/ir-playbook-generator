"""
Incident Response Playbook Generator
severity_calculator.py — Dynamically calculates incident severity
based on environmental and contextual factors
"""

FACTORS = [
    {
        "id": "attack_active",
        "question": "Is the attack currently active / still ongoing?",
        "options": {"yes": 20, "no": 0},
        "risk_label": "Active ongoing attack (+20)"
    },
    {
        "id": "internet_facing",
        "question": "Is the affected system internet-facing (publicly accessible)?",
        "options": {"yes": 15, "no": 0},
        "risk_label": "Internet-facing system (+15)"
    },
    {
        "id": "sensitive_data",
        "question": "Does the affected system store sensitive data? (PII, PHI, financial, credentials)",
        "options": {"yes": 20, "no": 5, "unknown": 10},
        "risk_label": "Sensitive data at risk (+20)"
    },
    {
        "id": "systems_affected",
        "question": "How many systems are affected?",
        "options": {"1": 5, "2-10": 10, "11-50": 15, "50+": 20},
        "risk_label": "Large number of systems affected (+15-20)"
    },
    {
        "id": "privileged_account",
        "question": "Is a privileged or admin account involved or compromised?",
        "options": {"yes": 15, "no": 0, "unknown": 8},
        "risk_label": "Privileged account compromised (+15)"
    },
    {
        "id": "business_impact",
        "question": "Is there currently a business/operational impact? (downtime, service disruption)",
        "options": {"yes": 10, "no": 0},
        "risk_label": "Active business impact (+10)"
    },
    {
        "id": "data_exfiltrated",
        "question": "Is there evidence that data has already been exfiltrated or encrypted?",
        "options": {"yes": 15, "no": 0, "unknown": 5},
        "risk_label": "Confirmed data exfiltration/encryption (+15)"
    },
    {
        "id": "detection_source",
        "question": "How was the incident detected?",
        "options": {
            "automated alert (SIEM/EDR)": 0,
            "user report": 3,
            "external notification (3rd party/law enforcement)": 8,
            "unknown": 5
        },
        "risk_label": "Late/external detection (+5-8)"
    },
]

SEVERITY_THRESHOLDS = [
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0,  "Low"),
]

SEVERITY_COLORS_CLI = {
    "Critical": "\033[91m",
    "High":     "\033[93m",
    "Medium":   "\033[94m",
    "Low":      "\033[92m",
}
RESET = "\033[0m"


def _ask(question: str, options: dict) -> str:
    keys = list(options.keys())
    print(f"\n  ? {question}")
    for i, key in enumerate(keys, 1):
        print(f"     {i}. {key}")
    while True:
        try:
            raw = input("     -> Enter number: ").strip()
            idx = int(raw) - 1
            if 0 <= idx < len(keys):
                chosen = keys[idx]
                print(f"     OK: {chosen}")
                return chosen
            else:
                print(f"     Please enter a number between 1 and {len(keys)}")
        except ValueError:
            print("     Please enter a valid number")


def calculate_severity(incident_type: str) -> dict:
    print("\n" + "=" * 60)
    print("  SEVERITY ASSESSMENT CALCULATOR")
    print(f"  Incident Type: {incident_type.replace('_', ' ').title()}")
    print("=" * 60)
    print("  Answer the following questions about this incident.\n")

    score = 0
    breakdown = []
    risk_factors_hit = []

    for factor in FACTORS:
        chosen = _ask(factor["question"], factor["options"])
        points = factor["options"][chosen]
        score += points
        breakdown.append({
            "question": factor["question"],
            "answer": chosen,
            "points": points
        })
        if points >= 10:
            risk_factors_hit.append(factor["risk_label"])

    score = min(score, 100)
    percentage = round((score / 100) * 100)

    severity = "Low"
    for threshold, level in SEVERITY_THRESHOLDS:
        if score >= threshold:
            severity = level
            break

    recommendations = _build_recommendations(breakdown, severity)

    result = {
        "score": score,
        "max_score": 100,
        "percentage": percentage,
        "severity": severity,
        "breakdown": breakdown,
        "top_risk_factors": risk_factors_hit if risk_factors_hit else ["No critical risk factors identified"],
        "recommendations": recommendations
    }

    _print_result(result)
    return result


def _build_recommendations(breakdown: list, severity: str) -> list:
    recs = []
    answers = {item["question"]: item["answer"] for item in breakdown}

    if answers.get("Is the attack currently active / still ongoing?") == "yes":
        recs.append("IMMEDIATE: Activate IR team now — attack is still active")
    if answers.get("Is a privileged or admin account involved or compromised?") in ["yes", "unknown"]:
        recs.append("Reset all privileged credentials immediately")
    if answers.get("Does the affected system store sensitive data? (PII, PHI, financial, credentials)") in ["yes", "unknown"]:
        recs.append("Assess regulatory notification obligations (GDPR 72hr / HIPAA 60 day)")
    if answers.get("Is there evidence that data has already been exfiltrated or encrypted?") == "yes":
        recs.append("Preserve all logs and engage legal counsel — breach notification may be required")
    if answers.get("How was the incident detected?") in ["external notification (3rd party/law enforcement)", "unknown"]:
        recs.append("Review detection gaps — incident was not caught by internal monitoring")
    if answers.get("How many systems are affected?") in ["11-50", "50+"]:
        recs.append("Assess lateral movement — large number of systems affected")
    if severity == "Critical":
        recs.append("Escalate to CISO and executive leadership immediately")
    elif severity == "High":
        recs.append("Notify IT Security Manager and begin formal IR process")

    return recs if recs else ["Follow standard IR procedures for this incident type"]


def _print_result(result: dict):
    color = SEVERITY_COLORS_CLI.get(result["severity"], "")
    divider = "-" * 60
    print(f"\n{divider}")
    print(f"  SEVERITY ASSESSMENT RESULT")
    print(divider)
    print(f"  Score    : {result['score']} / {result['max_score']} ({result['percentage']}%)")
    print(f"  Severity : {color}{result['severity'].upper()}{RESET}")
    print(divider)
    if result["top_risk_factors"]:
        print(f"\n  Top Risk Factors Identified:")
        for factor in result["top_risk_factors"]:
            print(f"    - {factor}")
    if result["recommendations"]:
        print(f"\n  Immediate Recommendations:")
        for rec in result["recommendations"]:
            print(f"    > {rec}")
    print(f"\n{divider}\n")
