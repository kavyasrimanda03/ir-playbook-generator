"""
Incident Response Playbook Generator
main.py — CLI entry point
"""

import argparse
import sys
from playbook_generator import generate_playbook, get_available_incidents, print_playbook_text
from report_generator import generate_pdf
from severity_calculator import calculate_severity
from log_scanner import scan_logs, generate_sample_logs, extract_smart_sample


def main():
    parser = argparse.ArgumentParser(
        description="IR Playbook Generator — Incident response automation tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--incident", "-i", type=str,
        help=f"Incident type. Available: {', '.join(get_available_incidents())}")
    parser.add_argument("--org", "-o", type=str, default="ACME Corporation",
        help="Organization name")
    parser.add_argument("--analyst", "-a", type=str, default="Security Analyst",
        help="Analyst name")
    parser.add_argument("--severity", "-s", type=str,
        choices=["Low", "Medium", "High", "Critical"],
        help="Manually override severity (skips calculator)")
    parser.add_argument("--assess", action="store_true",
        help="Run the interactive severity assessment calculator")
    parser.add_argument("--scan", type=str, metavar="LOG_FILE",
        help="Scan a log file for IOC patterns (CSV, TXT, or JSON)")
    parser.add_argument("--sample-from", type=str, metavar="LARGE_LOG_FILE",
        help="Extract a smart sample from a large log file, then scan it")
    parser.add_argument("--sample-logs", action="store_true",
        help="Generate built-in synthetic sample log for the incident type")
    parser.add_argument("--pdf", action="store_true",
        help="Export playbook as a PDF report")
    parser.add_argument("--output", "-out", type=str,
        help="Output path for PDF")
    parser.add_argument("--list", action="store_true",
        help="List all available incident types")

    args = parser.parse_args()

    # ── LIST ──────────────────────────────────────────────────────────────
    if args.list:
        print("\nAvailable Incident Types:")
        for key in get_available_incidents():
            print(f"  - {key}")
        print()
        return

    if not args.incident:
        print("\n" + "="*60)
        print("  IR PLAYBOOK GENERATOR — Usage Examples")
        print("="*60)
        print("\n  Basic playbook:")
        print("  python main.py --incident phishing --org 'Acme' --analyst 'Jane'")
        print("\n  With severity calculator:")
        print("  python main.py --incident ransomware --assess --pdf")
        print("\n  Scan built-in sample logs:")
        print("  python main.py --incident phishing --sample-logs")
        print("  python main.py --incident phishing --scan sample_logs.csv --pdf")
        print("\n  Scan your own log file directly:")
        print("  python main.py --incident sql_injection --scan myfile.txt --pdf")
        print("\n  Use a large real dataset (auto-extracts smart sample):")
        print("  python main.py --incident sql_injection --sample-from access.log --pdf")
        print("\n  List all incident types:")
        print("  python main.py --list\n")
        sys.exit(1)

    # ── SYNTHETIC SAMPLE LOG GENERATION ──────────────────────────────────
    if args.sample_logs:
        generate_sample_logs(args.incident)
        print(f"  Now run:")
        print(f"  python main.py --incident {args.incident} --scan sample_logs.csv --pdf\n")
        return

    # ── SMART SAMPLE FROM LARGE FILE ─────────────────────────────────────
    scan_file = args.scan
    if args.sample_from:
        sample_output = f"sample_{args.incident}_from_dataset.txt"
        scan_file = extract_smart_sample(args.sample_from, sample_output)

    # ── LOG SCANNER ───────────────────────────────────────────────────────
    scan_result = None
    if scan_file:
        scan_result = scan_logs(scan_file, args.incident)

    # ── SEVERITY ──────────────────────────────────────────────────────────
    calc_result = None
    severity    = args.severity

    if args.assess:
        calc_result = calculate_severity(args.incident)
        severity    = calc_result["severity"]
        print(f"  >> Severity calculated: {severity} — generating playbook...\n")
    elif not severity:
        print("\nNo severity specified.")
        print("  1. Run interactive severity assessment (recommended)")
        print("  2. Use default severity for this incident type")
        choice = input("  -> Enter 1 or 2: ").strip()
        if choice == "1":
            calc_result = calculate_severity(args.incident)
            severity    = calc_result["severity"]
            print(f"  >> Severity calculated: {severity} — generating playbook...\n")

    # ── GENERATE PLAYBOOK ─────────────────────────────────────────────────
    try:
        playbook = generate_playbook(
            incident_type=args.incident,
            org_name=args.org,
            analyst_name=args.analyst,
            severity=severity,
            calc_result=calc_result,
            scan_result=scan_result
        )
    except ValueError as e:
        print(f"\nError: {e}\n")
        sys.exit(1)

    print_playbook_text(playbook)

    # ── PDF ───────────────────────────────────────────────────────────────
    if args.pdf:
        try:
            output_path = generate_pdf(playbook, args.output)
            print(f"PDF report saved: {output_path}\n")
        except Exception as e:
            print(f"PDF generation failed: {e}")


if __name__ == "__main__":
    main()
