"""
Incident Response Playbook Generator
main.py — CLI entry point
"""

import argparse
import sys
import os
from playbook_generator import generate_playbook, get_available_incidents, print_playbook_text
from report_generator import generate_pdf


def main():
    parser = argparse.ArgumentParser(
        description="IR Playbook Generator — Generate structured incident response playbooks",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--incident", "-i",
        type=str,
        help=f"Incident type. Available: {', '.join(get_available_incidents())}"
    )
    parser.add_argument(
        "--org", "-o",
        type=str,
        default="ACME Corporation",
        help="Organization name (default: ACME Corporation)"
    )
    parser.add_argument(
        "--analyst", "-a",
        type=str,
        default="Security Analyst",
        help="Analyst name (default: Security Analyst)"
    )
    parser.add_argument(
        "--severity", "-s",
        type=str,
        choices=["Low", "Medium", "High", "Critical"],
        help="Override default severity level"
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Export playbook as a PDF report"
    )
    parser.add_argument(
        "--output", "-out",
        type=str,
        help="Output path for PDF (default: auto-generated filename)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available incident types"
    )

    args = parser.parse_args()

    if args.list:
        print("\n📋 Available Incident Types:")
        for key in get_available_incidents():
            print(f"  • {key}")
        print()
        return

    if not args.incident:
        print("\n⚠️  Please specify an incident type with --incident")
        print(f"Available: {', '.join(get_available_incidents())}")
        print("\nExample usage:")
        print("  python main.py --incident phishing --org 'Acme Corp' --analyst 'Jane Doe' --pdf")
        print("  python main.py --incident ransomware --severity Critical --pdf")
        print("  python main.py --list\n")
        sys.exit(1)

    try:
        playbook = generate_playbook(
            incident_type=args.incident,
            org_name=args.org,
            analyst_name=args.analyst,
            severity=args.severity
        )
    except ValueError as e:
        print(f"\n❌ Error: {e}\n")
        sys.exit(1)

    # Always print text version
    print_playbook_text(playbook)

    # Optionally generate PDF
    if args.pdf:
        try:
            output_path = generate_pdf(playbook, args.output)
            print(f"✅ PDF report saved: {output_path}\n")
        except ImportError:
            print("⚠️  fpdf2 not installed. Run: pip install fpdf2")
        except Exception as e:
            print(f"❌ PDF generation failed: {e}")


if __name__ == "__main__":
    main()
