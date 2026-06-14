"""
scripts/run_scheduled_report.py - Entry point for Task Scheduler.

Được gọi bởi Windows Task Scheduler. KHÔNG dùng trực tiếp từ CLI.

Cách dùng:
    python run_scheduled_report.py --id <schedule_id>
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path để import scheduler modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from scheduler.job_runner import run_job


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Execute scheduled report job (Task Scheduler only)"
    )
    parser.add_argument("--id", type=int, required=True, help="Schedule ID")
    args = parser.parse_args()

    result = run_job(args.id)

    # Exit with code 0 for success, 1 for failure
    exit_code = 0 if result.get("success") else 1

    # Print result for logging (Task Scheduler captures stdout)
    if result.get("success"):
        print(f"[OK] Schedule {args.id} completed. Report: {result.get('report_path')}")
    else:
        print(f"[FAILED] Schedule {args.id} error: {result.get('error')}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
