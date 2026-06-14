"""
scheduler/job_runner.py - Execute scheduled report jobs.
"""

from datetime import datetime
from typing import Optional
from auth import AuthDB, get_auth_service
from tools.nvd_client import fetch_nvd_cves
from tools.report_generator import generate_report


def run_job(schedule_id: int) -> dict:
    """Chạy một scheduled job.

    Args:
        schedule_id: ID của schedule từ auth.db

    Returns:
        Dict với {success, schedule_id, status, report_path, cve_count, error}
    """
    db = AuthDB("data/auth.db")
    run_id = None

    try:
        # Lấy schedule config
        schedule = db.get_schedule(schedule_id)
        if not schedule:
            return {"success": False, "error": f"Schedule {schedule_id} not found"}

        # Tạo record trong schedule_runs
        run_id = db.create_schedule_run(schedule_id)

        # Fetch CVE từ NVD (1 ngày gần đây)
        nvd_result = fetch_nvd_cves(
            keyword="",
            severity=schedule.severity_filter,
            days_back=1
        )

        cves = nvd_result.get("context", [])
        cve_count = len(cves)

        # Generate report
        state = {"collected_cves": cves, "collected_indicators": []}

        report_path = generate_report(
            report_type="daily_cve_digest",
            title=f"Daily CVE Digest - {datetime.utcnow().strftime('%Y-%m-%d')}",
            state=state,
            export_format="html"
        )

        # Update schedule run record
        db.update_schedule_run(run_id, "success", cve_count, report_path, None)

        # Update schedule last_run
        db.update_schedule_status(schedule_id, datetime.utcnow(), "success")

        # Audit log
        db.add_audit_entry(0, "schedule_run", f"schedule_id={schedule_id}")

        return {
            "success": True,
            "schedule_id": schedule_id,
            "status": "success",
            "report_path": report_path,
            "cve_count": cve_count
        }

    except Exception as e:
        # Update schedule run with error
        if run_id:
            db.update_schedule_run(run_id, "failed", None, None, str(e))
            db.update_schedule_status(schedule_id, datetime.utcnow(), "failed")

        return {
            "success": False,
            "schedule_id": schedule_id,
            "status": "failed",
            "error": str(e)
        }
