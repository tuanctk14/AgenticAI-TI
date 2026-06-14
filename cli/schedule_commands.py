"""
cli/schedule_commands.py - CLI commands cho schedule management (admin only).
"""

from datetime import datetime
from typing import Optional
from auth import AuthDB, Role, get_auth_service
from scheduler.os_adapter import WindowsScheduler
from .permission import require_role


@require_role(Role.ADMIN)
def cmd_schedule_add(db: AuthDB, name: str, time_of_day: str, severity_filter: str = "HIGH") -> bool:
    """Tạo schedule mới và register với Task Scheduler."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    try:
        # Validate time format HH:MM
        parts = time_of_day.split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            print("[LỖI] Thời gian phải là HH:MM (24h)")
            return False

        hour, minute = int(parts[0]), int(parts[1])
        if not (0 <= hour < 24 and 0 <= minute < 60):
            print("[LỖI] Thời gian không hợp lệ")
            return False

        # Tạo schedule trong DB
        schedule_id = db.create_schedule(name, time_of_day, severity_filter, session.user_id)

        # Register với Task Scheduler
        scheduler = WindowsScheduler()
        if scheduler.register(schedule_id, time_of_day):
            print(f"[OK] Schedule '{name}' (ID={schedule_id}) tạo thành công")
            print(f"     Thời gian: {time_of_day} | Severity: {severity_filter}")
            db.add_audit_entry(session.user_id, "schedule_create", f"id={schedule_id}")
            return True
        else:
            print("[CẢNH BÁO] Schedule tạo trong DB nhưng register Task Scheduler thất bại")
            print("             Chạy 'python main.py schedule list' để check")
            return True

    except Exception as e:
        print(f"[LỖI] {e}")
        return False


@require_role(Role.ADMIN)
def cmd_schedule_list(db: AuthDB) -> bool:
    """Liệt kê tất cả schedules."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedules = db.get_all_schedules()

    if not schedules:
        print("Không có schedule nào.")
        return True

    scheduler = WindowsScheduler()
    registered_ids = set(scheduler.list_registered())

    print("\n=== DANH SÁCH SCHEDULES ===\n")
    print(f"{'ID':<5} {'Tên':<20} {'Thời gian':<12} {'Severity':<10} {'Trạng thái':<15} {'Lần chạy cuối':<20}")
    print("-" * 95)

    for sched in schedules:
        status = "✓ Enabled" if sched.enabled else "✗ Disabled"
        is_registered = "✓ Registered" if sched.id in registered_ids else "✗ Not registered"
        last_run = sched.last_run.strftime("%Y-%m-%d %H:%M:%S") if sched.last_run else "-"

        print(f"{sched.id:<5} {sched.name:<20} {sched.time_of_day:<12} {sched.severity_filter:<10} "
              f"{status:<15} {last_run:<20}")
        print(f"      Task Scheduler: {is_registered}")

    print()
    return True


@require_role(Role.ADMIN)
def cmd_schedule_remove(db: AuthDB, schedule_id: int) -> bool:
    """Xóa schedule."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedule = db.get_schedule(schedule_id)
    if not schedule:
        print(f"[LỖI] Schedule {schedule_id} không tồn tại")
        return False

    confirm = input(f"Xác nhận xóa schedule '{schedule.name}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Đã hủy")
        return False

    try:
        # Xóa từ Task Scheduler
        scheduler = WindowsScheduler()
        scheduler.unregister(schedule_id)

        # Xóa từ DB
        db.delete_schedule(schedule_id)

        print(f"[OK] Schedule {schedule_id} đã xóa")
        db.add_audit_entry(session.user_id, "schedule_delete", f"id={schedule_id}")
        return True

    except Exception as e:
        print(f"[LỖI] {e}")
        return False


@require_role(Role.ADMIN)
def cmd_schedule_enable(db: AuthDB, schedule_id: int) -> bool:
    """Bật schedule."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedule = db.get_schedule(schedule_id)
    if not schedule:
        print(f"[LỖI] Schedule {schedule_id} không tồn tại")
        return False

    if schedule.enabled:
        print(f"Schedule {schedule_id} đã bật sẵn")
        return True

    db.toggle_schedule(schedule_id, True)
    print(f"[OK] Schedule {schedule_id} đã bật")
    db.add_audit_entry(session.user_id, "schedule_enable", f"id={schedule_id}")
    return True


@require_role(Role.ADMIN)
def cmd_schedule_disable(db: AuthDB, schedule_id: int) -> bool:
    """Tắt schedule."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedule = db.get_schedule(schedule_id)
    if not schedule:
        print(f"[LỖI] Schedule {schedule_id} không tồn tại")
        return False

    if not schedule.enabled:
        print(f"Schedule {schedule_id} đã tắt sẵn")
        return True

    db.toggle_schedule(schedule_id, False)
    print(f"[OK] Schedule {schedule_id} đã tắt")
    db.add_audit_entry(session.user_id, "schedule_disable", f"id={schedule_id}")
    return True


@require_role(Role.ADMIN)
def cmd_schedule_runs(db: AuthDB, schedule_id: int) -> bool:
    """Xem lịch sử chạy schedule."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedule = db.get_schedule(schedule_id)
    if not schedule:
        print(f"[LỖI] Schedule {schedule_id} không tồn tại")
        return False

    runs = db.get_schedule_runs(schedule_id, limit=10)

    if not runs:
        print(f"Schedule {schedule_id} chưa chạy lần nào.")
        return True

    print(f"\n=== LỊCH SỬ CHẠY: {schedule.name} ===\n")
    print(f"{'Thời gian bắt đầu':<25} {'Trạng thái':<10} {'CVEs':<8} {'Report':<40}")
    print("-" * 83)

    for run in runs:
        start_time = run.started_at.strftime("%Y-%m-%d %H:%M:%S")
        status = run.status.upper()
        cve_count = str(run.cve_count) if run.cve_count is not None else "-"
        report_file = run.report_path.split("/")[-1] if run.report_path else "-"

        print(f"{start_time:<25} {status:<10} {cve_count:<8} {report_file:<40}")

        if run.error_message:
            print(f"   Error: {run.error_message}")

    print()
    return True


@require_role(Role.ADMIN)
def cmd_schedule_run_now(db: AuthDB, schedule_id: int) -> bool:
    """Chạy schedule ngay lập tức."""
    session = get_auth_service().get_current_session()
    if not session:
        return False

    schedule = db.get_schedule(schedule_id)
    if not schedule:
        print(f"[LỖI] Schedule {schedule_id} không tồn tại")
        return False

    try:
        from scheduler.job_runner import run_job

        print(f"Đang chạy schedule {schedule_id}...")
        result = run_job(schedule_id)

        if result.get("success"):
            print(f"[OK] Chạy thành công")
            print(f"    CVEs collected: {result.get('cve_count')}")
            print(f"    Report: {result.get('report_path')}")
        else:
            print(f"[FAILED] {result.get('error')}")

        return result.get("success", False)

    except Exception as e:
        print(f"[LỖI] {e}")
        return False
