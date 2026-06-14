"""
scheduler/os_adapter.py - Windows Task Scheduler integration.
"""

import subprocess
import sys
from pathlib import Path
from typing import List, Optional


class WindowsScheduler:
    """Windows Task Scheduler adapter (Windows only)."""

    TASK_PREFIX = "ATI_"

    def __init__(self):
        """Khởi tạo Windows scheduler."""
        if sys.platform != "win32":
            raise RuntimeError("WindowsScheduler only works on Windows")

    @staticmethod
    def _get_python_exe() -> str:
        """Lấy đường dẫn Python interpreter."""
        return sys.executable

    @staticmethod
    def _get_project_root() -> Path:
        """Lấy project root directory."""
        return Path(__file__).parent.parent

    def register(self, schedule_id: int, time_of_day: str) -> bool:
        """Tạo Task Scheduler job.

        Args:
            schedule_id: ID của schedule
            time_of_day: Giờ chạy (HH:MM, 24h)

        Returns:
            True nếu thành công
        """
        try:
            python_exe = self._get_python_exe()
            project_root = self._get_project_root()
            script_path = project_root / "scripts" / "run_scheduled_report.py"

            task_name = f"{self.TASK_PREFIX}{schedule_id}"
            task_description = f"ATI Scheduled Report - Schedule {schedule_id}"

            # Format: HH:MM
            if not time_of_day or ":" not in time_of_day:
                return False

            cmd = [
                "schtasks",
                "/create",
                "/tn", task_name,
                "/tr", f'"{python_exe}" "{script_path}" --id {schedule_id}',
                "/sc", "daily",
                "/st", time_of_day,
                "/f"
            ]

            result = subprocess.run(cmd, capture_output=True, shell=False)
            return result.returncode == 0

        except Exception as e:
            print(f"[LỖI] Failed to register schedule: {e}")
            return False

    def unregister(self, schedule_id: int) -> bool:
        """Xóa Task Scheduler job."""
        try:
            task_name = f"{self.TASK_PREFIX}{schedule_id}"
            cmd = ["schtasks", "/delete", "/tn", task_name, "/f"]
            result = subprocess.run(cmd, capture_output=True, shell=False)
            return result.returncode == 0
        except Exception:
            return False

    def is_registered(self, schedule_id: int) -> bool:
        """Kiểm tra task đã được register."""
        try:
            task_name = f"{self.TASK_PREFIX}{schedule_id}"
            cmd = ["schtasks", "/query", "/tn", task_name]
            result = subprocess.run(cmd, capture_output=True, shell=False)
            return result.returncode == 0
        except Exception:
            return False

    def list_registered(self) -> List[int]:
        """Liệt kê tất cả ATI tasks đã register."""
        try:
            cmd = ["schtasks", "/query", "/fo", "csv", "/nh"]
            result = subprocess.run(cmd, capture_output=True, text=True, shell=False)

            if result.returncode != 0:
                return []

            task_ids = []
            for line in result.stdout.split("\n"):
                if self.TASK_PREFIX in line:
                    # Format: "task_name,..."
                    parts = line.split(",")
                    if parts:
                        task_name = parts[0].strip('"')
                        if task_name.startswith(self.TASK_PREFIX):
                            try:
                                task_id = int(task_name[len(self.TASK_PREFIX):])
                                task_ids.append(task_id)
                            except ValueError:
                                pass

            return sorted(task_ids)

        except Exception:
            return []
