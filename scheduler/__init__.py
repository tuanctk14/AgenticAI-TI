"""
scheduler - OS-driven scheduled reporting using Windows Task Scheduler.
"""

from .os_adapter import WindowsScheduler
from .job_runner import run_job

__all__ = ["WindowsScheduler", "run_job"]
