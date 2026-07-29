import asyncio
import threading
from enum import Enum
from typing import Any, Dict, Optional


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class JobQueue:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self._jobs: Dict[str, Dict[str, Any]] = {}
            self._queue: list = []
            self._condition = threading.Condition(threading.Lock())
            self._asyncio_lock = asyncio.Lock()

    def enqueue(self, scan_job_id: str) -> None:
        with self._condition:
            self._jobs[scan_job_id] = {
                "id": scan_job_id,
                "status": JobStatus.PENDING,
                "progress": 0.0,
                "error": None,
                "partial_results": None,
            }
            self._queue.append(scan_job_id)
            self._condition.notify()

    def dequeue(self) -> Optional[str]:
        with self._condition:
            while not self._queue:
                self._condition.wait()
            job_id = self._queue.pop(0)
            self._jobs[job_id]["status"] = JobStatus.RUNNING
            return job_id

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self._jobs.get(job_id)

    def update_status(
        self, job_id: str, status: JobStatus, progress: Optional[float] = None, error: Optional[str] = None
    ) -> None:
        with self._condition:
            if job_id in self._jobs:
                self._jobs[job_id]["status"] = status
                if progress is not None:
                    self._jobs[job_id]["progress"] = progress
                if error is not None:
                    self._jobs[job_id]["error"] = error

    def cancel(self, job_id: str) -> None:
        self.update_status(job_id, JobStatus.CANCELLED)

    def pause(self, job_id: str) -> None:
        self.update_status(job_id, JobStatus.PAUSED)

    def resume(self, job_id: str) -> None:
        self.update_status(job_id, JobStatus.PENDING)

    @property
    def active_count(self) -> int:
        return sum(
            1 for j in self._jobs.values() if j["status"] == JobStatus.RUNNING
        )
