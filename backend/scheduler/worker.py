import json
import logging
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from backend.config import SCAN_TIMEOUT
from backend.database import SessionLocal
from backend.models.scan import HostResult, PortResult, ScanJob, ScanResult, ServiceResult
from backend.scheduler.job_queue import JobQueue, JobStatus

logger = logging.getLogger(__name__)


class ScanWorker:
    def __init__(self, job_queue: JobQueue, db_session_factory=None):
        self.job_queue = job_queue
        self.db_session_factory = db_session_factory or SessionLocal
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._current_process: Optional[subprocess.Popen] = None
        self._paused_jobs: Dict[str, bool] = {}

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("ScanWorker started")

    def stop(self) -> None:
        self._running = False
        if self._current_process:
            self._current_process.terminate()
        logger.info("ScanWorker stopped")

    def _run_loop(self) -> None:
        while self._running:
            try:
                job_id = self.job_queue.dequeue()
            except Exception:
                continue
            if not self._running:
                break
            self._process_job(job_id)

    def _process_job(self, job_id: str) -> None:
        db: Session = self.db_session_factory()
        try:
            scan_job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if not scan_job:
                logger.error(f"ScanJob {job_id} not found")
                return

            from backend.models.target import Target
            from backend.models.scan import ScanProfile
            target = db.query(Target).filter(Target.id == scan_job.target_id).first()
            profile = None
            if scan_job.profile_id:
                profile = db.query(ScanProfile).filter(ScanProfile.id == scan_job.profile_id).first()
            from backend.config import DEFAULT_SCAN_PROFILES
            if not profile and scan_job.profile_id and str(scan_job.profile_id) in DEFAULT_SCAN_PROFILES:
                pd = DEFAULT_SCAN_PROFILES[str(scan_job.profile_id)]
                profile = ScanProfile(name=pd["name"], ports=pd.get("ports"), scan_type=pd.get("scan_type", "tcp_connect"), timing=pd.get("timing"))

            target_value = target.target_value if target else str(scan_job.target_id)
            nmap_args = self._build_nmap_args(target_value, profile)

            self.job_queue.update_status(job_id, JobStatus.RUNNING, progress=0.0)
            scan_job.status = JobStatus.RUNNING.value
            scan_job.started_at = datetime.now(timezone.utc)
            db.commit()

            logger.info(f"Starting scan {job_id}: nmap {' '.join(nmap_args)}")

            self._current_process = subprocess.Popen(
                nmap_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            try:
                stdout, stderr = self._current_process.communicate(timeout=SCAN_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
                stdout, stderr = self._current_process.communicate()
                self.job_queue.update_status(job_id, JobStatus.FAILED, error="Scan timed out")
                scan_job.status = JobStatus.FAILED.value
                scan_job.error = "Scan timed out"
                scan_job.raw_output = stdout
                scan_job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            self._current_process = None

            if self.job_queue.get_status(job_id) and self.job_queue.get_status(job_id).get("status") == JobStatus.CANCELLED:
                scan_job.status = JobStatus.CANCELLED.value
                scan_job.error = "Cancelled by user"
                scan_job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            if self._check_paused(job_id):
                scan_job.status = JobStatus.PAUSED.value
                scan_job.raw_output = stdout
                db.commit()
                self.job_queue.update_status(job_id, JobStatus.PAUSED, progress=0.5)
                return

            if self._current_process and self._current_process.returncode != 0 and stderr:
                self.job_queue.update_status(job_id, JobStatus.FAILED, error=stderr)
                scan_job.status = JobStatus.FAILED.value
                scan_job.error = stderr
                scan_job.raw_output = stdout
                scan_job.completed_at = datetime.now(timezone.utc)
                db.commit()
                return

            normalized = self._parse_nmap_output(stdout)
            scan_job.raw_output = stdout
            scan_job.completed_at = datetime.now(timezone.utc)

            scan_result = ScanResult(
                scan_job_id=job_id,
                raw_output=stdout,
                normalized_data=json.dumps(normalized),
                normalized_at=datetime.now(timezone.utc),
            )
            db.add(scan_result)
            db.flush()

            for host_data in normalized.get("hosts", []):
                host = HostResult(
                    scan_job_id=job_id,
                    ip=host_data.get("ip"),
                    hostname=host_data.get("hostname", ""),
                    is_alive=True,
                )
                db.add(host)
                db.flush()

                for port_data in host_data.get("ports", []):
                    port = PortResult(
                        scan_job_id=job_id,
                        host_id=host.id,
                        port=port_data.get("port"),
                        protocol=port_data.get("protocol", "tcp"),
                        state=port_data.get("state", "closed"),
                        service_name=port_data.get("service_name", port_data.get("service", "")),
                    )
                    db.add(port)
                    db.flush()

                    if port_data.get("version") or port_data.get("product"):
                        svc = ServiceResult(
                            port_id=port.id,
                            name=port_data.get("service_name", port_data.get("service", "")),
                            product=port_data.get("product", ""),
                            version=port_data.get("version", ""),
                            extra_info=port_data.get("extra_info", ""),
                        )
                        db.add(svc)

            self.job_queue.update_status(job_id, JobStatus.COMPLETED, progress=1.0)
            scan_job.status = JobStatus.COMPLETED.value
            db.commit()
            logger.info(f"Scan {job_id} completed")

        except Exception as e:
            logger.exception(f"Error processing scan job {job_id}")
            self.job_queue.update_status(job_id, JobStatus.FAILED, error=str(e))
            try:
                scan_job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
                if scan_job:
                    scan_job.status = JobStatus.FAILED.value
                    scan_job.error_message = str(e)
                    scan_job.completed_at = datetime.now(timezone.utc)
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()

    def _build_nmap_args(self, target: str, profile: Any) -> list:
        args = ["nmap"]

        if profile:
            if profile.scan_type == "syn":
                args.append("-sS")
            elif profile.scan_type == "udp":
                args.append("-sU")
            elif profile.scan_type == "tcp_connect":
                args.append("-sT")
            else:
                args.append("-sT")

            if hasattr(profile, "timing") and profile.timing:
                args.append(f"-T{profile.timing[-1]}")

            if hasattr(profile, "ports") and profile.ports:
                args.extend(["-p", str(profile.ports)])

            # Host discovery is on by default; no need for -sn

            if hasattr(profile, "service_detect") and profile.service_detect:
                args.append("-sV")

            if hasattr(profile, "os_detect") and profile.os_detect:
                args.append("-O")

            if hasattr(profile, "udp_ports") and profile.udp_ports:
                args.extend(["-sU", "-p", str(profile.udp_ports)])

        args.append(target)
        return args

    def _parse_nmap_output(self, raw_output: str) -> Dict[str, Any]:
        hosts = []
        current_host = None

        for line in raw_output.splitlines():
            if line.startswith("Nmap scan report for"):
                if current_host:
                    hosts.append(current_host)
                rest = line.split("Nmap scan report for")[-1].strip()
                ip = ""
                hostname = ""
                if "(" in rest and ")" in rest:
                    hostname = rest.split("(")[0].strip()
                    ip = rest.split("(")[1].split(")")[0].strip()
                else:
                    ip = rest
                current_host = {
                    "ip": ip,
                    "hostname": hostname,
                    "status": "up",
                    "os_guess": "",
                    "ports": [],
                }
            elif "Host is up" in line and current_host is not None:
                current_host["status"] = "up"
            elif current_host is not None and "/" in line and "open" in line or "filtered" in line:
                parts = line.split()
                if len(parts) >= 2:
                    port_proto = parts[0]
                    state = parts[1]
                    if "/" in port_proto:
                        port_str, proto = port_proto.split("/")
                        try:
                            port_num = int(port_str)
                        except ValueError:
                            continue
                        service = parts[2] if len(parts) > 2 else ""
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        product = ""
                        extra_info = ""
                        if version:
                            product = version
                            version = ""
                        current_host["ports"].append({
                            "port": port_num,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "product": product,
                            "version": version,
                            "extra_info": extra_info,
                        })

        if current_host:
            hosts.append(current_host)

        return {"hosts": hosts, "total_hosts": len(hosts)}

    def pause_job(self, job_id: str) -> None:
        self._paused_jobs[job_id] = True
        self.job_queue.pause(job_id)

    def resume_job(self, job_id: str) -> None:
        self._paused_jobs.pop(job_id, None)
        self.job_queue.resume(job_id)

    def cancel_job(self, job_id: str) -> None:
        self.job_queue.cancel(job_id)
        if self._current_process:
            self._current_process.send_signal(signal.SIGTERM)

    def _check_paused(self, job_id: str) -> bool:
        status_info = self.job_queue.get_status(job_id)
        return status_info is not None and status_info.get("status") == JobStatus.PAUSED
