import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from backend.engine.target_parser import TargetParser


class HostDiscovery:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self._check_nmap()

    def _check_nmap(self) -> None:
        if not shutil.which("nmap"):
            raise RuntimeError(
                "nmap is not installed or not found in PATH. "
                "Please install nmap first."
            )

    def ping_sweep(self, targets: List[str]) -> Dict[str, Any]:
        if not targets:
            return {
                "success": False,
                "error": "No targets provided for ping sweep",
                "hosts": [],
            }

        valid_targets = []
        for t in targets:
            valid, reason = TargetParser.validate_target(t)
            if not valid:
                continue
            valid_targets.append(t)

        if not valid_targets:
            return {
                "success": False,
                "error": "No valid targets provided for ping sweep",
                "hosts": [],
            }

        args = ["nmap", "-sn", "-oX", "-"] + valid_targets
        command_str = " ".join(args)
        start = time.monotonic()
        timed_out = False
        stdout_str = ""

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            stdout_str = proc.stdout or ""
            return_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            if e.stdout:
                stdout_str = e.stdout.decode("utf-8", errors="replace")
            return_code = -1
        except (FileNotFoundError, OSError) as e:
            return {
                "success": False,
                "error": f"Failed to run nmap ping sweep: {e}",
                "hosts": [],
            }

        duration_ms = int((time.monotonic() - start) * 1000)

        hosts = self._parse_ping_sweep(stdout_str)

        result: Dict[str, Any] = {
            "success": return_code == 0 or timed_out,
            "command": command_str,
            "duration_ms": duration_ms,
            "return_code": return_code,
            "hosts": hosts,
            "total_hosts": len(hosts),
        }

        if timed_out:
            result["warning"] = f"Ping sweep timed out after {self.timeout}s. Showing partial results."
        if return_code != 0 and not timed_out:
            result["error"] = f"nmap ping sweep returned exit code {return_code}"

        return result

    def discover(self, target_str: str) -> Dict[str, Any]:
        valid, reason = TargetParser.validate_target(target_str)
        if not valid:
            return {
                "success": False,
                "error": f"Invalid target: {reason}",
                "hosts": [],
                "total_hosts": 0,
            }

        args = ["nmap", "-sn", "-oX", "-", target_str]
        command_str = " ".join(args)
        start = time.monotonic()
        timed_out = False
        stdout_str = ""

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            stdout_str = proc.stdout or ""
            return_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            if e.stdout:
                stdout_str = e.stdout.decode("utf-8", errors="replace")
            return_code = -1
        except (FileNotFoundError, OSError) as e:
            return {
                "success": False,
                "error": f"Failed to run nmap discovery: {e}",
                "hosts": [],
                "total_hosts": 0,
            }

        duration_ms = int((time.monotonic() - start) * 1000)

        hosts = self._parse_ping_sweep(stdout_str)

        result: Dict[str, Any] = {
            "success": return_code == 0 or timed_out,
            "command": command_str,
            "duration_ms": duration_ms,
            "return_code": return_code,
            "hosts": hosts,
            "total_hosts": len(hosts),
        }

        if timed_out:
            result["warning"] = f"Discovery timed out after {self.timeout}s. Showing partial results."
        if return_code != 0 and not timed_out:
            result["error"] = f"nmap discovery returned exit code {return_code}"

        return result

    def _parse_ping_sweep(self, xml_str: str) -> List[Dict[str, str]]:
        hosts: List[Dict[str, str]] = []

        if not xml_str or not xml_str.strip():
            return hosts

        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return hosts

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            if status_elem is None:
                continue
            state = status_elem.get("state", "").lower()
            if state != "up":
                continue

            host: Dict[str, str] = {
                "ip": "",
                "hostname": "",
                "latency": "",
                "mac": "",
            }

            for addr in host_elem.findall("address"):
                addr_type = addr.get("addrtype", "")
                addr_val = addr.get("addr", "")
                if addr_type == "ipv4":
                    host["ip"] = addr_val
                elif addr_type == "mac":
                    host["mac"] = addr_val

            for hostname_elem in host_elem.findall("hostnames/hostname"):
                name = hostname_elem.get("name", "")
                if name:
                    host["hostname"] = name
                    break

            times_elem = host_elem.find("times")
            if times_elem is not None:
                srtt = times_elem.get("srtt", "")
                if srtt:
                    try:
                        host["latency"] = f"{float(srtt) / 1000:.2f}ms"
                    except (ValueError, TypeError):
                        pass

            if host["ip"]:
                hosts.append(host)

        return hosts
