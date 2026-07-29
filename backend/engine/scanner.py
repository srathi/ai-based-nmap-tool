import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.engine.target_parser import TargetParser


class NmapScanner:
    SCAN_TYPE_FLAGS = {
        "tcp_connect": "-sT",
        "syn": "-sS",
        "udp": "-sU",
    }

    def __init__(self, timeout: int = 600):
        self.timeout = timeout
        self._check_nmap()

    def _check_nmap(self) -> None:
        if not shutil.which("nmap"):
            raise RuntimeError(
                "nmap is not installed or not found in PATH. "
                "Please install nmap first: brew install nmap (macOS) "
                "or apt-get install nmap (Linux)"
            )

    def _build_args(
        self,
        target: str,
        ports: str = "22,80,443",
        scan_type: str = "tcp_connect",
        timing: str = "T3",
        service_detect: bool = False,
        os_detect: bool = False,
        discovery: bool = False,
        udp_ports: Optional[str] = None,
    ) -> List[str]:
        args = ["nmap"]

        if discovery:
            args.append("-sn")
        else:
            flag = self.SCAN_TYPE_FLAGS.get(scan_type)
            if not flag:
                raise ValueError(
                    f"Unknown scan type: {scan_type}. "
                    f"Supported: {list(self.SCAN_TYPE_FLAGS.keys())}"
                )
            args.append(flag)

            if scan_type == "udp" and udp_ports:
                args.extend(["-p", udp_ports])
            elif scan_type != "udp" and ports:
                args.extend(["-p", ports])

            timing = timing.upper()
            if timing not in ("T0", "T1", "T2", "T3", "T4", "T5"):
                timing = "T3"
            args.append(f"-{timing}")

            if service_detect:
                args.append("-sV")
            if os_detect:
                args.append("-O")

        args.extend(["-oX", "-"])
        args.append(target)
        return args

    def scan(
        self,
        target: str,
        ports: str = "22,80,443",
        scan_type: str = "tcp_connect",
        timing: str = "T3",
        service_detect: bool = False,
        os_detect: bool = False,
        udp_ports: Optional[str] = None,
    ) -> Dict[str, Any]:
        valid, reason = TargetParser.validate_target(target)
        if not valid:
            return {
                "success": False,
                "error": f"Invalid target: {reason}",
                "raw_output": "",
                "command": "",
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {
                    "elapsed": 0,
                    "total_hosts": 0,
                    "total_ports": 0,
                },
            }

        try:
            args = self._build_args(
                target=target,
                ports=ports,
                scan_type=scan_type,
                timing=timing,
                service_detect=service_detect,
                os_detect=os_detect,
                udp_ports=udp_ports,
            )
        except ValueError as e:
            return {
                "success": False,
                "error": str(e),
                "raw_output": "",
                "command": "",
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {
                    "elapsed": 0,
                    "total_hosts": 0,
                    "total_ports": 0,
                },
            }

        command_str = " ".join(args)
        start = time.monotonic()
        stdout_str = ""
        stderr_str = ""
        return_code = -1
        timed_out = False

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            stdout_str = proc.stdout or ""
            stderr_str = proc.stderr or ""
            return_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            if e.stdout:
                stdout_str = e.stdout.decode("utf-8", errors="replace")
            if e.stderr:
                stderr_str = e.stderr.decode("utf-8", errors="replace")
            return_code = -1
        except FileNotFoundError:
            return {
                "success": False,
                "error": "nmap executable not found. Please install nmap.",
                "raw_output": "",
                "command": command_str,
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {
                    "elapsed": 0,
                    "total_hosts": 0,
                    "total_ports": 0,
                },
            }
        except OSError as e:
            return {
                "success": False,
                "error": f"OS error running nmap: {e}",
                "raw_output": "",
                "command": command_str,
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {
                    "elapsed": 0,
                    "total_hosts": 0,
                    "total_ports": 0,
                },
            }

        duration_ms = int((time.monotonic() - start) * 1000)

        result: Dict[str, Any] = {
            "success": return_code == 0 or timed_out,
            "raw_output": stdout_str or stderr_str,
            "command": command_str,
            "return_code": return_code,
            "duration_ms": duration_ms,
            "hosts": [],
            "stats": {
                "elapsed": duration_ms / 1000.0,
                "total_hosts": 0,
                "total_ports": 0,
            },
        }

        if timed_out:
            result["warning"] = f"Scan timed out after {self.timeout}s. Showing partial results."

        if stdout_str:
            parsed = self._parse_nmap_xml(stdout_str)
            if parsed:
                result["hosts"] = parsed.get("hosts", [])
                result["stats"] = parsed.get("stats", result["stats"])

        if not result["hosts"] and stderr_str:
            result["error"] = stderr_str.strip()

        total_ports = sum(len(h.get("ports", [])) for h in result["hosts"])
        result["stats"]["total_ports"] = total_ports
        result["stats"]["total_hosts"] = len(result["hosts"])

        if return_code != 0 and not timed_out and not result.get("error"):
            result["warning"] = (
                f"nmap returned non-zero exit code {return_code}. "
                f"Results may be incomplete."
            )

        return result

    def discovery(self, target: str, ports: str = "22,80,443") -> Dict[str, Any]:
        valid, reason = TargetParser.validate_target(target)
        if not valid:
            return {
                "success": False,
                "error": f"Invalid target: {reason}",
                "raw_output": "",
                "command": "",
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {"elapsed": 0, "total_hosts": 0, "total_ports": 0},
            }

        args = self._build_args(target=target, discovery=True)
        command_str = " ".join(args)
        start = time.monotonic()
        stdout_str = ""
        stderr_str = ""
        return_code = -1
        timed_out = False

        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            stdout_str = proc.stdout or ""
            stderr_str = proc.stderr or ""
            return_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            if e.stdout:
                stdout_str = e.stdout.decode("utf-8", errors="replace")
            if e.stderr:
                stderr_str = e.stderr.decode("utf-8", errors="replace")
            return_code = -1
        except (FileNotFoundError, OSError) as e:
            return {
                "success": False,
                "error": f"Failed to run nmap: {e}",
                "raw_output": "",
                "command": command_str,
                "return_code": -1,
                "duration_ms": 0,
                "hosts": [],
                "stats": {"elapsed": 0, "total_hosts": 0, "total_ports": 0},
            }

        duration_ms = int((time.monotonic() - start) * 1000)

        result: Dict[str, Any] = {
            "success": return_code == 0 or timed_out,
            "raw_output": stdout_str or stderr_str,
            "command": command_str,
            "return_code": return_code,
            "duration_ms": duration_ms,
            "hosts": [],
            "stats": {
                "elapsed": duration_ms / 1000.0,
                "total_hosts": 0,
                "total_ports": 0,
            },
        }

        if timed_out:
            result["warning"] = f"Discovery timed out after {self.timeout}s. Showing partial results."

        if stdout_str:
            parsed = self._parse_nmap_xml(stdout_str)
            if parsed:
                result["hosts"] = parsed.get("hosts", [])

        result["stats"]["total_hosts"] = len(result["hosts"])

        if return_code != 0 and not timed_out:
            if not result.get("error"):
                result["error"] = stderr_str.strip() or f"nmap returned exit code {return_code}"

        return result

    def _parse_nmap_xml(self, xml_str: str) -> Optional[Dict[str, Any]]:
        if not xml_str or not xml_str.strip():
            return None
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            return None

        result: Dict[str, Any] = {"hosts": [], "stats": {}}

        run_stats = root.find("runstats")
        if run_stats is not None:
            finished = run_stats.find("finished")
            if finished is not None:
                elapsed = finished.get("elapsed", "0")
                result["stats"]["elapsed"] = float(elapsed)

        for host_elem in root.findall("host"):
            host = self._parse_host_elem(host_elem)
            if host:
                result["hosts"].append(host)

        return result

    def _parse_host_elem(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        status_elem = host_elem.find("status")
        if status_elem is None:
            return None

        state = status_elem.get("state", "unknown")
        reason = status_elem.get("reason", "")

        host: Dict[str, Any] = {
            "ip": "",
            "hostname": "",
            "mac": "",
            "os_guess": "",
            "latency": "",
            "status": state,
            "reason": reason,
            "ports": [],
        }

        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype", "")
            addr_val = addr.get("addr", "")
            if addr_type == "ipv4":
                host["ip"] = addr_val
            elif addr_type in ("ipv6",):
                if not host["ip"]:
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

        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host["os_guess"] = osmatch.get("name", "")

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info = self._parse_port_elem(port_elem)
                if port_info:
                    host["ports"].append(port_info)

        return host

    def _parse_port_elem(self, port_elem: ET.Element) -> Optional[Dict[str, Any]]:
        port_id = port_elem.get("portid", "")
        protocol = port_elem.get("protocol", "")

        state_elem = port_elem.find("state")
        if state_elem is None:
            return None
        state = state_elem.get("state", "unknown")

        service_info: Dict[str, str] = {
            "service_name": "",
            "service_version": "",
            "service_product": "",
            "service_protocol": "",
            "service_extra": "",
        }
        service_elem = port_elem.find("service")
        if service_elem is not None:
            service_info["service_name"] = service_elem.get("name", "")
            service_info["service_version"] = service_elem.get("version", "")
            service_info["service_product"] = service_elem.get("product", "")
            service_info["service_protocol"] = service_elem.get("proto", "")
            service_info["service_extra"] = service_elem.get("extrainfo", "")

        return {
            "port": int(port_id) if port_id.isdigit() else port_id,
            "protocol": protocol,
            "state": state,
            **service_info,
            "banner": "",
        }

    def _parse_nmap_normal(self, text: str) -> List[Dict[str, Any]]:
        import re as _re
        hosts: List[Dict[str, Any]] = []
        current_host: Optional[Dict[str, Any]] = None
        port_section = False
        port_header_detected = False

        for line in text.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if line_stripped.startswith("Nmap scan report for "):
                if current_host:
                    hosts.append(current_host)
                host_part = line_stripped[len("Nmap scan report for "):]
                current_host = {
                    "ip": "",
                    "hostname": "",
                    "mac": "",
                    "os_guess": "",
                    "latency": "",
                    "status": "up",
                    "reason": "",
                    "ports": [],
                }
                if "(" in host_part and ")" in host_part:
                    hostname = host_part.split("(")[0].strip()
                    ip_part = host_part.split("(")[1].split(")")[0].strip()
                    current_host["hostname"] = hostname
                    current_host["ip"] = ip_part
                else:
                    ip_part = host_part.strip()
                    try:
                        import ipaddress
                        ipaddress.ip_address(ip_part)
                        current_host["ip"] = ip_part
                    except ValueError:
                        current_host["hostname"] = ip_part
                port_section = False
                port_header_detected = False
                continue

            if line_stripped.startswith("Host is up"):
                if current_host:
                    current_host["status"] = "up"
                    latency_match = _re.search(
                        r"\(([\d.]+)\s*s\s+latency\)", line_stripped, _re.IGNORECASE
                    )
                    if latency_match:
                        current_host["latency"] = f"{float(latency_match.group(1)) * 1000:.2f}ms"
                continue

            if line_stripped.upper().startswith("PORT") and "STATE" in line_stripped.upper() and "SERVICE" in line_stripped.upper():
                port_section = True
                port_header_detected = True
                continue

            if "MAC Address:" in line_stripped and current_host:
                mac_match = _re.search(
                    r"MAC Address:\s+([0-9A-Fa-f:]{17})",
                    line_stripped,
                )
                if mac_match:
                    current_host["mac"] = mac_match.group(1)
                continue

            if "OS details:" in line_stripped and current_host:
                os_part = line_stripped[len("OS details:"):].strip()
                current_host["os_guess"] = os_part
                continue

            if "Device type:" in line_stripped and current_host:
                if not current_host["os_guess"]:
                    current_host["os_guess"] = line_stripped.strip()
                continue

            if port_section and current_host:
                if line_stripped.startswith("---"):
                    port_section = False
                    continue

                if "MAC Address:" in line_stripped or "Device type:" in line_stripped or "OS details:" in line_stripped:
                    port_section = False
                    continue

                first = line_stripped.split()[0] if line_stripped else ""
                if "/" not in first:
                    continue

                parts = line_stripped.split()
                if len(parts) >= 3:
                    port_protocol = parts[0]
                    state = parts[1]
                    service = " ".join(parts[2:])
                    port_id, protocol = port_protocol.split("/", 1)

                    service_name = service
                    service_version = ""
                    service_product = ""

                    if service and " " in service.strip():
                        svc_parts = service.strip().split(None, 2)
                        service_name = svc_parts[0] if svc_parts else ""
                        if len(svc_parts) > 1:
                            service_product = svc_parts[1]
                        if len(svc_parts) > 2:
                            service_version = svc_parts[2]

                    current_host["ports"].append({
                        "port": int(port_id) if port_id.isdigit() else port_id,
                        "protocol": protocol,
                        "state": state,
                        "service_name": service_name,
                        "service_version": service_version,
                        "service_product": service_product,
                        "service_protocol": protocol,
                        "service_extra": "",
                        "banner": "",
                    })

        if current_host:
            hosts.append(current_host)

        return hosts
