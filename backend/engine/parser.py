from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


class ScanResultParser:
    REQUIRED_TOP_KEYS = {"success", "raw_output", "command", "return_code", "duration_ms", "hosts", "stats"}
    OPTIONAL_TOP_KEYS = {"error", "warning"}
    HOST_REQUIRED_KEYS = {"ip", "hostname", "mac", "os_guess", "latency", "status", "ports"}
    PORT_REQUIRED_KEYS = {"port", "protocol", "state", "service_name", "service_version", "service_product", "banner"}

    @staticmethod
    def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {
            "success": bool(raw.get("success", False)),
            "raw_output": str(raw.get("raw_output", "")),
            "command": str(raw.get("command", "")),
            "return_code": int(raw.get("return_code", -1)),
            "duration_ms": int(raw.get("duration_ms", 0)),
            "hosts": [],
            "stats": {},
        }

        if "error" in raw and raw["error"]:
            normalized["error"] = str(raw["error"])
        if "warning" in raw and raw["warning"]:
            normalized["warning"] = str(raw["warning"])

        raw_stats = raw.get("stats", {})
        if isinstance(raw_stats, dict):
            normalized["stats"] = {
                "elapsed": float(raw_stats.get("elapsed", 0)),
                "total_hosts": int(raw_stats.get("total_hosts", 0)),
                "total_ports": int(raw_stats.get("total_ports", 0)),
            }
        else:
            normalized["stats"] = {"elapsed": 0, "total_hosts": 0, "total_ports": 0}

        raw_hosts = raw.get("hosts", [])
        if isinstance(raw_hosts, list):
            for host in raw_hosts:
                normalized_host = ScanResultParser._normalize_host(host)
                if normalized_host:
                    normalized["hosts"].append(normalized_host)

        normalized["stats"]["total_hosts"] = len(normalized["hosts"])

        total_ports = 0
        for h in normalized["hosts"]:
            total_ports += len(h.get("ports", []))
        normalized["stats"]["total_ports"] = total_ports

        return normalized

    @staticmethod
    def _normalize_host(host: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(host, dict):
            return None

        normalized_host: Dict[str, Any] = {
            "ip": str(host.get("ip", "")),
            "hostname": str(host.get("hostname", "")),
            "mac": str(host.get("mac", "")),
            "os_guess": str(host.get("os_guess", "")),
            "latency": str(host.get("latency", "")),
            "status": str(host.get("status", "unknown")),
            "ports": [],
        }

        raw_ports = host.get("ports", [])
        if isinstance(raw_ports, list):
            for port in raw_ports:
                normalized_port = ScanResultParser._normalize_port(port)
                if normalized_port:
                    normalized_host["ports"].append(normalized_port)

        return normalized_host

    @staticmethod
    def _normalize_port(port: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(port, dict):
            return None

        normalized_port: Dict[str, Any] = {
            "port": port.get("port", 0),
            "protocol": str(port.get("protocol", "")),
            "state": str(port.get("state", "unknown")),
            "service_name": str(port.get("service_name", "")),
            "service_version": str(port.get("service_version", "")),
            "service_product": str(port.get("service_product", "")),
            "banner": str(port.get("banner", "")),
        }

        port_val = normalized_port["port"]
        if not isinstance(port_val, int):
            try:
                normalized_port["port"] = int(port_val)
            except (ValueError, TypeError):
                normalized_port["port"] = 0

        return normalized_port

    @staticmethod
    def extract_services(port_data: Dict[str, Any]) -> Dict[str, Any]:
        services: List[Dict[str, Any]] = []

        for port in port_data:
            service_name = port.get("service_name", "").strip()
            if not service_name:
                continue
            services.append({
                "port": port.get("port", 0),
                "protocol": port.get("protocol", ""),
                "name": service_name,
                "version": port.get("service_version", ""),
                "product": port.get("service_product", ""),
                "state": port.get("state", ""),
            })

        service_counts = Counter(s["name"] for s in services)

        return {
            "services": services,
            "service_count": len(services),
            "unique_services": len(service_counts),
            "service_breakdown": dict(service_counts.most_common()),
            "top_services": [name for name, _ in service_counts.most_common(10)],
        }

    @staticmethod
    def compute_summary(hosts: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(hosts)
        status_counts: Counter = Counter()
        port_counts: Counter = Counter()
        all_services: List[str] = []
        os_list: List[str] = []

        for host in hosts:
            status = host.get("status", "unknown")
            status_counts[status] += 1

            for port in host.get("ports", []):
                state = port.get("state", "unknown")
                port_counts[state] += 1
                svc = port.get("service_name", "").strip()
                if svc:
                    all_services.append(svc)

            os_guess = host.get("os_guess", "").strip()
            if os_guess:
                os_list.append(os_guess)

        service_counts = Counter(all_services)

        top_open = []
        for host in hosts:
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    top_open.append({
                        "host": host.get("ip", ""),
                        "port": port.get("port", 0),
                        "protocol": port.get("protocol", ""),
                        "service": port.get("service_name", ""),
                    })

        return {
            "total_hosts": total,
            "host_statuses": dict(status_counts),
            "port_states": dict(port_counts),
            "total_ports_open": port_counts.get("open", 0),
            "total_ports_filtered": port_counts.get("filtered", 0),
            "total_ports_closed": port_counts.get("closed", 0),
            "top_services": [s for s, _ in service_counts.most_common(10)],
            "service_counts": dict(service_counts.most_common(20)),
            "os_detections": os_list[:10],
            "unique_os_guesses": len(set(os_list)),
            "top_open_ports": top_open[:20],
        }

    @staticmethod
    def merge_results(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {
            "success": existing.get("success", False) or new.get("success", False),
            "command": f"{existing.get('command', '')} | {new.get('command', '')}",
            "duration_ms": existing.get("duration_ms", 0) + new.get("duration_ms", 0),
            "hosts": [],
            "stats": {},
            "merged": True,
        }

        existing_hosts = {
            h.get("ip", ""): h
            for h in existing.get("hosts", [])
            if h.get("ip")
        }
        new_hosts = {
            h.get("ip", ""): h
            for h in new.get("hosts", [])
            if h.get("ip")
        }

        all_ips = set(existing_hosts.keys()) | set(new_hosts.keys())

        for ip in sorted(all_ips):
            existing_h = existing_hosts.get(ip, {})
            new_h = new_hosts.get(ip, {})

            merged_host: Dict[str, Any] = {
                "ip": ip,
                "hostname": existing_h.get("hostname", "") or new_h.get("hostname", ""),
                "mac": existing_h.get("mac", "") or new_h.get("mac", ""),
                "os_guess": existing_h.get("os_guess", "") or new_h.get("os_guess", ""),
                "latency": existing_h.get("latency", "") or new_h.get("latency", ""),
                "status": "up" if (existing_h.get("status") == "up" or new_h.get("status") == "up") else "unknown",
                "ports": [],
            }

            seen_ports: set = set()
            for src_host in (existing_h, new_h):
                for port in src_host.get("ports", []):
                    port_key = (port.get("port", 0), port.get("protocol", ""))
                    if port_key not in seen_ports:
                        seen_ports.add(port_key)
                        merged_host["ports"].append(port)

            merged_host["ports"].sort(key=lambda p: (p.get("protocol", ""), p.get("port", 0)))
            merged["hosts"].append(merged_host)

        merged["stats"] = {
            "elapsed": max(
                existing.get("stats", {}).get("elapsed", 0),
                new.get("stats", {}).get("elapsed", 0),
            ),
            "total_hosts": len(merged["hosts"]),
            "total_ports": sum(len(h["ports"]) for h in merged["hosts"]),
        }

        errors = []
        if existing.get("error"):
            errors.append(f"existing: {existing['error']}")
        if new.get("error"):
            errors.append(f"new: {new['error']}")
        if errors:
            merged["error"] = "; ".join(errors)

        warnings = []
        if existing.get("warning"):
            warnings.append(f"existing: {existing['warning']}")
        if new.get("warning"):
            warnings.append(f"new: {new['warning']}")
        if warnings:
            merged["warning"] = "; ".join(warnings)

        return merged

    @staticmethod
    def validate_result(result_dict: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not isinstance(result_dict, dict):
            return False, ["Result must be a dictionary"]

        for key in ScanResultParser.REQUIRED_TOP_KEYS:
            if key not in result_dict:
                errors.append(f"Missing required top-level key: '{key}'")

        if "success" in result_dict and not isinstance(result_dict["success"], bool):
            errors.append("'success' must be a boolean")

        if "return_code" in result_dict and not isinstance(result_dict["return_code"], int):
            errors.append("'return_code' must be an integer")

        if "duration_ms" in result_dict and not isinstance(result_dict["duration_ms"], (int, float)):
            errors.append("'duration_ms' must be numeric")

        if "hosts" in result_dict:
            hosts = result_dict["hosts"]
            if not isinstance(hosts, list):
                errors.append("'hosts' must be a list")
            else:
                for i, host in enumerate(hosts):
                    host_errors = ScanResultParser._validate_host(host, i)
                    errors.extend(host_errors)

        if "stats" in result_dict:
            stats = result_dict["stats"]
            if not isinstance(stats, dict):
                errors.append("'stats' must be a dictionary")
            else:
                for key in ("elapsed", "total_hosts", "total_ports"):
                    if key not in stats:
                        errors.append(f"Missing stats key: '{key}'")
                    elif not isinstance(stats[key], (int, float)):
                        errors.append(f"stats.{key} must be numeric")

        return len(errors) == 0, errors

    @staticmethod
    def _validate_host(host: Any, index: int) -> List[str]:
        errors: List[str] = []
        if not isinstance(host, dict):
            errors.append(f"hosts[{index}] must be a dictionary")
            return errors

        prefix = f"hosts[{index}]"
        for key in ScanResultParser.HOST_REQUIRED_KEYS:
            if key not in host:
                errors.append(f"{prefix}: missing required key '{key}'")

        if "ports" in host:
            ports = host["ports"]
            if not isinstance(ports, list):
                errors.append(f"{prefix}.ports must be a list")
            else:
                for j, port in enumerate(ports):
                    port_errors = ScanResultParser._validate_port(port, index, j)
                    errors.extend(port_errors)

        return errors

    @staticmethod
    def _validate_port(port: Any, host_idx: int, port_idx: int) -> List[str]:
        errors: List[str] = []
        if not isinstance(port, dict):
            errors.append(f"hosts[{host_idx}].ports[{port_idx}] must be a dictionary")
            return errors

        prefix = f"hosts[{host_idx}].ports[{port_idx}]"
        for key in ScanResultParser.PORT_REQUIRED_KEYS:
            if key not in port:
                errors.append(f"{prefix}: missing required key '{key}'")

        if "port" in port:
            pval = port["port"]
            if not isinstance(pval, int):
                try:
                    int(pval)
                except (ValueError, TypeError):
                    errors.append(f"{prefix}.port must be numeric")

        return errors
