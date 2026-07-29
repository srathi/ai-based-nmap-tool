import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class TargetParser:
    IP_PATTERN = re.compile(
        r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    )
    HOSTNAME_PATTERN = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )
    RANGE_PATTERN = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$"
    )
    CIDR_PATTERN = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$"
    )

    @staticmethod
    def parse_ip(ip_str: str) -> str:
        try:
            ipaddress.ip_address(ip_str)
            return ip_str.strip()
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_str}")

    @staticmethod
    def parse_cidr(cidr_str: str) -> str:
        cidr_str = cidr_str.strip()
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            prefix = network.prefixlen
            if prefix < 24:
                raise ValueError(
                    f"CIDR prefix /{prefix} expands to {network.num_addresses} "
                    f"hosts (max allowed is /24 = 256 hosts). "
                    f"Use a more specific range (e.g., /24 or smaller)."
                )
            return str(network)
        except ValueError as e:
            if "Use a more specific range" in str(e):
                raise
            raise ValueError(f"Invalid CIDR notation: {cidr_str}. {e}")

    @staticmethod
    def parse_range(range_str: str) -> str:
        range_str = range_str.strip()
        m = TargetParser.RANGE_PATTERN.match(range_str)
        if not m:
            raise ValueError(
                f"Invalid IP range format: {range_str}. "
                f"Expected format: 192.168.1.1-100"
            )
        base_ip = m.group(1)
        end_val = int(m.group(2))
        try:
            ipaddress.ip_address(base_ip)
        except ValueError:
            raise ValueError(f"Invalid base IP in range: {base_ip}")
        if end_val < 0 or end_val > 255:
            raise ValueError(f"Range end value must be between 0 and 255, got {end_val}")
        parts = [int(x) for x in base_ip.split(".")]
        start_val = parts[3]
        count = end_val - start_val + 1
        if count > 256:
            raise ValueError(
                f"Range {range_str} expands to {count} hosts (max allowed is 256). "
                f"Use a smaller range."
            )
        if count <= 0:
            raise ValueError(
                f"Invalid range: end value {end_val} must be >= start value {start_val}"
            )
        return range_str

    @staticmethod
    def parse_hostname(hostname: str) -> str:
        hostname = hostname.strip()
        if not hostname:
            raise ValueError("Hostname cannot be empty")
        if len(hostname) > 253:
            raise ValueError(f"Hostname too long ({len(hostname)} chars, max 253)")
        if not TargetParser.HOSTNAME_PATTERN.match(hostname):
            raise ValueError(f"Invalid hostname format: {hostname}")
        return hostname.lower()

    @staticmethod
    def parse_list(file_or_list: Union[str, List[str]]) -> List[str]:
        if isinstance(file_or_list, list):
            results = []
            for item in file_or_list:
                item = item.strip()
                if item and not item.startswith("#"):
                    results.append(item)
            if not results:
                raise ValueError("Target list is empty (no valid entries found)")
            return results
        path = Path(file_or_list)
        if not path.exists():
            raise ValueError(f"Target file not found: {file_or_list}")
        if not path.is_file():
            raise ValueError(f"Target path is not a file: {file_or_list}")
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as e:
            raise ValueError(f"Could not read target file {file_or_list}: {e}")
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        if not lines:
            raise ValueError(f"No valid targets found in file: {file_or_list}")
        return lines

    @staticmethod
    def parse(target_input: str) -> Dict[str, Any]:
        target_input = target_input.strip()
        if not target_input:
            raise ValueError("Target input cannot be empty")

        if "/" in target_input:
            try:
                cidr = TargetParser.parse_cidr(target_input)
                return {"type": "cidr", "value": cidr, "original": target_input}
            except ValueError:
                pass

        if "-" in target_input and TargetParser.RANGE_PATTERN.match(target_input):
            try:
                r = TargetParser.parse_range(target_input)
                return {"type": "range", "value": r, "original": target_input}
            except ValueError:
                pass

        try:
            ip = TargetParser.parse_ip(target_input)
            return {"type": "ip", "value": ip, "original": target_input}
        except ValueError:
            pass

        try:
            hostname = TargetParser.parse_hostname(target_input)
            return {"type": "hostname", "value": hostname, "original": target_input}
        except ValueError:
            pass

        raise ValueError(
            f"Could not determine target type for: {target_input}. "
            f"Supported formats: IP (192.168.1.1), CIDR (192.168.1.0/24), "
            f"range (192.168.1.1-100), hostname (example.com)"
        )

    @staticmethod
    def expand_targets(target_str: str) -> List[str]:
        info = TargetParser.parse(target_str)
        ttype = info["type"]
        value = info["value"]

        if ttype == "ip":
            return [value]
        if ttype == "hostname":
            return [value]
        if ttype == "cidr":
            network = ipaddress.ip_network(value, strict=False)
            return [str(ip) for ip in network.hosts()]
        if ttype == "range":
            m = TargetParser.RANGE_PATTERN.match(value)
            base_ip = m.group(1)
            end_val = int(m.group(2))
            parts = [int(x) for x in base_ip.split(".")]
            start_val = parts[3]
            return [
                f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
                for i in range(start_val, end_val + 1)
            ]
        raise ValueError(f"Cannot expand target type: {ttype}")

    @staticmethod
    def validate_target(target_str: str) -> Tuple[bool, str]:
        if not target_str or not target_str.strip():
            return False, "Target input is empty"
        target_str = target_str.strip()
        if "/" in target_str:
            try:
                TargetParser.parse_cidr(target_str)
                return True, "valid CIDR"
            except ValueError as e:
                return False, str(e)
        if "-" in target_str:
            try:
                TargetParser.parse_range(target_str)
                return True, "valid IP range"
            except ValueError as e:
                return False, str(e)
        try:
            TargetParser.parse_ip(target_str)
            return True, "valid IP address"
        except ValueError:
            pass
        try:
            TargetParser.parse_hostname(target_str)
            return True, "valid hostname"
        except ValueError as e:
            return False, str(e)
        return False, f"Unrecognized target format: {target_str}"
