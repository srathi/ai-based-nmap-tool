from backend.exporters.base import BaseExporter


class ReportExporter(BaseExporter):

    SEPARATOR = "=" * 72
    SUB_SEPARATOR = "-" * 72

    def export(self, scan_result: dict) -> str:
        lines = []
        lines.append(self.SEPARATOR)
        lines.append("PORT SCAN REPORT")
        lines.append(self.SEPARATOR)

        lines.append("")
        lines.append("SUMMARY")
        lines.append(self.SUB_SEPARATOR)
        hosts = scan_result.get("hosts", [])
        total_hosts = scan_result.get("total_hosts", len(hosts))
        total_ports = sum(len(h.get("ports", [])) for h in hosts)
        lines.append(f"  Total hosts scanned : {total_hosts}")
        lines.append(f"  Hosts found         : {len(hosts)}")
        lines.append(f"  Total open ports    : {total_ports}")
        lines.append("")

        lines.append("HOST DETAILS")
        lines.append(self.SUB_SEPARATOR)
        for i, host in enumerate(hosts, 1):
            ip = host.get("ip", "unknown")
            hostname = host.get("hostname", "")
            status = host.get("status", "unknown")
            os_guess = host.get("os_guess", "")

            lines.append(f"  [{i}] Host: {ip}")
            if hostname:
                lines.append(f"      Hostname : {hostname}")
            lines.append(f"      Status   : {status}")
            if os_guess:
                lines.append(f"      OS Guess : {os_guess}")

            ports = host.get("ports", [])
            if ports:
                lines.append("")
                lines.append("      PORTS")
                header = f"      {'PORT':>8} {'PROTOCOL':<8} {'STATE':<10} {'SERVICE':<20} {'VERSION'}"
                lines.append(f"      {'-' * (len(header) - 6)}")
                lines.append(header)
                lines.append(f"      {'-' * (len(header) - 6)}")
                for port in ports:
                    port_str = str(port.get("port", ""))
                    proto = port.get("protocol", "tcp")
                    state = port.get("state", "")
                    service = port.get("service", "")
                    version = port.get("version", "")
                    product = port.get("product", "")
                    version_str = f"{product} {version}".strip() if product else version
                    lines.append(
                        f"      {port_str:>8} {proto:<8} {state:<10} {service:<20} {version_str}"
                    )
            lines.append("")

        lines.append("FINDINGS")
        lines.append(self.SUB_SEPARATOR)
        findings = scan_result.get("findings", [])
        if findings:
            for finding in findings:
                severity = finding.get("severity", "info")
                title = finding.get("title", "")
                desc = finding.get("description", "")
                lines.append(f"  [{severity.upper()}] {title}")
                if desc:
                    lines.append(f"       {desc}")
                lines.append("")
        else:
            lines.append("  No additional findings.")
            lines.append("")

        lines.append(self.SEPARATOR)
        lines.append("END OF REPORT")
        lines.append(self.SEPARATOR)
        return "\n".join(lines)

    def get_mime_type(self) -> str:
        return "text/plain"

    def get_extension(self) -> str:
        return ".txt"
