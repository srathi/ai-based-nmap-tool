import csv
import io

from backend.exporters.base import BaseExporter


class CSVExporter(BaseExporter):

    def export(self, scan_result: dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "port", "protocol", "state", "service", "version", "product"])
        for host in scan_result.get("hosts", []):
            ip = host.get("ip", "")
            ports = host.get("ports", [])
            if ports:
                for port in ports:
                    writer.writerow([
                        ip,
                        port.get("port", ""),
                        port.get("protocol", "tcp"),
                        port.get("state", ""),
                        port.get("service", ""),
                        port.get("version", ""),
                        port.get("product", ""),
                    ])
            else:
                writer.writerow([ip, "", "", host.get("status", ""), "", "", ""])
        return output.getvalue()

    def get_mime_type(self) -> str:
        return "text/csv"

    def get_extension(self) -> str:
        return ".csv"
