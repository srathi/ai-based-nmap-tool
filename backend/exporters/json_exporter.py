import json

from backend.exporters.base import BaseExporter


class JSONExporter(BaseExporter):

    def export(self, scan_result: dict) -> str:
        return json.dumps(scan_result, indent=2, default=str)

    def get_mime_type(self) -> str:
        return "application/json"

    def get_extension(self) -> str:
        return ".json"
