from abc import ABC, abstractmethod
from typing import Any


class BaseExporter(ABC):

    @abstractmethod
    def export(self, scan_result: dict) -> str:
        pass

    @abstractmethod
    def get_mime_type(self) -> str:
        pass

    @abstractmethod
    def get_extension(self) -> str:
        pass
