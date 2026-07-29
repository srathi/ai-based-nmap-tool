from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AIInsightResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_job_id: int | None
    insight_type: str
    content: str
    evidence_refs: list[str] | None
    confidence: float
    model_used: str | None
    created_at: datetime


class RiskScoreResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_id: int | None
    port_id: int | None
    score: float
    severity: str
    factors: list[str] | None
    recommendation: str | None


class RecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category: str
    priority: str
    title: str
    description: str
    evidence_refs: list[str] | None


class AIQueryRequest(BaseModel):
    query: str
    question: str | None = None
    scan_id: int | None = None
    scan_job_id: int | None = None

    def resolved_scan_id(self) -> int | None:
        if self.scan_id is not None:
            return self.scan_id
        return self.scan_job_id

    def resolved_question(self) -> str:
        return self.question or self.query


class AIQueryResponse(BaseModel):
    answer: str
    confidence: float
    evidence_refs: list[str]


class ScanComparisonRequest(BaseModel):
    scan_job_id_1: int | None = None
    scan_job_id_2: int | None = None
    scan_id_1: int | None = None
    scan_id_2: int | None = None

    def resolved_id1(self) -> int | None:
        return self.scan_id_1 if self.scan_id_1 is not None else self.scan_job_id_1

    def resolved_id2(self) -> int | None:
        return self.scan_id_2 if self.scan_id_2 is not None else self.scan_job_id_2


class ScanComparisonResponse(BaseModel):
    new_hosts: list[str]
    removed_hosts: list[str]
    new_ports: list[str]
    removed_ports: list[str]
    summary: str
