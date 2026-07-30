import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.config import AI_PROVIDER
from backend.database import get_db
from backend.models.ai_insight import AIInsight, Recommendation, RiskScore
from backend.models.scan import ScanResult
from backend.models.user import User
from backend.api.auth import get_current_user
from backend.ai_service.summarizer import ScanSummarizer
from backend.ai_service.risk_scorer import RiskScorer
from backend.ai_service.recommender import ScanRecommender
from backend.ai_service.comparator import ScanComparator
from backend.ai_service.qa import ScanQA

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


class SummaryResponse(BaseModel):
    summary: str
    scan_id: int


class RiskScoreResponse(BaseModel):
    risk_score: int = 0
    score: int = 0
    overall_score: float = 0.0
    max_score: float = 10.0
    risk_level: str = "low"
    reason: str = ""
    detail: str = ""
    details: Optional[dict] = None


class CompareRequest(BaseModel):
    scan_id_1: int
    scan_id_2: int


class CompareResponse(BaseModel):
    new_hosts: list = []
    removed_hosts: list = []
    new_ports: list = []
    removed_ports: list = []
    changed_services: list = []
    summary: str = ""
    detail: str = ""
    comparison: str = ""
    new_concerns: list = []
    resolved_concerns: list = []


class RecommendResponse(BaseModel):
    recommendations: list = []
    summary: str = ""


class QueryRequest(BaseModel):
    query: str = ""
    question: str = ""
    scan_id: int = 0
    scan_job_id: int = 0

    def resolved_scan_id(self) -> int:
        return self.scan_id or self.scan_job_id

    def resolved_question(self) -> str:
        return self.question or self.query


class QueryResponse(BaseModel):
    answer: str = ""
    confidence: float = 0.0
    evidence_refs: list = []


class InsightResponse(BaseModel):
    id: int
    scan_job_id: int
    insight_type: str
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


def get_scan_data(scan_id: int, db: Session) -> dict:
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results found for this scan")
    return json.loads(result.normalized_data) if result.normalized_data else {}


@router.post("/summarize/{scan_id}", response_model=SummaryResponse)
async def summarize_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = get_scan_data(scan_id, db)
    summarizer = ScanSummarizer(provider=AI_PROVIDER)
    result = summarizer.summarize(data)
    return SummaryResponse(
        summary=result.get("summary", "No summary available."),
        scan_id=scan_id,
    )


@router.post("/risk-score/{scan_id}", response_model=RiskScoreResponse)
async def risk_score_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = get_scan_data(scan_id, db)
    scorer = RiskScorer(provider=AI_PROVIDER)
    result = scorer.score_scan(data)

    if isinstance(result, dict) and "risk_score" in result:
        return RiskScoreResponse(
            risk_score=result.get("risk_score", 0),
            score=result.get("score", 0),
            overall_score=float(result.get("risk_score", 0)),
            max_score=100.0,
            risk_level=result.get("risk_level", "medium"),
            reason=result.get("reason", ""),
            detail=result.get("reason", ""),
            details=result.get("details"),
        )

    scores = []
    for s in result:
        if s.get("port_id") is None:
            scores.append(s)
    if scores:
        top = max(scores, key=lambda x: x.get("score", 0))
        risk_score = top.get("score", 0)
        risk_level = top.get("severity", "low")
        reason = "; ".join(top.get("factors", [])) or "Standard host assessment."
        return RiskScoreResponse(
            risk_score=risk_score,
            score=risk_score,
            overall_score=float(risk_score),
            max_score=100.0,
            risk_level=risk_level,
            reason=reason,
            detail=reason,
            details={"scores": result},
        )

    return RiskScoreResponse()


@router.post("/compare", response_model=CompareResponse)
async def compare_scans(
    req: CompareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    d1 = get_scan_data(req.scan_id_1, db)
    d2 = get_scan_data(req.scan_id_2, db)
    comparator = ScanComparator(provider=AI_PROVIDER)
    result = comparator.compare(d1, d2)
    return CompareResponse(
        new_hosts=result.get("new_hosts", []),
        removed_hosts=result.get("removed_hosts", []),
        new_ports=result.get("new_ports", []),
        removed_ports=result.get("removed_ports", []),
        changed_services=result.get("changed_services", []),
        summary=result.get("summary", ""),
        detail=result.get("detail", result.get("summary", "")),
        comparison=result.get("comparison", result.get("summary", "")),
        new_concerns=result.get("new_concerns", []),
        resolved_concerns=result.get("resolved_concerns", []),
    )


@router.post("/recommend/{scan_id}", response_model=RecommendResponse)
async def recommend_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = get_scan_data(scan_id, db)
    recommender = ScanRecommender(provider=AI_PROVIDER)
    recs = recommender.recommend(data)
    summary = f"Found {len(recs)} recommendation(s)." if recs else "No recommendations."
    formatted = []
    for r in recs:
        title = r.get("title", "")
        desc = r.get("description", "")
        formatted.append(f"[{r.get('priority', 0)}] {title}: {desc}" if title else desc)
    return RecommendResponse(
        recommendations=formatted,
        summary=summary,
    )


@router.post("/query", response_model=QueryResponse)
async def query_scan(
    req: QueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan_id = req.scan_id or req.scan_job_id
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id or scan_job_id is required")
    data = get_scan_data(scan_id, db)
    question = req.question or req.query
    if not question:
        raise HTTPException(status_code=400, detail="query or question is required")
    qa = ScanQA(provider=AI_PROVIDER)
    result = qa.answer(question, data)
    return QueryResponse(
        answer=result.get("answer", ""),
        confidence=result.get("confidence", 0.0),
        evidence_refs=result.get("evidence_refs", []),
    )


@router.get("/insights/{scan_id}", response_model=List[InsightResponse])
async def get_insights(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    insights = db.query(AIInsight).filter(AIInsight.scan_id == scan_id).order_by(AIInsight.created_at.desc()).all()
    return insights
