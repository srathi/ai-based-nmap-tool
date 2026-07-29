from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Enum, ForeignKey, Text, JSON
from backend.database import Base
import enum


class InsightType(str, enum.Enum):
    SUMMARY = "summary"
    RISK = "risk"
    COMPARISON = "comparison"
    RECOMMENDATION = "recommendation"
    QA = "qa"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecommendationCategory(str, enum.Enum):
    REMEDIATION = "remediation"
    FOLLOW_UP = "follow_up"
    BEST_PRACTICE = "best_practice"


class AIInsight(Base):
    __tablename__ = "ai_insights"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    insight_type = Column(Enum(InsightType), nullable=False)
    content = Column(Text, nullable=False)
    evidence_refs = Column(JSON, nullable=True)
    confidence = Column(Float, default=0.0)
    model_used = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("host_results.id"), nullable=True)
    port_id = Column(Integer, ForeignKey("port_results.id"), nullable=True)
    score = Column(Integer, default=0)
    severity = Column(Enum(Severity), default=Severity.LOW)
    factors = Column(JSON, nullable=True)
    recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    category = Column(Enum(RecommendationCategory), nullable=False)
    priority = Column(Integer, default=3)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence_refs = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
