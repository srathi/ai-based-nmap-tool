import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.ai_insight import AIInsight, Recommendation, RiskScore
from backend.models.scan import ScanResult
from backend.models.user import User
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


class SummaryResponse(BaseModel):
    summary: str
    scan_id: int


class RiskScoreResponse(BaseModel):
    overall_score: float
    max_score: float
    risk_level: str
    details: Optional[dict]


class CompareRequest(BaseModel):
    scan_id_1: int
    scan_id_2: int


class CompareResponse(BaseModel):
    new_hosts: list
    removed_hosts: list
    new_ports: list
    removed_ports: list
    summary: str


class RecommendResponse(BaseModel):
    recommendations: List[str]


class QueryRequest(BaseModel):
    query: str
    question: str | None = None
    scan_id: int | None = None
    scan_job_id: int | None = None

    def resolved_scan_id(self) -> int | None:
        return self.scan_id or self.scan_job_id

    def resolved_question(self) -> str:
        return self.question or self.query


class QueryResponse(BaseModel):
    answer: str
    confidence: float = 0.0
    evidence_refs: list = []


class InsightResponse(BaseModel):
    id: int
    scan_job_id: int
    insight_type: str
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("/summarize/{scan_id}", response_model=SummaryResponse)
async def summarize_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results found for this scan")
    data = json.loads(result.normalized_data) if result.normalized_data else {}
    hosts = data.get("hosts", [])
    total = len(hosts)
    open_ports = sum(len(h.get("ports", [])) for h in hosts)
    summary = (
        f"Scan {str(scan_id)[:8]}... found {total} host(s) with {open_ports} open port(s). "
        f"Services detected include: "
        + ", ".join(
            sorted(set(
                p.get("service", "unknown") for h in hosts for p in h.get("ports", [])
            ))
        )
        + "."
    )
    return SummaryResponse(summary=summary, scan_id=scan_id)


@router.post("/risk-score/{scan_id}", response_model=RiskScoreResponse)
async def risk_score_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results found for this scan")
    data = json.loads(result.normalized_data) if result.normalized_data else {}
    hosts = data.get("hosts", [])
    total_open = sum(len(h.get("ports", [])) for h in hosts)
    risky_ports = sum(
        1 for h in hosts for p in h.get("ports", [])
        if p.get("port", 0) in (22, 23, 21, 3389, 1433, 1521)
    )
    score = min(10.0, (total_open * 0.5) + (risky_ports * 1.5))
    level = "low" if score < 3 else "medium" if score < 7 else "high"
    return RiskScoreResponse(
        overall_score=round(score, 1),
        max_score=10.0,
        risk_level=level,
        details={"total_open_ports": total_open, "risky_ports_found": risky_ports},
    )


@router.post("/compare", response_model=CompareResponse)
async def compare_scans(
    req: CompareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    id1 = req.resolved_id1() if hasattr(req, "resolved_id1") else req.scan_id_1
    id2 = req.resolved_id2() if hasattr(req, "resolved_id2") else req.scan_id_2
    r1 = db.query(ScanResult).filter(ScanResult.scan_job_id == id1).first()
    r2 = db.query(ScanResult).filter(ScanResult.scan_job_id == id2).first()
    if not r1 or not r2:
        raise HTTPException(status_code=404, detail="One or both scans not found")
    d1 = json.loads(r1.normalized_data) if r1.normalized_data else {}
    d2 = json.loads(r2.normalized_data) if r2.normalized_data else {}
    hosts1 = {h["ip"]: h for h in d1.get("hosts", [])}
    hosts2 = {h["ip"]: h for h in d2.get("hosts", [])}
    new_hosts = [ip for ip in hosts2 if ip not in hosts1]
    removed_hosts = [ip for ip in hosts1 if ip not in hosts2]
    common = [ip for ip in hosts1 if ip in hosts2]
    new_ports = []
    for ip in common:
        ports1 = {p["port"] for p in hosts1[ip].get("ports", [])}
        ports2 = {p["port"] for p in hosts2[ip].get("ports", [])}
        new_ports.extend([{"host": ip, "port": p} for p in ports2 - ports1])
    removed_ports = []
    return CompareResponse(
        new_hosts=new_hosts,
        removed_hosts=removed_hosts,
        new_ports=new_ports,
        removed_ports=removed_ports,
        summary=f"Comparison: {len(new_hosts)} new hosts, {len(removed_hosts)} removed, {len(new_ports)} new ports.",
    )


@router.post("/recommend/{scan_id}", response_model=RecommendResponse)
async def recommend_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results found for this scan")
    data = json.loads(result.normalized_data) if result.normalized_data else {}
    hosts = data.get("hosts", [])
    recs = []
    for h in hosts:
        ip = h.get("ip", "")
        for p in h.get("ports", []):
            port = p.get("port", 0)
            svc = p.get("service", "")
            if port == 22:
                recs.append(f"Host {ip}: SSH on port 22 - ensure key-based auth and disable root login")
            elif port == 23:
                recs.append(f"Host {ip}: Telnet on port 23 - replace with SSH")
            elif port == 21:
                recs.append(f"Host {ip}: FTP on port 21 - use SFTP or FTPS instead")
            elif port == 3389:
                recs.append(f"Host {ip}: RDP on port 3389 - restrict via VPN and enable NLA")
            elif port in (1433, 1521, 3306, 5432, 6379, 27017):
                recs.append(f"Host {ip}: Database ({svc}) on port {port} - restrict access and use TLS")
        if not h.get("ports"):
            recs.append(f"Host {ip}: No open ports detected - host may be down or firewalled")
    if not recs:
        recs.append("No specific recommendations; host appears well-configured.")
    return RecommendResponse(recommendations=recs[:10])


@router.post("/query", response_model=QueryResponse)
async def query_scan(
    req: QueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan_id = req.resolved_scan_id() if hasattr(req, "resolved_scan_id") else req.scan_id
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results found for this scan")
    data = json.loads(result.normalized_data) if result.normalized_data else {}
    q = (req.resolved_question() if hasattr(req, "resolved_question") else req.question).lower()
    hosts = data.get("hosts", [])

    # Collect all data once
    all_ports = []
    all_services = set()
    open_ports_by_host = {}
    for h in hosts:
        ip = h.get("ip", "unknown")
        for p in h.get("ports", []):
            port = p.get("port")
            proto = p.get("protocol", "tcp")
            state = p.get("state", "unknown")
            svc = p.get("service_name") or p.get("service", "unknown")
            ver = p.get("service_version", "")
            all_ports.append({"host": ip, "port": port, "protocol": proto, "state": state, "service": svc, "version": ver})
            if state == "open":
                all_services.add(svc)
                open_ports_by_host.setdefault(ip, []).append(p)

    total_open = sum(len(v) for v in open_ports_by_host.values())
    total_ports = len(all_ports)

    # Smart query matching
    if any(w in q for w in ["port", "ports", "which port", "what port", "open port", "list port", "scan port"]):
        open_ports = [p for p in all_ports if p["state"] == "open"]
        if open_ports:
            lines = [f"  {p['host']}:{p['port']}/{p['protocol']} - {p['service']} {p['version']}".strip() for p in open_ports]
            answer = f"Found {len(open_ports)} open port(s) across {len(hosts)} host(s):\n" + "\n".join(lines)
        else:
            answer = "No open ports found in this scan."
    elif any(w in q for w in ["service", "services", "application", "running", "what is running"]):
        svc_list = sorted(all_services)
        if svc_list:
            answer = f"Detected {len(svc_list)} service(s): {', '.join(svc_list)}"
        else:
            answer = "No services detected."
    elif any(w in q for w in ["host", "hosts", "ip", "ips", "target", "targets", "alive", "online", "which host"]):
        ips = [h.get("ip", "?") for h in hosts]
        answer = f"Found {len(ips)} host(s): {', '.join(ips)}"
    elif any(w in q for w in ["risk", "danger", "vulnerable", "critical", "security", "threat", "unsafe", "expos"]):
        risky_ports = {22, 23, 21, 3389, 3306, 5432, 27017, 6379}
        risky = [(p["host"], p["port"], p["service"]) for p in all_ports if p["state"] == "open" and p["port"] in risky_ports]
        if risky:
            lines = [f"  {h}:{pt} ({s})" for h, pt, s in sorted(risky)]
            answer = f"Potential security concerns ({len(risky)}):\n" + "\n".join(lines) + "\nConsider restricting access to these services."
        else:
            answer = "No obvious security risks detected based on exposed ports."
    elif any(w in q for w in ["how many", "count", "total"]):
        answer = f"This scan found {len(hosts)} host(s) with {total_open} open port(s) total."
    elif any(w in q for w in ["detail", "details", "show me", "tell me more", "info", "information"]):
        if hosts:
            lines = []
            for h in hosts:
                ports_str = ", ".join(f"{p.get('port')}/{p.get('protocol')} ({p.get('service_name') or p.get('service', '?')})" for p in h.get("ports", []) if p.get("state") == "open")
                lines.append(f"  {h.get('ip')}: {ports_str or 'no open ports'}")
            answer = f"Scan details for {len(hosts)} host(s):\n" + "\n".join(lines)
        else:
            answer = "No hosts found in this scan."
    elif any(w in q for w in ["summary", "summarize", "overview", "what does", "describe"]):
        svc_by_host = []
        for h in hosts:
            svcs = [p.get("service_name") or p.get("service", "?") for p in h.get("ports", []) if p.get("state") == "open"]
            if svcs:
                svc_by_host.append(f"  {h.get('ip')}: {', '.join(svcs)}")
        answer = f"Scan Summary: {len(hosts)} host(s) found with {total_open} open port(s).\n" + "\n".join(svc_by_host)
    elif any(w in q for w in ["compare", "difference", "changed", "new", "removed"]):
        answer = "Comparison feature requires two scans. Use the AI Insights page to compare two scans side by side."
    elif any(w in q for w in ["recommend", "suggest", "advice", "next step", "follow up", "remediat"]):
        answer = "Based on the scan results, consider: 1) Review all open ports for necessity, 2) Secure any exposed services, 3) Run a follow-up scan after making changes. Use the AI Insights page for detailed recommendations."
    else:
        # Default: give a useful summary
        svc_list = sorted(all_services)
        answer = (f"This scan found {len(hosts)} host(s) with {total_open} open port(s). "
                  f"Services detected: {', '.join(svc_list) if svc_list else 'none'}. "
                  f"Try asking about ports, services, hosts, risk, or details for more specific information.")

    return QueryResponse(answer=answer)


@router.get("/insights/{scan_id}", response_model=List[InsightResponse])
async def get_insights(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    insights = db.query(AIInsight).filter(AIInsight.scan_id == scan_id).order_by(AIInsight.created_at.desc()).all()
    return insights
