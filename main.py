import asyncio
import logging
import os
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("vercel-main")
logger.info("Starting Vercel entrypoint...")

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))

FAKE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake-token-for-vercel"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    yield
    logger.info("Shutting down...")


app = FastAPI(title="AI Nmap Scanner", version="1.0.0", lifespan=lifespan)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class RateLimitMiddleware:
    def __init__(self, app, calls_per_minute: int = 60):
        self.app = app
        self.calls_per_minute = calls_per_minute
        self.clients: dict = defaultdict(list)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = 60.0
        self.clients[client_ip] = [t for t in self.clients[client_ip] if now - t < window]
        if len(self.clients[client_ip]) >= self.calls_per_minute:
            response = JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
            await response(scope, receive, send)
            return
        self.clients[client_ip].append(now)
        await self.app(scope, receive, send)


app.add_middleware(RateLimitMiddleware, calls_per_minute=RATE_LIMIT_PER_MINUTE)


@app.post("/api/v1/auth/login")
async def login(request: Request):
    return {"access_token": FAKE_TOKEN, "token_type": "bearer"}


@app.post("/api/v1/auth/refresh")
async def refresh_token(request: Request):
    return {"access_token": FAKE_TOKEN, "token_type": "bearer"}


@app.get("/api/v1/auth/me")
async def me(request: Request):
    return {"id": "1", "username": "admin", "email": "admin@local", "role": "admin", "is_active": True}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI Nmap Scanner", "version": "1.0.0"}


@app.get("/debug")
async def debug():
    return {
        "python": sys.version,
        "working_dir": os.getcwd(),
        "files": os.listdir("."),
        "has_frontend": FRONTEND_DIR.exists(),
    }


# Load AI service modules (with graceful fallback on Vercel)
try:
    import json
    from backend.config import AI_PROVIDER
    from backend.ai_service.summarizer import ScanSummarizer
    from backend.ai_service.risk_scorer import RiskScorer
    from backend.ai_service.recommender import ScanRecommender
    from backend.ai_service.comparator import ScanComparator
    from backend.ai_service.qa import ScanQA
    AI_MODULES_LOADED = True
except ImportError as e:
    logger.warning(f"AI modules not loaded: {e}")
    AI_MODULES_LOADED = False

# Database helpers for Vercel (sqlite + /tmp/data)
try:
    import json
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker
    from backend.config import DATABASE_URL
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    DB_AVAILABLE = True
except Exception as e:
    logger.warning(f"Database not available: {e}")
    DB_AVAILABLE = False


def get_scan_data(scan_id: int) -> dict:
    if not DB_AVAILABLE:
        return {"hosts": []}
    try:
        db = SessionLocal()
        result = db.execute(text("SELECT normalized_data FROM scan_results WHERE scan_job_id = :id"), {"id": scan_id}).fetchone()
        db.close()
        if result and result[0]:
            return json.loads(result[0])
    except Exception as e:
        logger.warning(f"get_scan_data error: {e}")
    return {"hosts": []}


# ---- AI Endpoints ----

@app.post("/api/v1/ai/summarize/{scan_id}")
async def ai_summarize(scan_id: int, request: Request):
    data = get_scan_data(scan_id)
    if AI_MODULES_LOADED:
        summarizer = ScanSummarizer(provider=AI_PROVIDER)
        result = summarizer.summarize(data)
        return {"summary": result.get("summary", "No summary"), "scan_id": scan_id}
    hosts = data.get("hosts", [])
    return {"summary": f"Scan found {len(hosts)} host(s)", "scan_id": scan_id}


@app.post("/api/v1/ai/risk-score/{scan_id}")
async def ai_risk_score(scan_id: int, request: Request):
    data = get_scan_data(scan_id)
    if AI_MODULES_LOADED:
        scorer = RiskScorer(provider=AI_PROVIDER)
        result = scorer.score_scan(data)
        if isinstance(result, dict) and "risk_score" in result:
            return result
        scores = [s for s in result if s.get("port_id") is None]
        if scores:
            top = max(scores, key=lambda x: x.get("score", 0))
            return {
                "risk_score": top.get("score", 0), "score": top.get("score", 0),
                "risk_level": top.get("severity", "low"), "reason": "; ".join(top.get("factors", []))
            }
    return {"risk_score": 0, "score": 0, "risk_level": "unknown", "reason": "No data"}


@app.post("/api/v1/ai/recommend/{scan_id}")
async def ai_recommend(scan_id: int, request: Request):
    data = get_scan_data(scan_id)
    if AI_MODULES_LOADED:
        recommender = ScanRecommender(provider=AI_PROVIDER)
        recs = recommender.recommend(data)
        formatted = []
        for r in recs:
            title = r.get("title", "")
            desc = r.get("description", "")
            formatted.append(f"[{r.get('priority', 0)}] {title}: {desc}" if title else desc)
        return {"recommendations": formatted, "summary": f"Found {len(recs)} recommendation(s)"}
    return {"recommendations": ["Run a full scan for recommendations"], "summary": "No recommendations"}


@app.post("/api/v1/ai/compare")
async def ai_compare(request: Request):
    body = await request.json()
    id1, id2 = body.get("scan_id_1"), body.get("scan_id_2")
    d1, d2 = get_scan_data(id1), get_scan_data(id2)
    if AI_MODULES_LOADED:
        comparator = ScanComparator(provider=AI_PROVIDER)
        result = comparator.compare(d1, d2)
        result["detail"] = result.get("detail", result.get("summary", ""))
        result["comparison"] = result.get("comparison", result.get("summary", ""))
        return result
    return {"summary": "Comparison not available", "detail": "Comparison not available", "comparison": "Comparison not available"}


@app.post("/api/v1/ai/query")
async def ai_query(request: Request):
    body = await request.json()
    question = body.get("query") or body.get("question", "")
    scan_id = body.get("scan_id") or body.get("scan_job_id", 0)
    data = get_scan_data(scan_id)
    if AI_MODULES_LOADED:
        qa = ScanQA(provider=AI_PROVIDER)
        result = qa.answer(question, data)
        return {"answer": result.get("answer", ""), "confidence": result.get("confidence", 0.0), "evidence_refs": result.get("evidence_refs", [])}
    hosts = data.get("hosts", [])
    return {"answer": f"Scan has {len(hosts)} host(s). Use GROQ_API_KEY for AI analysis.", "confidence": 0.5, "evidence_refs": []}


@app.get("/api/v1/ai/insights/{scan_id}")
async def ai_insights(scan_id: int):
    return []


FRONTEND_DIR = Path(__file__).parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"


@app.get("/")
async def serve_frontend():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(), media_type="text/html")
    return JSONResponse({"status": "ok", "service": "AI Nmap Scanner", "version": "1.0.0"})


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
