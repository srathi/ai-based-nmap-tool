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
