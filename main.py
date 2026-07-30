import asyncio
import hashlib
import logging
import os
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
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


def make_jwt(user_id: int, role: str) -> str:
    from jose import jwt
    secret = os.getenv("SECRET_KEY", "change-me-in-production-insecure-default")
    return jwt.encode({"sub": str(user_id), "role": role, "exp": datetime.now(timezone.utc) + timedelta(days=1)}, secret, algorithm="HS256")


def check_jwt(token: str) -> dict:
    from jose import jwt
    secret = os.getenv("SECRET_KEY", "change-me-in-production-insecure-default")
    return jwt.decode(token, secret, algorithms=["HS256"])


ADMIN_USER = "admin"
ADMIN_PASS = "admin"


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
    try:
        try:
            body = await request.json()
        except Exception:
            body = {}
        username = body.get("username", "")
        password = body.get("password", "")
        logger.info(f"Login attempt: username={username}, password_len={len(password)}")
        if username == ADMIN_USER and password == ADMIN_PASS:
            token = make_jwt(1, "admin")
            logger.info("Login successful")
            return {"access_token": token, "token_type": "bearer"}
        logger.warning(f"Login failed for {username}: expected={ADMIN_USER}/{ADMIN_PASS}, got={username}/{password}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Login error: {e}")
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/v1/auth/refresh")
async def refresh_token(request: Request):
    body = await request.json()
    payload = check_jwt(body.get("token", ""))
    new_token = make_jwt(int(payload.get("sub", 0)), payload.get("role", "admin"))
    return {"access_token": new_token, "token_type": "bearer"}


@app.get("/api/v1/auth/me")
async def me(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = check_jwt(auth[7:])
    return {"id": payload.get("sub", ""), "username": ADMIN_USER, "email": "admin@local", "role": "admin", "is_active": True}


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
