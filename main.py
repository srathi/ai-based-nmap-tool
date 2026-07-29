import asyncio
import hashlib
import json
import logging
import sqlite3
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

DATA_DIR = Path(os.getenv("DATA_DIR", "/tmp/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "scanner.db")

# --- Standalone SQLite auth (no SQLAlchemy/backend dependency) ---

def init_auth_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'admin'
        )
    """)
    conn.commit()
    # Ensure admin user exists
    cur = conn.execute("SELECT id FROM auth_users WHERE username = ?", ("admin",))
    if not cur.fetchone():
        pw_hash = hashlib.sha256("admin".encode()).hexdigest()
        conn.execute("INSERT INTO auth_users (username, password_hash, role) VALUES (?, ?, ?)",
                     ("admin", pw_hash, "admin"))
        conn.commit()
        logger.info("Created admin user in auth DB")
    conn.close()

init_auth_db()

def verify_admin_password(password: str) -> bool:
    expected = hashlib.sha256("admin".encode()).hexdigest()
    return hashlib.sha256(password.encode()).hexdigest() == expected

def create_jwt_token(user_id: int, role: str) -> str:
    import jwt as pyjwt
    secret = os.getenv("SECRET_KEY", "change-me-in-production-insecure-default")
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    return pyjwt.encode(payload, secret, algorithm="HS256")

def verify_jwt_token(token: str) -> dict:
    import jwt as pyjwt
    secret = os.getenv("SECRET_KEY", "change-me-in-production-insecure-default")
    try:
        return pyjwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# --- End standalone auth ---

RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))

# Try to load backend modules (optional - graceful fallback)
try:
    from backend.database import init_db
    init_db()
    logger.info("Backend database initialized")
except Exception as e:
    logger.warning(f"Backend database init skipped: {e}")

worker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker
    logger.info("Starting up lifespan...")
    try:
        from backend.database import init_db
        init_db()
        logger.info("Backend database initialized in lifespan")
    except Exception as e:
        logger.warning(f"Backend DB init in lifespan failed: {e}")
    try:
        from backend.scheduler.job_queue import JobQueue
        from backend.scheduler.worker import ScanWorker
        job_queue = JobQueue()
        worker = ScanWorker(job_queue)
        worker.start()
        logger.info("ScanWorker started")
    except Exception as e:
        logger.warning(f"ScanWorker could not start: {e}")
        worker = None
    yield
    logger.info("Shutting down...")
    if worker is not None:
        try:
            worker.stop()
        except Exception:
            pass


app = FastAPI(
    title="AI Nmap Scanner",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


# --- Standalone auth endpoints ---

@app.post("/api/v1/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")

    if username == "admin":
        # Try backend DB first
        try:
            from backend.database import SessionLocal
            from backend.models.user import User
            from backend.api.auth import pwd_context as bcrypt_ctx
            db = SessionLocal()
            user = db.query(User).filter(User.username == "admin").first()
            if not user:
                hashed = bcrypt_ctx.hash("admin")
                user = User(username="admin", email="admin@local", hashed_password=hashed, role="admin")
                db.add(user)
                db.commit()
                db.refresh(user)
            if bcrypt_ctx.verify(password, user.hashed_password):
                token = create_jwt_token(user.id, user.role)
                return {"access_token": token, "token_type": "bearer"}
            db.close()
        except Exception as e:
            logger.warning(f"Backend auth failed, using direct auth: {e}")

        # Fallback: direct hash verification
        if verify_admin_password(password):
            token = create_jwt_token(1, "admin")
            return {"access_token": token, "token_type": "bearer"}

    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/v1/auth/refresh")
async def refresh_token(request: Request):
    body = await request.json()
    token = body.get("token", "")
    payload = verify_jwt_token(token)
    new_token = create_jwt_token(int(payload.get("sub", 0)), payload.get("role", "admin"))
    return {"access_token": new_token, "token_type": "bearer"}


@app.get("/api/v1/auth/me")
async def me(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_jwt_token(auth[7:])
    return {
        "id": payload.get("sub", ""),
        "username": "admin",
        "email": "admin@local",
        "role": payload.get("role", "admin"),
        "is_active": True
    }


# Try to load backend API routers (optional)
try:
    from backend.api.auth import router as auth_router
    from backend.api.users import router as users_router
    from backend.api.targets import router as targets_router
    from backend.api.scans import router as scans_router
    from backend.api.ai import router as ai_router
    from backend.api.exports import router as exports_router

    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(targets_router)
    app.include_router(scans_router)
    app.include_router(ai_router)
    app.include_router(exports_router)
    logger.info("Backend API routers loaded")
except Exception as e:
    logger.warning(f"Backend API routers not loaded: {e}")


connected_websockets: dict = {}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    connected_websockets.setdefault(scan_id, set()).add(websocket)
    try:
        while True:
            try:
                from backend.scheduler.job_queue import JobQueue
                job_queue = JobQueue()
                status = job_queue.get_status(scan_id)
                if status:
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "status": status.get("status", "unknown"),
                        "progress": status.get("progress", 0.0),
                        "error": status.get("error"),
                    })
                else:
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "status": "not_found",
                        "progress": 0.0,
                    })
            except Exception:
                pass
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        connected_websockets.get(scan_id, set()).discard(websocket)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI Nmap Scanner", "version": "1.0.0"}


FRONTEND_DIR = Path(__file__).parent / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"


@app.get("/")
async def serve_frontend():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(), media_type="text/html")
    return JSONResponse({"status": "ok", "service": "AI Nmap Scanner", "version": "1.0.0"})


if STATIC_DIR.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
