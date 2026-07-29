import asyncio
import logging
import os
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure project root is in Python path for Vercel
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set database path BEFORE any backend imports (engine is created at import time)
DATA_DIR = Path(os.getenv("DATA_DIR", "/tmp/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{DATA_DIR}/scanner.db"

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("vercel-main")
logger.info("Starting Vercel entrypoint...")

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import Response
logger.info("FastAPI imports OK")

RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))

# Initialize database at import time (for serverless cold starts)
try:
    from backend.database import init_db
    init_db()
    logger.info("Database initialized at import time")
except Exception as e:
    logger.warning(f"Database init failed: {e}")

worker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker
    logger.info("Starting up lifespan...")
    try:
        from backend.database import init_db
        init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.warning(f"Database init failed: {e}")
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
            response = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )
            await response(scope, receive, send)
            return

        self.clients[client_ip].append(now)
        await self.app(scope, receive, send)


app.add_middleware(RateLimitMiddleware, calls_per_minute=RATE_LIMIT_PER_MINUTE)

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
    logger.info("API routers loaded")
except Exception as e:
    logger.warning(f"Could not import API routers: {e}")


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