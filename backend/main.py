import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response

from backend.config import DATA_DIR, RATE_LIMIT_PER_MINUTE
from backend.database import init_db
from backend.scheduler.job_queue import JobQueue
from backend.scheduler.worker import ScanWorker

logger = logging.getLogger("uvicorn")

worker: ScanWorker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker
    logger.info("Starting up...")
    init_db()
    job_queue = JobQueue()
    worker = ScanWorker(job_queue)
    worker.start()
    yield
    logger.info("Shutting down...")
    if worker:
        worker.stop()


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

connected_websockets: dict = {}


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    connected_websockets.setdefault(scan_id, set()).add(websocket)
    try:
        while True:
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
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        connected_websockets.get(scan_id, set()).discard(websocket)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI Nmap Scanner", "version": "1.0.0"}


frontend_dir = DATA_DIR.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
