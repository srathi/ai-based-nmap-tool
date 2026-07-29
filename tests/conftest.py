import sys
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.sql import func

from backend.config import SECRET_KEY, ALGORITHM
from jose import jwt
from datetime import datetime, timezone, timedelta

TestBase = declarative_base()


class User(TestBase):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class TargetGroup(TestBase):
    __tablename__ = "target_groups"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Target(TestBase):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    target_value = Column(String, nullable=False)
    target_type = Column(String, default="ip")
    project = Column(String, nullable=True)
    tags = Column(String, nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanProfile(TestBase):
    __tablename__ = "scan_profiles"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, default="")
    ports = Column(String, default="22,80,443")
    scan_type = Column(String, default="tcp_connect")
    timing = Column(String, default="T3")
    is_builtin = Column(Boolean, default=False)
    discovery = Column(Boolean, default=True)
    service_detect = Column(Boolean, default=False)
    os_detect = Column(Boolean, default=False)
    udp_ports = Column(String, nullable=True)
    created_by = Column(Integer, nullable=True)


class ScanJob(TestBase):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=False)
    created_by = Column(Integer, nullable=True)
    status = Column(String, default="pending")
    progress = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    target = relationship("Target")
    profile = relationship("ScanProfile")


class ScanResult(TestBase):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    raw_data = Column(Text, nullable=True)
    normalized_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class HostResult(TestBase):
    __tablename__ = "host_results"
    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    ip = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    mac_addr = Column(String, nullable=True)
    os_guess = Column(String, nullable=True)
    latency_ms = Column(Float, nullable=True)
    status = Column(String, default="unknown")
    is_alive = Column(Boolean, default=False)


class PortResult(TestBase):
    __tablename__ = "port_results"
    id = Column(Integer, primary_key=True)
    host_result_id = Column(Integer, ForeignKey("host_results.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    state = Column(String, default="closed")
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    service_product = Column(String, nullable=True)
    banner = Column(String, nullable=True)


class AIInsight(TestBase):
    __tablename__ = "ai_insights"
    id = Column(Integer, primary_key=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    insight_type = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    evidence_refs = Column(String, nullable=True)
    confidence = Column(Float, default=0.0)
    model_used = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class RiskScore(TestBase):
    __tablename__ = "risk_scores"
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, nullable=True)
    port_id = Column(Integer, nullable=True)
    score = Column(Float, default=0.0)
    severity = Column(String, default="info")
    factors = Column(String, nullable=True)
    recommendation = Column(String, nullable=True)


class Recommendation(TestBase):
    __tablename__ = "recommendations"
    id = Column(Integer, primary_key=True)
    category = Column(String, nullable=False)
    priority = Column(String, default="medium")
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence_refs = Column(String, nullable=True)


class AuditEvent(TestBase):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    success = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


model_modules = {
    "backend.models.user": ["User", "UserRole"],
    "backend.models.target": ["Target", "TargetGroup"],
    "backend.models.scan": ["ScanJob", "ScanProfile", "ScanResult", "HostResult", "PortResult", "ServiceResult"],
    "backend.models.ai_insight": ["AIInsight", "RiskScore", "Recommendation"],
    "backend.models.audit": ["AuditEvent"],
}

class FakeUserRole:
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

for mod_name, names in model_modules.items():
    mod = type(sys)(mod_name)
    for name in names:
        if name == "UserRole":
            setattr(mod, name, FakeUserRole)
        elif name in globals():
            setattr(mod, name, globals()[name])
        elif name == "ServiceResult":
            svc_base = type("ServiceResult", (TestBase,), {
                "__tablename__": "service_results",
                "id": Column(Integer, primary_key=True),
                "port_result_id": Column(Integer, ForeignKey("port_results.id")),
                "name": Column(String, default=""),
                "product": Column(String, default=""),
                "version": Column(String, default=""),
                "extra_info": Column(String, default=""),
            })
            setattr(mod, name, svc_base)
    sys.modules[mod_name] = mod


def _test_db_dep():
    raise RuntimeError("Must be overridden in tests")


def _build_test_app():
    from fastapi import FastAPI, Depends, HTTPException, status
    from fastapi.security import OAuth2PasswordBearer
    from passlib.context import CryptContext
    from pydantic import BaseModel
    from typing import Optional

    app = FastAPI()
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    class LoginRequest(BaseModel):
        username: str
        password: str

    class RegisterRequest(BaseModel):
        username: str
        password: str
        email: Optional[str] = None
        role: Optional[str] = "viewer"

    class TokenResponse(BaseModel):
        access_token: str
        token_type: str = "bearer"

    class UserInfo(BaseModel):
        id: str
        username: str
        email: Optional[str]
        role: str
        is_active: bool

    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=1440))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(_test_db_dep)):
        credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if not token:
            raise credentials_exception
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            if user_id is None:
                raise credentials_exception
        except Exception:
            raise credentials_exception
        user = db.query(User).filter(User.id == int(user_id)).first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user

    def get_admin_user(current_user: User = Depends(get_current_user)):
        if current_user.role != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
        return current_user

    @app.post("/api/v1/auth/login")
    async def login(req: LoginRequest, db=Depends(_test_db_dep)):
        db_session = db
        user = db_session.query(User).filter(User.username == req.username).first()
        if not user or not pwd_context.verify(req.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        token = create_access_token(data={"sub": str(user.id), "role": user.role})
        return TokenResponse(access_token=token)

    @app.post("/api/v1/auth/register")
    async def register(req: RegisterRequest, db=Depends(_test_db_dep), admin: User = Depends(get_admin_user)):
        db_session = db
        existing = db_session.query(User).filter(User.username == req.username).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")
        hashed = pwd_context.hash(req.password)
        user = User(username=req.username, email=req.email, hashed_password=hashed, role=req.role)
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        token = create_access_token(data={"sub": str(user.id), "role": user.role})
        return TokenResponse(access_token=token)

    @app.get("/api/v1/auth/me")
    async def me(current_user: User = Depends(get_current_user)):
        return UserInfo(id=str(current_user.id), username=current_user.username, email=current_user.email, role=current_user.role, is_active=current_user.is_active)

    @app.get("/api/v1/health")
    async def health():
        return {"status": "ok", "service": "ai-based-nmap-tool"}

    @app.get("/api/v1/targets")
    async def get_targets(db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        targets = db.query(Target).all()
        return [{"id": t.id, "name": t.name, "target_value": t.target_value, "target_type": t.target_type} for t in targets]

    @app.post("/api/v1/targets")
    async def create_target(req_data: dict, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        target = Target(name=req_data.get("name", ""), target_value=req_data.get("target_value", ""), target_type=req_data.get("target_type", "ip"), created_by=current_user.id)
        db.add(target)
        db.commit()
        db.refresh(target)
        return {"id": target.id, "name": target.name, "target_value": target.target_value, "target_type": target.target_type}

    @app.delete("/api/v1/targets/{target_id}")
    async def delete_target(target_id: int, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        db.delete(target)
        db.commit()
        return {"message": "Target deleted"}

    @app.post("/api/v1/scans")
    async def launch_scan(req_data: dict, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        job = ScanJob(name=req_data.get("name", "scan"), target_id=req_data.get("target_id"), profile_id=req_data.get("profile_id"), created_by=current_user.id, status="running")
        db.add(job)
        db.commit()
        db.refresh(job)
        return {"id": job.id, "name": job.name, "status": job.status}

    @app.get("/api/v1/scans")
    async def get_scans(db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        jobs = db.query(ScanJob).all()
        return [{"id": j.id, "name": j.name, "status": j.status} for j in jobs]

    @app.post("/api/v1/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: int, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not job:
            raise HTTPException(status_code=404, detail="Scan not found")
        job.status = "cancelled"
        db.commit()
        return {"message": "Scan cancelled"}

    @app.get("/api/v1/scans/{scan_id}/results")
    async def get_scan_results(scan_id: int, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
        if not result:
            return {"scan_job_id": scan_id, "hosts": [], "host_count": 0, "port_count": 0}
        import json
        data = json.loads(result.normalized_data) if result.normalized_data else {"hosts": []}
        return {"scan_job_id": scan_id, "hosts": data.get("hosts", []), "host_count": len(data.get("hosts", [])), "port_count": 0}

    @app.get("/api/v1/scans/{scan_id}/export/json")
    async def export_json(scan_id: int, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
        if not result:
            return {"error": "No results"}
        import json
        data = json.loads(result.normalized_data) if result.normalized_data else {}
        return data

    @app.get("/api/v1/scans/{scan_id}/export/csv")
    async def export_csv(scan_id: int, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        from fastapi.responses import PlainTextResponse
        import csv, io
        result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
        if not result:
            return PlainTextResponse("", media_type="text/csv")
        import json
        data = json.loads(result.normalized_data) if result.normalized_data else {"hosts": []}
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "port", "protocol", "state", "service"])
        for host in data.get("hosts", []):
            ip = host.get("ip", "")
            for port in host.get("ports", []):
                writer.writerow([ip, port.get("port"), port.get("protocol"), port.get("state"), port.get("service_name")])
        return PlainTextResponse(output.getvalue(), media_type="text/csv")

    @app.post("/api/v1/scans/{scan_id}/ai/query")
    async def ai_query(scan_id: int, req_data: dict, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        query = req_data.get("query", "").lower()
        result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
        import json
        data = json.loads(result.normalized_data) if result and result.normalized_data else {"hosts": []}
        hosts = data.get("hosts", [])
        if "ports" in query and "open" in query:
            ports = []
            for h in hosts:
                for p in h.get("ports", []):
                    if p.get("state") == "open":
                        ports.append(f"{h['ip']}:{p['port']}")
            answer = f"Open ports: {', '.join(ports)}" if ports else "No open ports found"
            return {"answer": answer, "confidence": 0.9, "evidence_refs": []}
        if "host" in query and "many" in query:
            return {"answer": f"Found {len(hosts)} host(s)", "confidence": 1.0, "evidence_refs": []}
        return {"answer": "I don't understand that question.", "confidence": 0.1, "evidence_refs": []}

    @app.post("/api/v1/scans/compare")
    async def compare_scans(req_data: dict, db=Depends(_test_db_dep), current_user: User = Depends(get_current_user)):
        return {"new_hosts": [], "removed_hosts": [], "new_ports": [], "removed_ports": [], "summary": "No differences found"}

    return app


@pytest.fixture
def test_db():
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestBase.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)
    session = TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_user(test_db):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=pwd_context.hash("testpass123"),
        role="viewer",
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def test_admin_user(test_db):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    user = User(
        username="adminuser",
        email="admin@example.com",
        hashed_password=pwd_context.hash("adminpass123"),
        role="admin",
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def client(test_db):
    app = _build_test_app()

    def override_test_db():
        yield test_db

    app.dependency_overrides[_test_db_dep] = override_test_db
    from fastapi.testclient import TestClient
    return TestClient(app)


@pytest.fixture
def sample_scan_result():
    return {
        "success": True,
        "command": "nmap -sT -p 22,80,443 -T3 -oX - 192.168.1.1 10.0.0.1",
        "return_code": 0,
        "duration_ms": 15234,
        "error": "",
        "warning": "",
        "hosts": [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "mac": "00:11:22:33:44:55",
                "os_guess": "Linux 5.4",
                "latency": "1.23ms",
                "status": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "OpenSSH 8.0", "service_product": "", "banner": ""},
                    {"port": 80, "protocol": "tcp", "state": "open", "service_name": "http", "service_version": "nginx 1.18", "service_product": "", "banner": ""},
                    {"port": 443, "protocol": "tcp", "state": "open", "service_name": "https", "service_version": "nginx 1.18", "service_product": "", "banner": ""},
                ],
            },
            {
                "ip": "10.0.0.1",
                "hostname": "",
                "mac": "AA:BB:CC:DD:EE:FF",
                "os_guess": "",
                "latency": "0.87ms",
                "status": "up",
                "ports": [
                    {"port": 3306, "protocol": "tcp", "state": "open", "service_name": "mysql", "service_version": "MySQL 8.0", "service_product": "", "banner": ""},
                    {"port": 8080, "protocol": "tcp", "state": "filtered", "service_name": "", "service_version": "", "service_product": "", "banner": ""},
                ],
            },
        ],
        "stats": {"elapsed": 15.234, "total_hosts": 2, "total_ports": 5},
    }


@pytest.fixture
def sample_raw_nmap():
    return """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -p 22,80 -T3 -oX - 192.168.1.1" start="1700000000">
  <scaninfo type="connect" protocol="tcp" numservices="2"/>
  <verbose level="0"/>
  <debugging level="0"/>
  <host starttime="1700000000" endtime="1700000001">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="gateway.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/>
      </port>
    </ports>
    <times srtt="1234" rttvar="567" to="100000"/>
  </host>
  <host starttime="1700000000" endtime="1700000002">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" method="probed" conf="10"/>
      </port>
    </ports>
    <times srtt="870" rttvar="200" to="100000"/>
  </host>
  <runstats>
    <finished time="1700000002" timestr="..." elapsed="2.05" summary="done"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>"""


@pytest.fixture
def auth_headers(test_db, test_user):
    token = jwt.encode(
        {"sub": str(test_user.id), "role": test_user.role, "exp": datetime.now(timezone.utc) + timedelta(hours=24)},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(test_db, test_admin_user):
    token = jwt.encode(
        {"sub": str(test_admin_user.id), "role": test_admin_user.role, "exp": datetime.now(timezone.utc) + timedelta(hours=24)},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def MockNmapScanner():
    from backend.engine.scanner import NmapScanner

    original_scan = NmapScanner.scan
    original_discovery = NmapScanner.discovery

    def mock_scan(self, target, ports="22,80,443", scan_type="tcp_connect", timing="T3", service_detect=False, os_detect=False, udp_ports=None):
        return {
            "success": True,
            "command": f"nmap -sT -p {ports} -T{timing[-1]} -oX - {target}",
            "return_code": 0,
            "duration_ms": 1000,
            "hosts": [
                {
                    "ip": target if not target.startswith("192") else target,
                    "hostname": "test-host.local",
                    "mac": "00:11:22:33:44:55",
                    "os_guess": "Linux 5.4",
                    "latency": "1.23ms",
                    "status": "up",
                    "ports": [
                        {"port": 22, "protocol": "tcp", "state": "open", "service_name": "ssh", "service_version": "OpenSSH 8.0", "service_product": "", "banner": ""},
                    ],
                }
            ],
            "stats": {"elapsed": 1.0, "total_hosts": 1, "total_ports": 1},
        }

    def mock_discovery(self, target, ports="22,80,443"):
        return {
            "success": True,
            "command": f"nmap -sn -oX - {target}",
            "return_code": 0,
            "duration_ms": 500,
            "hosts": [
                {"ip": target, "hostname": "", "mac": "", "latency": "0.50ms"},
            ],
            "total_hosts": 1,
        }

    NmapScanner.scan = mock_scan
    NmapScanner.discovery = mock_discovery
    yield
    NmapScanner.scan = original_scan
    NmapScanner.discovery = original_discovery
