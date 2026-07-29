import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.config import DEFAULT_SCAN_PROFILES
from backend.database import get_db
from backend.exporters.csv_exporter import CSVExporter
from backend.exporters.json_exporter import JSONExporter
from backend.exporters.report_exporter import ReportExporter
from backend.exporters.xml_exporter import XMLExporter
from backend.models.scan import HostResult, PortResult, ScanJob, ScanProfile, ScanResult, ServiceResult
from backend.models.target import Target
from backend.models.user import User
from backend.api.auth import get_current_user
from backend.scheduler.job_queue import JobQueue

router = APIRouter(prefix="/api/v1", tags=["scans"])

EXPORTERS = {
    "json": JSONExporter(),
    "csv": CSVExporter(),
    "xml": XMLExporter(),
    "report": ReportExporter(),
}


class ScanProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    ports: Optional[str] = None
    scan_type: str = "tcp_connect"
    timing: Optional[str] = "T3"
    discovery: bool = False
    service_detect: bool = False
    os_detect: bool = False
    udp_ports: Optional[str] = None


class ScanProfileResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    ports: Optional[str]
    scan_type: str
    timing: Optional[str]
    is_builtin: bool

    model_config = {"from_attributes": True}


class ScanLaunchRequest(BaseModel):
    name: str
    target_id: int
    profile_id: str | int | None = None


class ScanJobResponse(BaseModel):
    id: int
    name: str
    target_id: int
    profile_id: Optional[int]
    status: str
    progress: float
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    id: int
    status: str
    progress: float
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class HostResponse(BaseModel):
    id: int
    ip: str
    hostname: Optional[str]
    status: str
    os_guess: Optional[str]
    port_count: int = 0
    is_alive: bool = True

    model_config = {"from_attributes": True}

    model_config = {"from_attributes": True}


class PortResponse(BaseModel):
    id: int
    port: int
    protocol: str
    state: str
    service_name: str
    service_version: Optional[str]
    product: Optional[str]
    banner: Optional[str]

    model_config = {"from_attributes": True}

    model_config = {"from_attributes": True}


class HostDetailResponse(HostResponse):
    ports: List[PortResponse] = []


@router.get("/scan-profiles", response_model=List[ScanProfileResponse])
async def list_profiles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db_profiles = db.query(ScanProfile).all()
    result = []
    for name, data in DEFAULT_SCAN_PROFILES.items():
        result.append(ScanProfileResponse(
            id=name,
            name=data["name"],
            description=data.get("description"),
            ports=data.get("ports"),
            scan_type=data.get("scan_type", "tcp_connect"),
            timing=data.get("timing"),
            is_builtin=True,
        ))
    for p in db_profiles:
        result.append(ScanProfileResponse(
            id=str(p.id),
            name=p.name,
            description=p.description,
            ports=p.ports,
            scan_type=p.scan_type,
            timing=p.timing,
            is_builtin=False,
        ))
    return result


@router.post("/scan-profiles", response_model=ScanProfileResponse, status_code=201)
async def create_profile(
    req: ScanProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    profile = ScanProfile(
        name=req.name,
        description=req.description,
        ports=req.ports,
        scan_type=req.scan_type,
        timing=req.timing,
        discovery=req.discovery,
        service_detect=req.service_detect,
        os_detect=req.os_detect,
        udp_ports=req.udp_ports,
        created_by=current_user.id,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.post("/scans", response_model=ScanJobResponse, status_code=201)
async def launch_scan(
    req: ScanLaunchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == req.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    profile = None
    if req.profile_id:
        if req.profile_id in DEFAULT_SCAN_PROFILES:
            profile_data = DEFAULT_SCAN_PROFILES[req.profile_id]
            profile = ScanProfile(
                name=profile_data["name"],
                ports=profile_data.get("ports"),
                scan_type=profile_data.get("scan_type", "tcp_connect"),
                timing=profile_data.get("timing"),
            )
        else:
            profile = db.query(ScanProfile).filter(ScanProfile.id == req.profile_id).first()
            if not profile:
                raise HTTPException(status_code=404, detail="Profile not found")

    scan_job = ScanJob(
        name=req.name,
        target_id=target.id,
        profile_id=profile.id if profile else None,
        status="pending",
        created_by=current_user.id,
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    JobQueue().enqueue(str(scan_job.id))
    return scan_job


@router.get("/scans", response_model=List[ScanJobResponse])
async def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    query = db.query(ScanJob)
    if status:
        query = query.filter(ScanJob.status == status)
    if target_id:
        query = query.filter(ScanJob.target_id == target_id)
    jobs = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()
    return jobs


@router.get("/scans/{scan_id}", response_model=ScanJobResponse)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    queue_status = JobQueue().get_status(scan_id)
    progress = queue_status.get("progress", 0.0) if queue_status else 0.0
    return ScanStatusResponse(
        id=str(job.id),
        status=job.status,
        progress=progress,
        error_message=job.error_message,
    )


@router.get("/scans/{scan_id}/results")
async def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results yet")
    if result.normalized_data:
        return json.loads(result.normalized_data)
    return {"raw": result.raw_data}


@router.get("/scans/{scan_id}/raw")
async def get_raw_output(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return Response(content=job.raw_output or "", media_type="text/plain")


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Scan is already {job.status}")
    JobQueue().cancel(scan_id)
    job.status = "cancelled"
    db.commit()
    return {"message": "Scan cancelled", "id": scan_id}


@router.post("/scans/{scan_id}/pause")
async def pause_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")
    JobQueue().pause(scan_id)
    job.status = "paused"
    db.commit()
    return {"message": "Scan paused", "id": scan_id}


@router.post("/scans/{scan_id}/resume")
async def resume_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "paused":
        raise HTTPException(status_code=400, detail="Scan is not paused")
    JobQueue().resume(scan_id)
    job.status = "pending"
    db.commit()
    return {"message": "Scan resumed", "id": scan_id}


@router.get("/scans/{scan_id}/hosts", response_model=List[HostResponse])
async def list_scan_hosts(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    hosts = db.query(HostResult).filter(HostResult.scan_job_id == int(scan_id)).all()
    if not hosts:
        raise HTTPException(status_code=404, detail="No hosts found yet")
    output = []
    for h in hosts:
        port_count = db.query(PortResult).filter(PortResult.host_id == h.id).count()
        output.append(HostResponse(
            id=str(h.id),
            ip=h.ip,
            hostname=h.hostname,
            status=h.status,
            os_guess=h.os_guess,
            port_count=port_count,
        ))
    return output


@router.get("/scans/{scan_id}/hosts/{host_id}", response_model=HostDetailResponse)
async def get_host_detail(
    scan_id: int,
    host_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    host = db.query(HostResult).filter(HostResult.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    ports = db.query(PortResult).filter(PortResult.host_id == host.id).all()
    port_list = []
    for p in ports:
        svc = db.query(ServiceResult).filter(ServiceResult.port_result_id == p.id).first()
        port_list.append(PortResponse(
            id=str(p.id),
            port=p.port,
            protocol=p.protocol,
            state=p.state,
            service_name=p.service_name,
            product=svc.product if svc else None,
            version=svc.version if svc else None,
        ))
    return HostDetailResponse(
        id=str(host.id),
        ip=host.ip,
        hostname=host.hostname,
        status=host.status,
        os_guess=host.os_guess,
        port_count=len(port_list),
        ports=port_list,
    )


@router.get("/scans/export/{scan_id}")
async def export_scan(
    scan_id: int,
    format: str = Query("json", regex="^(json|csv|xml|report)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    result = db.query(ScanResult).filter(ScanResult.scan_job_id == scan_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="No results yet")

    if result.normalized_data:
        data = json.loads(result.normalized_data)
    else:
        data = {"raw": result.raw_data, "hosts": []}

    exporter = EXPORTERS.get(format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    content = exporter.export(data)
    return Response(
        content=content,
        media_type=exporter.get_mime_type(),
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}{exporter.get_extension()}"},
    )
