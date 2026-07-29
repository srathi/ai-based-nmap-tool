import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.exporters.csv_exporter import CSVExporter
from backend.exporters.json_exporter import JSONExporter
from backend.exporters.report_exporter import ReportExporter
from backend.exporters.xml_exporter import XMLExporter
from backend.models.scan import ScanJob, ScanResult
from backend.models.user import User
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])

EXPORTERS = {
    "json": JSONExporter(),
    "csv": CSVExporter(),
    "xml": XMLExporter(),
    "report": ReportExporter(),
}


class ScheduledExport(BaseModel):
    id: str
    scan_id: str
    format: str
    created_at: str

    model_config = {"from_attributes": True}


@router.get("/{scan_id}")
async def export_results(
    scan_id: str,
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
        data = {"hosts": [], "total_hosts": 0}

    exporter = EXPORTERS.get(format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    content = exporter.export(data)
    return Response(
        content=content,
        media_type=exporter.get_mime_type(),
        headers={
            "Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}_{format}{exporter.get_extension()}"
        },
    )


@router.get("/scheduled", response_model=List[ScheduledExport])
async def list_scheduled_exports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return []
