from typing import List, Optional

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.engine.target_parser import TargetParser
from backend.models.target import Target
from backend.models.user import User
from backend.api.auth import get_current_user

router = APIRouter(prefix="/api/v1", tags=["targets"])


class TargetCreate(BaseModel):
    name: str
    target_value: str
    target_type: str = "ip"
    project: Optional[str] = None
    tags: Optional[list] = None


class TargetResponse(BaseModel):
    id: int
    name: str
    target_value: str
    target_type: str
    project: Optional[str]
    tags: Optional[list]
    created_by: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TargetGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None


class TargetGroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_by: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ValidateResponse(BaseModel):
    valid: bool
    type: str
    message: str


class BatchTargetCreate(BaseModel):
    targets: List[str]
    description: Optional[str] = None


@router.post("/targets", response_model=TargetResponse, status_code=201)
async def create_target(
    req: TargetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    parsed = TargetParser.parse(req.target_value)
    target = Target(
        name=req.name,
        target_value=req.target_value,
        target_type=parsed["type"],
        project=req.project,
        tags=req.tags,
        created_by=current_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets", response_model=List[TargetResponse])
async def list_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    targets = db.query(Target).filter(Target.created_by == current_user.id).offset(skip).limit(limit).all()
    return targets


@router.get("/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/targets/{target_id}", status_code=204)
async def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()


@router.post("/targets/validate", response_model=ValidateResponse)
async def validate_target(req: TargetCreate):
    try:
        parsed = TargetParser.parse(req.target_value)
        return ValidateResponse(valid=True, type=parsed["type"], message="Valid target")
    except ValueError as e:
        return ValidateResponse(valid=False, type="unknown", message=str(e))


@router.post("/targets/batch", response_model=List[TargetResponse], status_code=201)
async def batch_create_targets(
    req: BatchTargetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = []
    for t in req.targets:
        parsed = TargetParser.parse(t)
        target = Target(
            name=t,
            target_value=t,
            target_type=parsed["type"],
            created_by=current_user.id,
        )
        db.add(target)
        created.append(target)
    db.commit()
    for t in created:
        db.refresh(t)
    return created
