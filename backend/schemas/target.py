from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TargetCreate(BaseModel):
    name: str
    target_value: str
    target_type: str = "ip"
    project: str | None = None
    tags: list[str] | None = None


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_value: str
    target_type: str
    project: str | None
    tags: list[str] | None
    created_by: int
    created_at: datetime


class TargetGroupCreate(BaseModel):
    name: str
    description: str | None = None


class TargetGroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    created_by: int
    created_at: datetime


class TargetValidateResponse(BaseModel):
    valid: bool
    reason: str | None = None
