from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanProfileCreate(BaseModel):
    name: str
    description: str = ""
    ports: str = "22,80,443,8080,8443"
    scan_type: str = "tcp_connect"
    timing: str = "T3"
    discovery: bool = True
    service_detect: bool = False
    os_detect: bool = False
    udp_ports: str | None = None


class ScanProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    ports: str
    scan_type: str
    timing: str
    is_builtin: bool
    created_by: int | None


class ScanJobCreate(BaseModel):
    name: str
    target_id: int
    profile_id: int


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    target_id: int
    profile_id: int
    created_by: int | None
    status: str
    progress: int
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime


class ScanJobStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    progress: int
    started_at: datetime | None
    completed_at: datetime | None


class PortResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service_name: str | None
    service_version: str | None
    service_product: str | None
    banner: str | None


class HostResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    hostname: str | None
    mac_addr: str | None
    os_guess: str | None
    latency_ms: float | None
    status: str
    is_alive: bool
    ports: list[PortResultResponse]


class ScanResultResponse(BaseModel):
    scan_job_id: int
    host_count: int
    port_count: int
    hosts: list[HostResultResponse]
