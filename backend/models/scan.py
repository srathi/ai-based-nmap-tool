from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Enum, ForeignKey, Text
from backend.database import Base
import enum


class ScanType(str, enum.Enum):
    TCP_CONNECT = "tcp_connect"
    SYN = "syn"
    UDP = "udp"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class HostStatus(str, enum.Enum):
    UP = "up"
    DOWN = "down"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class PortProtocol(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    ports = Column(String, nullable=False)
    scan_type = Column(Enum(ScanType), default=ScanType.TCP_CONNECT)
    timing = Column(String, default="T3")
    discovery = Column(Boolean, default=True)
    service_detect = Column(Boolean, default=False)
    os_detect = Column(Boolean, default=False)
    udp_ports = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Float, default=0.0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    raw_output = Column(Text, nullable=True)
    normalized_at = Column(DateTime, default=datetime.utcnow)
    normalized_data = Column(Text, nullable=True)
    host_count = Column(Integer, default=0)
    port_count = Column(Integer, default=0)


class HostResult(Base):
    __tablename__ = "host_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    ip = Column(String, nullable=False)
    hostname = Column(String, nullable=True)
    mac_addr = Column(String, nullable=True)
    os_guess = Column(String, nullable=True)
    latency_ms = Column(Float, nullable=True)
    status = Column(Enum(HostStatus), default=HostStatus.UP)
    is_alive = Column(Boolean, default=True)


class PortResult(Base):
    __tablename__ = "port_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=False)
    host_id = Column(Integer, ForeignKey("host_results.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(Enum(PortProtocol), default=PortProtocol.TCP)
    state = Column(Enum(PortState), default=PortState.OPEN)
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    service_product = Column(String, nullable=True)
    banner = Column(String, nullable=True)


class ServiceResult(Base):
    __tablename__ = "service_results"

    id = Column(Integer, primary_key=True, index=True)
    port_id = Column(Integer, ForeignKey("port_results.id"), nullable=False)
    name = Column(String, nullable=True)
    version = Column(String, nullable=True)
    product = Column(String, nullable=True)
    extra_info = Column(Text, nullable=True)
    cpe = Column(String, nullable=True)
