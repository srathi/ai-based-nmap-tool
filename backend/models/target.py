from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, JSON, Table
from backend.database import Base
import enum


class TargetType(str, enum.Enum):
    IP = "ip"
    CIDR = "cidr"
    RANGE = "range"
    HOSTNAME = "hostname"
    LIST = "list"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    target_value = Column(String, nullable=False)
    target_type = Column(Enum(TargetType), nullable=False)
    project = Column(String, nullable=True)
    tags = Column(JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


target_group_association = Table(
    "target_group_association",
    Base.metadata,
    Column("target_id", Integer, ForeignKey("targets.id")),
    Column("group_id", Integer, ForeignKey("target_groups.id")),
)


class TargetGroup(Base):
    __tablename__ = "target_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
