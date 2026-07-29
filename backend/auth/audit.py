from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models.audit import AuditEvent


class AuditLogger:
    @staticmethod
    def log_event(
        db: Session,
        user_id: int,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        details: str | None = None,
        ip_address: str | None = None,
        success: bool = True,
    ) -> AuditEvent:
        event = AuditEvent(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            success=success,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def get_recent_events(db: Session, limit: int = 50) -> list[AuditEvent]:
        return (
            db.query(AuditEvent)
            .order_by(AuditEvent.timestamp.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_events_by_user(
        db: Session, user_id: int, limit: int = 50
    ) -> list[AuditEvent]:
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.user_id == user_id)
            .order_by(AuditEvent.timestamp.desc())
            .limit(limit)
            .all()
        )
