from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

from backend.config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,
)

if "sqlite" in DATABASE_URL:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from backend.models.user import User
    from backend.models.target import Target, TargetGroup
    from backend.models.scan import ScanJob, ScanProfile, ScanResult, HostResult, PortResult, ServiceResult
    from backend.models.ai_insight import AIInsight, RiskScore, Recommendation
    from backend.models.audit import AuditEvent
    from backend.auth.jwt import pwd_context
    Base.metadata.create_all(bind=engine)

    # Create default admin user if not exists
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@localhost",
                hashed_password=pwd_context.hash("admin"),
                role="admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()