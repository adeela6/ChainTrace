from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def new_id() -> str:
    return str(uuid4())


def utc_now() -> str:
    return (
        datetime.now(UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin','analyst','viewer')", name="ck_users_role"),
    )

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str]
    role: Mapped[str]
    public_key: Mapped[str | None]             
    encrypted_private_key: Mapped[str | None]   
    key_fingerprint: Mapped[str | None]        
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[str] = mapped_column(default=utc_now)


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    csrf_token: Mapped[str]
    created_at: Mapped[str] = mapped_column(default=utc_now)
    last_seen_at: Mapped[str] = mapped_column(default=utc_now)
    expires_at: Mapped[str]


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    case_number: Mapped[str] = mapped_column(unique=True)   
    title: Mapped[str]
    description: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[str] = mapped_column(default=utc_now)


class CaseMember(Base):
    __tablename__ = "case_members"

    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), primary_key=True)


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("case_id", "sha256", name="uq_evidence_case_sha256"),
    )

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"))
    original_filename: Mapped[str]             
    stored_filename: Mapped[str]               
    mime_type: Mapped[str]
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str]                       
    registered_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    current_custodian_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    registered_at: Mapped[str] = mapped_column(default=utc_now)


class Block(Base):
    
    __tablename__ = "blocks"

    index: Mapped[int] = mapped_column(
        "index", Integer, primary_key=True, autoincrement=False
    )
    block_id: Mapped[str] = mapped_column(unique=True, default=new_id)
    timestamp: Mapped[str] = mapped_column(default=utc_now)
    case_id: Mapped[str | None]         
    evidence_id: Mapped[str | None]      
    event_type: Mapped[str]             
    actor_id: Mapped[str | None]        
    key_fingerprint: Mapped[str | None]
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str]
    signature: Mapped[str | None]      
    block_hash: Mapped[str] = mapped_column(unique=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "outcome IN ('SUCCESS','FAILURE','DENIED')", name="ck_audit_outcome"
        ),
    )

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    timestamp: Mapped[str] = mapped_column(default=utc_now)
    actor_id: Mapped[str | None]
    actor_role: Mapped[str | None]
    event_type: Mapped[str]
    target_type: Mapped[str | None]
    target_id: Mapped[str | None]
    outcome: Mapped[str]
    ip: Mapped[str | None]
    request_id: Mapped[str | None]
    details_json: Mapped[str] = mapped_column(Text, default="{}")


class ConfigEntry(Base):
    __tablename__ = "config"

    key: Mapped[str] = mapped_column(primary_key=True)
    value: Mapped[str]
    updated_by: Mapped[str | None]
    updated_at: Mapped[str] = mapped_column(default=utc_now)


class VerificationResult(Base):
    """Stored verification runs. Append-only (clarification #4)."""
    __tablename__ = "verification_results"

    id: Mapped[str] = mapped_column(primary_key=True, default=new_id)
    scope: Mapped[str]                  
    target_id: Mapped[str | None]
    status: Mapped[str]                
    result_json: Mapped[str] = mapped_column(Text)
    run_by: Mapped[str]
    run_at: Mapped[str] = mapped_column(default=utc_now)