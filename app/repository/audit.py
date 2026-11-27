import json

from fastapi import Request
from sqlalchemy.orm import Session

from app.repository.models import AuditEvent

EVENT_TYPES = frozenset({
    "LOGIN", "LOGOUT", "LOGIN_FAILED", "SESSION_EXPIRED", "USER_CREATED",
    "ROLE_CHANGED", "CONFIG_CHANGED", "CASE_CREATED", "EVIDENCE_REGISTERED",
    "UPLOAD_REJECTED", "TRANSFER_CREATED", "TRANSFER_ACCEPTED",
    "TRANSFER_REJECTED", "VERIFICATION_RUN", "REPORT_EXPORTED",
    "AUDIT_EXPORTED", "ACCESS_DENIED", "RATE_LIMITED",
})
OUTCOMES = frozenset({"SUCCESS", "FAILURE", "DENIED"})

FORBIDDEN_KEYS = frozenset({
    "password", "passwd", "new_password", "session_id", "session",
    "csrf_token", "private_key", "encrypted_private_key", "master_key",
    "content", "file_content", "file_contents",
})


def _check_details(value) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                raise ValueError(f"Forbidden key '{k}' in audit details")
            _check_details(v)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_details(item)


def log(
    db: Session,
    *,
    actor_id: str | None,
    actor_role: str | None,
    event_type: str,
    outcome: str,
    ip: str | None,
    request_id: str | None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> AuditEvent:
    """The ONLY way to write an audit event. Everyone calls this.

    commit=False: joins the caller's transaction (flush only).
    commit=True : commits right away. Use this for FAILURE/DENIED events:
                  call db.rollback() first, then log(..., commit=True), so the
                  audit row survives even though the main action was rolled back.
    """
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown audit event_type: {event_type}")
    if outcome not in OUTCOMES:
        raise ValueError(f"Unknown audit outcome: {outcome}")
    _check_details(details)

    event = AuditEvent(
        actor_id=actor_id,
        actor_role=actor_role,
        event_type=event_type,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        ip=ip,
        request_id=request_id,
        details_json=json.dumps(details or {}, sort_keys=True, ensure_ascii=False),
    )
    db.add(event)
    if commit:
        db.commit()
    else:
        db.flush()
    return event


def log_request(
    db: Session,
    request: Request,
    *,
    actor_id: str | None,
    actor_role: str | None,
    event_type: str,
    outcome: str,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> AuditEvent:
    return log(
        db,
        actor_id=actor_id,
        actor_role=actor_role,
        event_type=event_type,
        outcome=outcome,
        ip=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None),
        target_type=target_type,
        target_id=target_id,
        details=details,
        commit=commit,
    )