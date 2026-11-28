import secrets
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.api.errors import err
from app.api.security import utc_after
from app.repository import audit
from app.repository.models import User, UserSession, utc_now

SESSION_COOKIE = "chaintrace_session"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


@dataclass
class AuthContext:
    user: User
    session: UserSession


def require_session(
    request: Request,
    db: DbSession,
    x_csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuthContext:
   
    settings = request.app.state.settings

    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        raise err("UNAUTHENTICATED")
    session = db.get(UserSession, session_id)
    if session is None:
        raise err("UNAUTHENTICATED")

    now = utc_now()
    user = db.get(User, session.user_id)

    if session.expires_at <= now:
        db.delete(session)
        audit.log_request(
            db, request,
            actor_id=session.user_id, actor_role=user.role if user else None,
            event_type="SESSION_EXPIRED", outcome="FAILURE",
            target_type="user", target_id=session.user_id,  # never the session id
            commit=True,
        )
        raise err("UNAUTHENTICATED")

    if user is None or not user.is_active:
        db.delete(session)
        db.commit()
        raise err("UNAUTHENTICATED")

    if request.method not in SAFE_METHODS:
        sent = (x_csrf_token or "").encode()
        if not secrets.compare_digest(sent, session.csrf_token.encode()):
            audit.log_request(
                db, request,
                actor_id=user.id, actor_role=user.role,
                event_type="ACCESS_DENIED", outcome="DENIED",
                details={"reason": "CSRF_FAILED", "path": request.url.path},
                commit=True,
            )
            raise err("CSRF_FAILED")

    session.last_seen_at = now
    session.expires_at = utc_after(settings.SESSION_IDLE_MINUTES)
    db.commit()
    return AuthContext(user=user, session=session)


CurrentAuth = Annotated[AuthContext, Depends(require_session)]


def require_role(*roles: str):
    
    def dependency(request: Request, ctx: CurrentAuth, db: DbSession) -> AuthContext:
        if ctx.user.role not in roles:
            audit.log_request(
                db, request,
                actor_id=ctx.user.id, actor_role=ctx.user.role,
                event_type="ACCESS_DENIED", outcome="DENIED",
                details={"required_roles": sorted(roles), "path": request.url.path},
                commit=True,
            )
            raise err("FORBIDDEN")
        return ctx

    return dependency