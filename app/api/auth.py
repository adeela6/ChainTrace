import secrets

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select

from app.api.deps import SESSION_COOKIE, CurrentAuth, DbSession
from app.api.errors import err
from app.api.ratelimit import enforce_rate_limit
from app.api.security import DUMMY_HASH, utc_after, verify_password
from app.repository import audit
from app.repository.models import User, UserSession, utc_now

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown JSON fields rejected

    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=1024)


def _user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "key_fingerprint": user.key_fingerprint,
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response, db: DbSession):
    settings = request.app.state.settings
    ip = request.client.host if request.client else "unknown"

    
    enforce_rate_limit(
        request, db,
        scope="login", key=(ip, body.username.lower()),
        spec=settings.RATE_LIMIT_LOGIN,
    )

    user = db.scalar(select(User).where(User.username == body.username))
    password_ok = verify_password(user.password_hash if user else DUMMY_HASH, body.password)

    if user is None or not user.is_active or not password_ok:
        audit.log_request(
            db, request,
            actor_id=None, actor_role=None,
            event_type="LOGIN_FAILED", outcome="FAILURE",
            details={"username": body.username},  # the typed username and nothing else
            commit=True,
        )
        raise err("INVALID_CREDENTIALS")  # same answer for every failure reason

    now = utc_now()
    db.execute(  
        delete(UserSession).where(
            UserSession.user_id == user.id, UserSession.expires_at <= now
        )
    )
    session = UserSession(
        id=secrets.token_urlsafe(32),  # always a NEW session: no session fixation
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        expires_at=utc_after(settings.SESSION_IDLE_MINUTES),
    )
    db.add(session)
    audit.log_request(
        db, request,
        actor_id=user.id, actor_role=user.role,
        event_type="LOGIN", outcome="SUCCESS",
        target_type="user", target_id=user.id,
    )
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE,
        value=session.id,
        httponly=True,
        samesite="strict",
        secure=settings.SESSION_COOKIE_SECURE,
        path="/",
    )
    return {"user": _user_payload(user), "csrf_token": session.csrf_token}


@router.post("/logout")
def logout(request: Request, response: Response, ctx: CurrentAuth, db: DbSession):
    audit.log_request(
        db, request,
        actor_id=ctx.user.id, actor_role=ctx.user.role,
        event_type="LOGOUT", outcome="SUCCESS",
        target_type="user", target_id=ctx.user.id,
    )
    db.delete(ctx.session)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    return {"ok": True}


@router.get("/me")
def me(ctx: CurrentAuth):
    return {"user": _user_payload(ctx.user), "csrf_token": ctx.session.csrf_token}