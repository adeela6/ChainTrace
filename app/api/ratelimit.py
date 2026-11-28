import threading
import time
from collections import deque

from fastapi import Request
from sqlalchemy.orm import Session

from app.api.errors import err
from app.repository import audit

_UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def parse_limit(spec: str) -> tuple[int, int]:
    count, _, unit = spec.partition("/")
    return int(count), _UNITS[unit.strip().rstrip("s")]


class RateLimiter:
 
    def __init__(self) -> None:
        self._hits: dict[tuple, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: tuple, spec: str) -> bool:
        limit, window = parse_limit(spec)
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True


def enforce_rate_limit(
    request: Request,
    db: Session,
    *,
    scope: str,
    key: tuple,
    spec: str,
    actor_id: str | None = None,
    actor_role: str | None = None,
) -> None:

    if request.app.state.limiter.allow((scope, *key), spec):
        return
    audit.log_request(
        db, request,
        actor_id=actor_id, actor_role=actor_role,
        event_type="RATE_LIMITED", outcome="DENIED",
        details={"scope": scope},
        commit=True,
    )
    raise err("RATE_LIMITED")