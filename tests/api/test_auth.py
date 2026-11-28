import json
from typing import Annotated

import pytest
from cryptography.fernet import Fernet
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.deps import AuthContext, require_role
from app.api.security import hash_password
from app.config import Settings
from app.main import create_app
from app.repository.models import AuditEvent, User, UserSession

PASSWORD = "correct-horse-battery"
BAD = "wrong-password-1"


@pytest.fixture
def app(tmp_path):
    settings = Settings(
        _env_file=None,
        CHAINTRACE_MASTER_KEY=Fernet.generate_key().decode(),
        DATABASE_URL=f"sqlite:///{tmp_path / 'test.db'}",
        STORAGE_DIR=str(tmp_path / "storage" / "evidence"),
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    return TestClient(app)


def make_user(app, username, role="analyst", active=True):
    with app.state.session_factory() as db:
        user = User(
            username=username,
            password_hash=hash_password(PASSWORD),
            role=role,
            is_active=active,
        )
        db.add(user)
        db.commit()
        return user.id


def audit_rows(app, event_type):
    with app.state.session_factory() as db:
        return list(
            db.scalars(select(AuditEvent).where(AuditEvent.event_type == event_type))
        )


def login(client, username="alice", password=PASSWORD):
    return client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


def test_login_success(app, client):
    make_user(app, "alice")
    r = login(client)
    assert r.status_code == 200
    body = r.json()
    assert body["csrf_token"]
    assert body["user"]["role"] == "analyst"
    assert "password_hash" not in r.text
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert len(audit_rows(app, "LOGIN")) == 1


def test_failed_logins_look_identical_and_log_only_the_username(app, client):
    make_user(app, "alice")
    a = login(client, "alice", BAD)
    b = login(client, "nobody", BAD)
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["code"] == b.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert a.json()["error"]["message"] == b.json()["error"]["message"]

    rows = audit_rows(app, "LOGIN_FAILED")
    assert sorted(json.loads(r.details_json)["username"] for r in rows) == ["alice", "nobody"]
    assert all(BAD not in r.details_json for r in rows)  # never log passwords


def test_inactive_user_cannot_log_in(app, client):
    make_user(app, "alice", active=False)
    r = login(client)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_me_requires_a_session_then_returns_user_and_csrf(app, client):
    make_user(app, "alice")
    assert client.get("/api/v1/auth/me").status_code == 401
    token = login(client).json()["csrf_token"]
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "alice"
    assert r.json()["csrf_token"] == token


def test_logout_needs_the_csrf_header(app, client):
    make_user(app, "alice")
    token = login(client).json()["csrf_token"]

    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"
    r = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": "wrong"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"

    r = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    assert len(audit_rows(app, "LOGOUT")) == 1


def test_idle_session_expires(app, client):
    make_user(app, "alice")
    login(client)
    with app.state.session_factory() as db:
        session = db.scalars(select(UserSession)).one()
        session.expires_at = "2000-01-01T00:00:00.000Z"
        db.commit()
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "UNAUTHENTICATED"
    assert len(audit_rows(app, "SESSION_EXPIRED")) == 1


def test_login_rate_limit_is_per_ip_and_username(app, client):
    make_user(app, "alice")
    make_user(app, "bob")
    for _ in range(5):
        assert login(client, "alice", BAD).status_code == 401
    r = login(client, "alice", BAD)
    assert r.status_code == 429 and r.json()["error"]["code"] == "RATE_LIMITED"
    assert login(client, "alice").status_code == 429  # even the right password
    assert login(client, "bob").status_code == 200  # other usernames unaffected
    assert audit_rows(app, "RATE_LIMITED")


def test_require_role_denies_and_audits(app, client):
    @app.get("/t/admin-only")
    def admin_only(ctx: Annotated[AuthContext, Depends(require_role("admin"))]):
        return {"role": ctx.user.role}

    make_user(app, "alice", role="analyst")
    make_user(app, "root", role="admin")

    assert client.get("/t/admin-only").status_code == 401  # no session

    login(client, "alice")
    r = client.get("/t/admin-only")
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    assert len(audit_rows(app, "ACCESS_DENIED")) == 1

    admin = TestClient(app)
    login(admin, "root")
    assert admin.get("/t/admin-only").json() == {"role": "admin"}