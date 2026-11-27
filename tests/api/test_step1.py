import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.config import Settings
from app.main import create_app
from app.repository import audit
from app.repository.models import Block


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
def db(app):
    session = app.state.session_factory()
    yield session
    session.close()


def test_unknown_route_uses_error_envelope(app):
    r = TestClient(app).get("/nope")
    assert r.status_code == 404
    body = r.json()["error"]
    assert body["code"] == "NOT_FOUND"
    assert body["request_id"]


def test_blocks_are_append_only(db):
    db.add(Block(index=0, event_type="GENESIS", payload_json="{}",
                 prev_hash="0" * 64, block_hash="a" * 64))
    db.commit()
    with pytest.raises(DBAPIError):
        db.execute(text("UPDATE blocks SET block_hash='x' WHERE \"index\"=0"))
    db.rollback()
    with pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM blocks"))
    db.rollback()


def test_audit_log_writes_event(db):
    event = audit.log(
        db, actor_id=None, actor_role=None, event_type="LOGIN_FAILED",
        outcome="FAILURE", ip="127.0.0.1", request_id="r1",
        details={"username": "bob"}, commit=True,
    )
    assert event.id and event.timestamp.endswith("Z")


def test_audit_rejects_secrets_and_bad_types(db):
    with pytest.raises(ValueError):
        audit.log(db, actor_id=None, actor_role=None, event_type="LOGIN_FAILED",
                  outcome="FAILURE", ip=None, request_id=None,
                  details={"password": "hunter2"})
    with pytest.raises(ValueError):
        audit.log(db, actor_id=None, actor_role=None, event_type="MADE_UP",
                  outcome="SUCCESS", ip=None, request_id=None)