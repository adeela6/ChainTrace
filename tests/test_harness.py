"""Tests for the test harness itself: isolation and the format helpers.

The helpers are checked against the examples in the kickoff doc, so if a
helper is wrong, these fail before it hides a real bug elsewhere.
"""

import json
import os
import uuid
from pathlib import Path

import pytest

from tests.helpers import (
    assert_audit_event,
    assert_error_body,
    assert_no_leaks,
    assert_verification_result,
)


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.text = json.dumps(body)
        self._body = body

    def json(self):
        return self._body


# --- Isolation ---------------------------------------------------------------------


def test_every_setting_is_overridden_for_tests():
    """If A adds a setting, it must be added to build_test_env, or it could leak from the real .env."""
    from app.config import Settings
    from tests.conftest import build_test_env

    assert set(build_test_env(Path("x"))) == set(Settings.model_fields)


def test_settings_never_point_at_real_files(settings, test_env):
    repo_root = Path(__file__).resolve().parent.parent
    assert settings.CHAINTRACE_ENV == "test"
    assert str(test_env.base) in settings.DATABASE_URL.replace("/", os.sep)
    assert Path(settings.STORAGE_DIR).resolve() != (repo_root / "storage" / "evidence").resolve()
    assert test_env.storage_dir.is_dir()


def test_master_key_is_a_throwaway_key(settings):
    from tests.conftest import TEST_MASTER_KEY

    assert settings.CHAINTRACE_MASTER_KEY == TEST_MASTER_KEY


def test_each_test_gets_its_own_folder(test_env, tmp_path):
    assert test_env.base == tmp_path
    assert not test_env.db_path.exists()


# --- Error envelope ----------------------------------------------------------------


def make_error(code="INVALID_SIGNATURE", **overrides):
    error = {"code": code, "message": "Signature check failed for this transfer.", "request_id": str(uuid.uuid4())}
    error.update(overrides)
    return {"error": error}


def test_error_envelope_from_kickoff_doc_passes():
    assert_error_body(make_error(), "INVALID_SIGNATURE")


@pytest.mark.parametrize(
    "body",
    [
        {"detail": "Not Found"},  # FastAPI's default error shape
        make_error(code="SOMETHING_ELSE"),
        make_error(request_id="not-a-uuid"),
        make_error(message=""),
        {"error": {"code": "FORBIDDEN", "message": "x"}},  # missing request_id
    ],
)
def test_bad_error_envelopes_are_caught(body):
    with pytest.raises(AssertionError):
        assert_error_body(body)


# --- Leak scanning -----------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        'Traceback (most recent call last):\n  File "app/api/x.py", line 3',
        "sqlite3.IntegrityError: UNIQUE constraint failed",
        "ValueError: bad input",
        "SELECT * FROM users WHERE id = 1",
        r"could not open D:\IS_Project\ChainTrace\storage\evidence\x.bin",
        "/home/runner/chaintrace/app.py",
    ],
)
def test_leaks_are_caught(text):
    with pytest.raises(AssertionError):
        assert_no_leaks(text)


def test_clean_text_and_urls_are_not_flagged():
    assert_no_leaks(json.dumps(make_error()))
    assert_no_leaks("See https://example.com/docs at 2026-11-10T08:30:00.123Z")


def test_secret_values_are_caught():
    with pytest.raises(AssertionError):
        assert_no_leaks('{"note": "pw is hunter2-long-pass"}', secrets=["hunter2-long-pass"])


# --- Verification result -----------------------------------------------------------


def make_result(**overrides):
    result = {
        "verification_id": str(uuid.uuid4()),
        "scope": "chain",
        "target_id": None,
        "status": "PASS",
        "engine_version": "1.0.0",
        "run_by": str(uuid.uuid4()),
        "run_at": "2026-11-10T08:31:02.004Z",
        "duration_ms": 12,
        "blocks_checked": 57,
        "checks": [],
        "first_failure": None,
    }
    result.update(overrides)
    return result


FAILED_CHECK = {
    "check": "PREV_HASH_LINK",
    "block_index": 7,
    "status": "FAIL",
    "expected": "9c1e...",
    "actual": "44ab...",
    "reason": "Block 7 prev_hash does not match block 6 hash",
}


def test_clean_pass_result():
    assert_verification_result(make_result(), "PASS")


def test_fail_result_from_kickoff_doc():
    result = make_result(
        status="FAIL", checks=[FAILED_CHECK], first_failure={"check": "PREV_HASH_LINK", "block_index": 7}
    )
    assert_verification_result(result, "FAIL", first_failure=("PREV_HASH_LINK", 7))


@pytest.mark.parametrize(
    "result, status, first_failure",
    [
        (make_result(status="FAIL", checks=[FAILED_CHECK], first_failure=None), "FAIL", None),
        (make_result(status="FAIL", checks=[FAILED_CHECK], first_failure={"check": "PREV_HASH_LINK", "block_index": 7}),
         "FAIL", ("BLOCK_HASH_VALID", 5)),
        (make_result(checks=[FAILED_CHECK]), "PASS", None),
        (make_result(status="FAIL", checks=[{**FAILED_CHECK, "check": "LOOKS_INVALID"}],
                     first_failure={"check": "LOOKS_INVALID", "block_index": 7}), "FAIL", None),
        (make_result(run_at="2026-11-10 08:31:02"), "PASS", None),
        (make_result(scope="evidence", target_id=None), "PASS", None),
        ({k: v for k, v in make_result().items() if k != "blocks_checked"}, "PASS", None),
    ],
    ids=["first_failure-missing", "wrong-block", "pass-with-checks", "unknown-check",
         "bad-timestamp", "evidence-without-target", "missing-field"],
)
def test_bad_verification_results_are_caught(result, status, first_failure):
    with pytest.raises(AssertionError):
        assert_verification_result(result, status, first_failure)


# --- Audit event -------------------------------------------------------------------


def test_audit_event_from_kickoff_doc():
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": "2026-11-10T08:30:00.123Z",
        "actor_id": str(uuid.uuid4()),
        "actor_role": "analyst",
        "event_type": "TRANSFER_CREATED",
        "target_type": "evidence",
        "target_id": str(uuid.uuid4()),
        "outcome": "SUCCESS",
        "ip": "127.0.0.1",
        "request_id": str(uuid.uuid4()),
        "details": {"error_code": None, "block_index": 42},
    }
    assert_audit_event(event, "TRANSFER_CREATED", "SUCCESS")
    with pytest.raises(AssertionError):
        assert_audit_event({**event, "event_type": "TRANSFER_DONE"})
    with pytest.raises(AssertionError):
        assert_audit_event({**event, "outcome": "OK"})


# --- App client --------------------------------------------------------------------


def test_client_fixture_waits_for_app(client):
    """Skips until A pushes app.main.create_app(); then checks the app starts."""
    assert client is not None
