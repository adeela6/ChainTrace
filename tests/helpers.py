"""Assertion helpers that encode the team's agreed formats.

Every test should use these instead of re-checking formats by hand, so a
format change in the kickoff doc is updated in exactly one place.
"""

import re
import uuid

# --- Agreed constants (kickoff doc) -------------------------------------------

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ERROR_CODES = {
    "VALIDATION_ERROR": 400,
    "INVALID_FILE_TYPE": 400,
    "FILE_TOO_LARGE": 413,
    "UNAUTHENTICATED": 401,
    "INVALID_CREDENTIALS": 401,
    "FORBIDDEN": 403,
    "CSRF_FAILED": 403,
    "REAUTH_FAILED": 403,
    "NOT_FOUND": 404,
    "NOT_CUSTODIAN": 409,
    "NOT_RECEIVER": 409,
    "TRANSFER_NOT_PENDING": 409,
    "DUPLICATE_TRANSFER": 409,
    "DUPLICATE_EVIDENCE": 409,
    "INVALID_SIGNATURE": 422,
    "INVALID_RECIPIENT": 422,
    "HASH_MISMATCH": 422,
    "RATE_LIMITED": 429,
    "INTERNAL_ERROR": 500,
}

# Agreed order. Per-block checks run first, in this order, for each block;
# FILE_HASH_MATCH then runs per evidence item, and CHAIN_HEAD_CONSISTENT last.
CHECK_ORDER = [
    "PREV_HASH_LINK",
    "INDEX_SEQUENTIAL",
    "BLOCK_HASH_VALID",
    "SIGNATURE_VALID",
    "CUSTODY_CONTINUITY",
    "FILE_HASH_MATCH",
    "CHAIN_HEAD_CONSISTENT",
]
VERIFICATION_CHECKS = set(CHECK_ORDER)

AUDIT_EVENT_TYPES = {
    "LOGIN", "LOGOUT", "LOGIN_FAILED", "SESSION_EXPIRED", "USER_CREATED",
    "ROLE_CHANGED", "CONFIG_CHANGED", "CASE_CREATED", "EVIDENCE_REGISTERED",
    "UPLOAD_REJECTED", "TRANSFER_CREATED", "TRANSFER_ACCEPTED", "TRANSFER_REJECTED",
    "VERIFICATION_RUN", "REPORT_EXPORTED", "AUDIT_EXPORTED", "ACCESS_DENIED",
    "RATE_LIMITED",
}

# Things that must never appear in an API response, export or audit row.
LEAK_PATTERNS = {
    "stack trace": re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+"),
    "python exception": re.compile(r"\b\w+(Error|Exception): "),
    "SQL": re.compile(r"\b(SELECT .+ FROM|INSERT INTO|UPDATE \w+ SET|DELETE FROM)\b", re.IGNORECASE),
    "database driver": re.compile(r"sqlalchemy\.|sqlite3\.", re.IGNORECASE),
    "file path": re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/](?!/)|/(home|Users|tmp|var)/|storage[\\/]evidence"),
}


# --- Helpers ---------------------------------------------------------------------


def is_uuid4(value) -> bool:
    try:
        return uuid.UUID(str(value)).version == 4
    except (ValueError, TypeError, AttributeError):
        return False


def assert_timestamp(value, field="timestamp"):
    assert isinstance(value, str) and TIMESTAMP_RE.match(value), (
        f"{field} must be UTC ISO 8601 like 2026-11-10T08:30:00.123Z, got {value!r}"
    )


def assert_error(response, code: str) -> dict:
    """Assert `response` is the agreed error envelope with this code and its HTTP status."""
    assert code in ERROR_CODES, f"{code} is not an agreed error code"
    assert response.status_code == ERROR_CODES[code], (
        f"expected HTTP {ERROR_CODES[code]} for {code}, got {response.status_code}: {response.text[:300]}"
    )
    assert_error_body(response.json(), code)
    assert_no_leaks(response.text)
    return response.json()["error"]


def assert_error_body(body, code: str | None = None):
    assert isinstance(body, dict) and set(body) == {"error"}, f"envelope must be {{'error': {{...}}}}, got {body!r}"
    error = body["error"]
    assert set(error) == {"code", "message", "request_id"}, f"error must have code, message, request_id: {error!r}"
    assert error["code"] in ERROR_CODES, f"unknown error code {error['code']!r}"
    if code is not None:
        assert error["code"] == code, f"expected {code}, got {error['code']}"
    assert isinstance(error["message"], str) and error["message"], "message must be a non-empty string"
    assert is_uuid4(error["request_id"]), f"request_id must be a UUIDv4, got {error['request_id']!r}"


def assert_no_leaks(text: str, secrets=()):
    """Fail if `text` contains internals (stack traces, SQL, paths) or any of `secrets`."""
    for name, pattern in LEAK_PATTERNS.items():
        match = pattern.search(text)
        assert match is None, f"leaked {name}: {match.group(0)!r}"
    for secret in secrets:
        if secret:
            assert str(secret) not in text, "a secret value (password, token, key or file content) leaked"


def failure_sort_key(check: dict):
    """Lowest block index first; within one block, the agreed check order.

    A failure without a block index (e.g. FILE_HASH_MATCH, if B reports it per
    evidence item) sorts after every per-block failure, since those checks run last.
    """
    index = check.get("block_index")
    return (index is None, index if index is not None else 0, CHECK_ORDER.index(check["check"]))


def drop_triggers(db_path, trigger_names):
    """Drop the append-only triggers in a COPY of the database, so T1 can tamper with it.

    Never call this on a real database. A publishes the trigger names as constants;
    there is deliberately no trigger-dropping code in the app itself.
    """
    import sqlite3

    connection = sqlite3.connect(db_path)
    try:
        for name in trigger_names:
            if not re.fullmatch(r"\w+", name):
                raise ValueError(f"not a trigger name: {name!r}")
            connection.execute(f"DROP TRIGGER {name}")  # no IF EXISTS: a renamed trigger must fail loudly
        connection.commit()
    finally:
        connection.close()


def assert_verification_result(result: dict, status: str, first_failure: tuple[str, int | None] | None = None):
    """Check the agreed verification result shape, and optionally which check failed first.

    first_failure: (check_name, block_index), e.g. ("BLOCK_HASH_VALID", 5).
    """
    expected_fields = {
        "verification_id", "scope", "target_id", "status", "engine_version", "run_by",
        "run_at", "duration_ms", "blocks_checked", "checks", "first_failure",
        "head_index", "head_hash",
    }
    missing = expected_fields - result.keys()
    assert not missing, f"verification result is missing {sorted(missing)}"
    assert is_uuid4(result["verification_id"]), "verification_id must be a UUIDv4"
    assert result["scope"] in {"chain", "case", "evidence"}, f"bad scope {result['scope']!r}"
    if result["scope"] == "chain":
        assert result["target_id"] is None, "chain scope must have target_id null"
    else:
        assert is_uuid4(result["target_id"]), "case/evidence scope needs a UUID target_id"
    assert_timestamp(result["run_at"], "run_at")
    assert isinstance(result["duration_ms"], int) and result["duration_ms"] >= 0
    assert isinstance(result["blocks_checked"], int) and result["blocks_checked"] >= 0
    assert isinstance(result["head_index"], int) and result["head_index"] >= 0, "head_index must be the last block's index"
    assert isinstance(result["head_hash"], str) and SHA256_RE.match(result["head_hash"]), "head_hash must be 64 hex"
    assert result["status"] == status, f"expected {status}, got {result['status']}: {result['checks']}"

    for check in result["checks"]:
        assert check["check"] in VERIFICATION_CHECKS, f"unknown check {check['check']!r}"
        assert check["status"] == "FAIL", "only failed checks belong in `checks`"
        assert check.get("reason"), "every failed check needs a human-readable reason"

    if status == "PASS":
        assert result["checks"] == [], "a PASS result must have an empty checks list"
        assert result["first_failure"] is None, "a PASS result must have first_failure null"
    else:
        assert result["checks"], "a FAIL result must list the failed checks"
        first = min(result["checks"], key=failure_sort_key)
        assert result["first_failure"] == {"check": first["check"], "block_index": first["block_index"]}, (
            "first_failure must be the failure with the lowest block index (ties: agreed check order)"
        )
        if first_failure is not None:
            assert (first["check"], first["block_index"]) == first_failure, (
                f"expected first failure {first_failure}, got {(first['check'], first['block_index'])}"
            )


def assert_audit_event(event: dict, event_type: str | None = None, outcome: str | None = None):
    expected_fields = {
        "id", "timestamp", "actor_id", "actor_role", "event_type", "target_type",
        "target_id", "outcome", "ip", "request_id", "details",
    }
    missing = expected_fields - event.keys()
    assert not missing, f"audit event is missing {sorted(missing)}"
    assert is_uuid4(event["id"])
    assert_timestamp(event["timestamp"])
    assert event["actor_id"] is None or is_uuid4(event["actor_id"])
    assert event["event_type"] in AUDIT_EVENT_TYPES, f"unknown audit event type {event['event_type']!r}"
    assert event["outcome"] in {"SUCCESS", "FAILURE", "DENIED"}, f"bad outcome {event['outcome']!r}"
    assert isinstance(event["details"], dict)
    if event_type is not None:
        assert event["event_type"] == event_type
    if outcome is not None:
        assert event["outcome"] == outcome
