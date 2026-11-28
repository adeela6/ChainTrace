"""Tests for app/engine/verify.py, including engine-level T1-T6 scenarios.

Each test starts from the known-good demo chain (fixtures/engine_fixtures.py)
and breaks exactly one thing, then checks verify_chain() names the right
check at the right block.
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from app.engine.blocks import validate_new_block
from app.engine.exceptions import BlockError
from app.engine.verify import CHECK_ORDER, ENGINE_VERSION, verify_chain
from fixtures.engine_fixtures import (
    alter_file,
    append_replayed_transfer,
    build_demo_scenario,
    build_long_chain,
    delete_block,
    flip_signature_byte,
    forged_transfer_block,
    resign_with_wrong_key,
    tamper_block_payload,
    truncate_head,
)

# Block layout of the demo chain (see build_demo_scenario):
#   0 GENESIS | 1-4 REGISTER (4 files) | 5 TRANSFER ahmed->sara | 6 ACCEPT
#   7 TRANSFER sara->bilal | 8 ACCEPT | 9 TRANSFER ahmed->sara (log) | 10 ACCEPT


@pytest.fixture
def scenario(tmp_path):
    return build_demo_scenario(tmp_path)


def verify(scenario, blocks=None, **options):
    """Run verify_chain on the scenario (or on a tampered copy of its blocks)."""
    return verify_chain(
        scenario["blocks"] if blocks is None else blocks,
        scenario["public_keys"],
        scenario["evidence_files"],
        **options,
    )


def failed_checks(result):
    return [(check["check"], check["block_index"]) for check in result["checks"]]


# ---------- result schema ----------

def test_result_has_team_doc_fields(scenario):
    result = verify(scenario, run_by="user-1")
    expected = {"verification_id", "scope", "target_id", "status", "engine_version",
                "run_by", "run_at", "duration_ms", "blocks_checked", "head",
                "checks", "first_failure"}
    assert set(result) == expected
    assert result["engine_version"] == ENGINE_VERSION
    assert result["run_by"] == "user-1"


def test_result_is_json_serialisable(scenario):
    # The backend stores it as JSON, so this must never fail.
    json.dumps(verify(scenario))


def test_bad_scope_rejected(scenario):
    with pytest.raises(ValueError):
        verify(scenario, scope="everything")


# ---------- clean chain (no false positives) ----------

def test_clean_chain_passes(scenario):
    result = verify(scenario)
    assert result["status"] == "PASS"
    assert result["checks"] == [] and result["first_failure"] is None
    assert result["blocks_checked"] == 11


def test_long_clean_chain_passes(tmp_path):
    # T5 (first half): a clean chain of 50+ blocks passes.
    long_chain = build_long_chain(55, tmp_path)
    result = verify_chain(long_chain["blocks"], long_chain["public_keys"], long_chain["evidence_files"])
    assert result["status"] == "PASS"
    assert result["blocks_checked"] >= 55


# ---------- T1: tampered record ----------

def test_t1_edited_block_detected(scenario):
    tampered = tamper_block_payload(scenario["blocks"], 5, "reason", "Edited later")
    result = verify(scenario, tampered)
    assert result["status"] == "FAIL"
    assert result["first_failure"] == {"check": "BLOCK_HASH_VALID", "block_index": 5}


def test_t1_edited_block_with_rebuilt_hash_detected(scenario):
    # A smarter attacker also rewrites block_hash: the signature and next link still catch it.
    tampered = tamper_block_payload(scenario["blocks"], 5, "reason", "Edited later", rehash=True)
    checks = failed_checks(verify(scenario, tampered))
    assert ("SIGNATURE_VALID", 5) in checks
    assert ("PREV_HASH_LINK", 6) in checks


# ---------- T2: altered file ----------

def test_t2_altered_file_detected(scenario):
    item = scenario["evidence"]["server_access.log"]
    alter_file(item["path"])
    result = verify(scenario)
    assert result["status"] == "FAIL"
    failure = result["checks"][0]
    assert failure["check"] == "FILE_HASH_MATCH"
    assert failure["expected"] == item["sha256"]
    assert failure["actual"] != item["sha256"]


def test_t2_missing_file_detected(scenario):
    scenario["evidence"]["cctv_frame.png"]["path"].unlink()
    assert verify(scenario)["checks"][0]["check"] == "FILE_HASH_MATCH"


# ---------- T3: invalid signature ----------

def test_t3_flipped_signature_detected(scenario):
    result = verify(scenario, flip_signature_byte(scenario["blocks"], 6))
    assert result["first_failure"] == {"check": "SIGNATURE_VALID", "block_index": 6}


def test_t3_wrong_key_detected(scenario):
    tampered = resign_with_wrong_key(scenario["blocks"], 6, scenario["users"]["bilal"])
    result = verify(scenario, tampered)
    assert result["first_failure"] == {"check": "SIGNATURE_VALID", "block_index": 6}
    assert "registered key" in result["checks"][0]["reason"]


def test_t3_forged_transfer_rejected_before_append(scenario):
    # Signed with Bilal's key while claiming to be from Ahmed.
    forged = forged_transfer_block(scenario, signer_name="bilal", claimed_name="ahmed")
    with pytest.raises(BlockError) as info:
        validate_new_block(scenario["blocks"][-1], forged, scenario["users"]["ahmed"]["public_key"])
    assert info.value.code == "INVALID_SIGNATURE"


def test_unknown_signer_detected(scenario):
    keys = dict(scenario["public_keys"])
    del keys[scenario["users"]["sara"]["id"]]
    result = verify_chain(scenario["blocks"], keys, scenario["evidence_files"])
    assert result["first_failure"]["check"] == "SIGNATURE_VALID"


# ---------- T4: duplicate transfer ----------

def test_t4_replayed_transfer_detected(scenario):
    replayed = append_replayed_transfer(scenario, transfer_index=0)
    result = verify(scenario, replayed)
    assert result["first_failure"] == {"check": "CUSTODY_CONTINUITY", "block_index": 11}
    assert result["checks"][0]["actual"] == "DUPLICATE_TRANSFER"


# ---------- T5: chain validation ----------

def test_t5_deleted_middle_block_detected(tmp_path):
    long_chain = build_long_chain(55, tmp_path)
    tampered = delete_block(long_chain["blocks"], 25)
    result = verify_chain(tampered, long_chain["public_keys"], long_chain["evidence_files"])
    assert result["first_failure"] == {"check": "PREV_HASH_LINK", "block_index": 26}
    assert ("INDEX_SEQUENTIAL", 26) in failed_checks(result)


def test_deleted_newest_blocks_detected_with_last_head(scenario):
    # Removing the newest blocks leaves a perfectly linked chain...
    first = verify(scenario)
    shortened = truncate_head(scenario["blocks"], 2)
    assert verify(scenario, shortened)["status"] == "PASS"

    # ...so only the head recorded at the last verification can catch it.
    result = verify(scenario, shortened, last_head=first["head"])
    assert result["first_failure"]["check"] == "CHAIN_HEAD_CONSISTENT"


def test_head_still_matches_after_new_blocks(scenario):
    # Adding blocks after the last verification is normal, not tampering.
    first = verify(scenario, truncate_head(scenario["blocks"], 2))
    assert verify(scenario, last_head=first["head"])["status"] == "PASS"


# ---------- T6: privacy (engine side) ----------

def test_t6_result_contains_no_secrets_or_paths(scenario):
    alter_file(scenario["evidence"]["server_access.log"]["path"])
    text = json.dumps(verify(scenario))

    # No private key in any form.
    for user in scenario["users"].values():
        raw = user["private_key"].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        assert base64.b64encode(raw).decode() not in text
        assert raw.hex() not in text

    # No file paths and no file contents.
    for item in scenario["evidence"].values():
        assert str(item["path"]) not in text
    assert "laptop seized" not in text


# ---------- ordering and scope ----------

def test_failures_sorted_by_block_then_check_order(scenario):
    tampered = delete_block(tamper_block_payload(scenario["blocks"], 3, "mime_type", "x/y"), 7)
    checks = verify(scenario, tampered)["checks"]
    keys = [(c["block_index"], CHECK_ORDER.index(c["check"])) for c in checks]
    assert keys == sorted(keys)


def test_evidence_scope_ignores_other_evidence_signatures(scenario):
    # A broken signature on the log's transfer doesn't fail a check of the notes file...
    tampered = flip_signature_byte(scenario["blocks"], 9, rehash=False)
    notes_id = scenario["evidence"]["incident_notes.txt"]["id"]
    result = verify_chain(tampered, scenario["public_keys"], {},
                          evidence_ids=[notes_id], scope="evidence", target_id=notes_id)
    assert ("SIGNATURE_VALID", 9) not in failed_checks(result)
    # ...but the whole-chain hash check still sees the damage.
    assert ("BLOCK_HASH_VALID", 9) in failed_checks(result)


def test_malformed_row_does_not_crash(scenario):
    broken = list(scenario["blocks"]) + ["not a block"]
    result = verify(scenario, broken)
    assert result["status"] == "FAIL"


def test_empty_chain_passes():
    assert verify_chain([], {})["status"] == "PASS"
