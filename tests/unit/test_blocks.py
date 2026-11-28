"""Unit tests for app/engine/blocks.py."""

import copy

import pytest

from app.engine.blocks import (
    BLOCK_FIELDS,
    GENESIS_PREV_HASH,
    build_block,
    compute_block_hash,
    create_genesis_block,
    is_sha256_hex,
    signing_fields,
    utc_now_iso,
    validate_new_block,
    validate_payload,
)
from app.engine.exceptions import BlockError
from app.engine.hashing import hash_record
from app.engine.keys import generate_keypair, key_fingerprint, public_key_to_b64
from app.engine.signing import verify_signature

FILE_HASH = "a" * 64


@pytest.fixture
def analyst():
    private_key = generate_keypair()
    return {"id": "user-ahmed", "private_key": private_key,
            "public_key": public_key_to_b64(private_key.public_key())}


def register_payload():
    return {"evidence_sha256": FILE_HASH, "size_bytes": 120,
            "mime_type": "text/plain", "original_filename": "notes.txt"}


def make_register(prev, analyst):
    return build_block(prev, event_type="REGISTER", case_id="case-1", evidence_id="ev-1",
                       actor_id=analyst["id"], payload=register_payload(),
                       private_key=analyst["private_key"])


# ---------- genesis ----------

def test_genesis_block_shape():
    genesis = create_genesis_block()
    assert set(genesis) == set(BLOCK_FIELDS)
    assert genesis["index"] == 0
    assert genesis["prev_hash"] == GENESIS_PREV_HASH
    assert genesis["signature"] is None
    assert genesis["block_hash"] == compute_block_hash(genesis)


def test_genesis_is_valid_first_block():
    validate_new_block(None, create_genesis_block())


def test_genesis_cannot_follow_another_block():
    first = create_genesis_block()
    second = create_genesis_block()
    second["index"] = 1
    second["prev_hash"] = first["block_hash"]
    second["block_hash"] = compute_block_hash(second)
    with pytest.raises(BlockError):
        validate_new_block(first, second)


# ---------- building ----------

def test_build_block_links_to_previous(analyst):
    genesis = create_genesis_block()
    block = make_register(genesis, analyst)
    assert block["index"] == 1
    assert block["prev_hash"] == genesis["block_hash"]


def test_build_block_without_previous_starts_chain(analyst):
    block = make_register(None, analyst)
    assert block["index"] == 0
    assert block["prev_hash"] == GENESIS_PREV_HASH


def test_block_hash_matches_team_doc_formula(analyst):
    # block_hash = SHA256(canonical(signing_fields + signature))
    block = make_register(create_genesis_block(), analyst)
    expected = hash_record({**signing_fields(block), "signature": block["signature"]})
    assert block["block_hash"] == expected


def test_block_is_signed_over_signing_fields(analyst):
    block = make_register(create_genesis_block(), analyst)
    assert verify_signature(signing_fields(block), block["signature"], analyst["public_key"])
    assert block["key_fingerprint"] == key_fingerprint(analyst["public_key"])


def test_signing_fields_exclude_signature_and_hash(analyst):
    fields = signing_fields(make_register(create_genesis_block(), analyst))
    assert "signature" not in fields and "block_hash" not in fields


def test_build_block_rejects_genesis_event(analyst):
    with pytest.raises(BlockError):
        build_block(None, event_type="GENESIS", case_id="c", evidence_id="e",
                    actor_id=analyst["id"], payload={"note": "x"},
                    private_key=analyst["private_key"])


def test_build_block_rejects_missing_ids(analyst):
    with pytest.raises(BlockError):
        build_block(None, event_type="REGISTER", case_id="", evidence_id="ev-1",
                    actor_id=analyst["id"], payload=register_payload(),
                    private_key=analyst["private_key"])


def test_build_block_copies_payload(analyst):
    # Changing the caller's dict afterwards must not change the block.
    payload = register_payload()
    block = build_block(None, event_type="REGISTER", case_id="c", evidence_id="e",
                        actor_id=analyst["id"], payload=payload,
                        private_key=analyst["private_key"])
    payload["original_filename"] = "changed.txt"
    assert block["payload"]["original_filename"] == "notes.txt"


# ---------- payload validation ----------

def test_payload_missing_field_rejected():
    payload = register_payload()
    del payload["mime_type"]
    with pytest.raises(BlockError):
        validate_payload("REGISTER", payload)


def test_payload_extra_field_rejected():
    with pytest.raises(BlockError):
        validate_payload("REGISTER", {**register_payload(), "secret": "x"})


@pytest.mark.parametrize("bad_hash", ["abc", "A" * 64, "g" * 64, None])
def test_payload_bad_hash_rejected(bad_hash):
    with pytest.raises(BlockError):
        validate_payload("REGISTER", {**register_payload(), "evidence_sha256": bad_hash})


@pytest.mark.parametrize("bad_size", [0, -5, "120", True])
def test_payload_bad_size_rejected(bad_size):
    with pytest.raises(BlockError):
        validate_payload("REGISTER", {**register_payload(), "size_bytes": bad_size})


def test_transfer_reason_too_long_rejected():
    payload = {"transfer_id": "t1", "from_user_id": "a", "to_user_id": "b",
               "evidence_sha256": FILE_HASH, "reason": "x" * 1001}
    with pytest.raises(BlockError):
        validate_payload("TRANSFER", payload)


def test_unknown_event_type_rejected():
    with pytest.raises(BlockError):
        validate_payload("DELETE", {})


# ---------- validate_new_block ----------

def test_valid_block_passes(analyst):
    genesis = create_genesis_block()
    validate_new_block(genesis, make_register(genesis, analyst), analyst["public_key"])


def test_wrong_index_is_chain_conflict(analyst):
    genesis = create_genesis_block()
    block = make_register(genesis, analyst)
    other = make_register(genesis, analyst)
    # Pretend another block was stored first: ours no longer fits on the end.
    with pytest.raises(BlockError) as info:
        validate_new_block(other, block, analyst["public_key"])
    assert info.value.code == "CHAIN_CONFLICT"


def test_edited_block_fails_hash_check(analyst):
    genesis = create_genesis_block()
    block = make_register(genesis, analyst)
    block["payload"]["original_filename"] = "edited.txt"
    with pytest.raises(BlockError) as info:
        validate_new_block(genesis, block, analyst["public_key"])
    assert info.value.code == "BLOCK_HASH_INVALID"


def test_wrong_signer_key_is_invalid_signature(analyst):
    # T3: the block is checked against a different user's stored public key.
    genesis = create_genesis_block()
    block = make_register(genesis, analyst)
    other_public = public_key_to_b64(generate_keypair().public_key())
    with pytest.raises(BlockError) as info:
        validate_new_block(genesis, block, other_public)
    assert info.value.code == "INVALID_SIGNATURE"


def test_resigned_block_with_matching_fingerprint_but_bad_signature(analyst):
    # Fingerprint is right, but the signature was corrupted and the hash rebuilt.
    genesis = create_genesis_block()
    block = make_register(genesis, analyst)
    block["signature"] = block["signature"][::-1]
    block["block_hash"] = compute_block_hash(block)
    with pytest.raises(BlockError) as info:
        validate_new_block(genesis, block, analyst["public_key"])
    assert info.value.code == "INVALID_SIGNATURE"


def test_block_with_extra_field_rejected(analyst):
    genesis = create_genesis_block()
    block = copy.deepcopy(make_register(genesis, analyst))
    block["extra"] = 1
    with pytest.raises(BlockError):
        validate_new_block(genesis, block, analyst["public_key"])


# ---------- helpers ----------

def test_timestamp_format():
    stamp = utc_now_iso()
    assert stamp.endswith("Z") and len(stamp) == len("2026-11-10T08:30:00.123Z")


def test_is_sha256_hex():
    assert is_sha256_hex("0" * 64)
    assert not is_sha256_hex("0" * 63)
