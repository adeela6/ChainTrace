"""Unit tests for app/engine/custody.py."""

import pytest

from app.engine.custody import (
    apply_block,
    check_accept,
    check_register,
    check_transfer,
    custody_state,
)
from app.engine.exceptions import CustodyError

HASH = "b" * 64


def register(actor="ahmed"):
    return {"event_type": "REGISTER", "evidence_id": "ev-1", "actor_id": actor,
            "payload": {"evidence_sha256": HASH}}


def transfer(actor, to, transfer_id="t1"):
    return {"event_type": "TRANSFER", "evidence_id": "ev-1", "actor_id": actor,
            "payload": {"transfer_id": transfer_id, "from_user_id": actor,
                        "to_user_id": to, "evidence_sha256": HASH}}


def accept(actor, transfer_id="t1"):
    return {"event_type": "ACCEPT", "evidence_id": "ev-1", "actor_id": actor,
            "payload": {"transfer_id": transfer_id, "evidence_sha256": HASH}}


def code_of(func, *args):
    with pytest.raises(CustodyError) as info:
        func(*args)
    return info.value.code


# ---------- state ----------

def test_register_makes_actor_custodian():
    state = custody_state([register()], "ev-1")
    assert state["custodian"] == "ahmed" and state["pending"] is None


def test_transfer_alone_does_not_change_custodian():
    # Rule 5: custody only changes after ACCEPT.
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert state["custodian"] == "ahmed"
    assert state["pending"]["to_user_id"] == "sara"


def test_accept_moves_custody():
    state = custody_state([register(), transfer("ahmed", "sara"), accept("sara")], "ev-1")
    assert state["custodian"] == "sara" and state["pending"] is None


def test_other_evidence_is_ignored():
    other = {**register("bilal"), "evidence_id": "ev-2"}
    state = custody_state([register(), other], "ev-1")
    assert state["custodian"] == "ahmed"


def test_unregistered_evidence_has_no_state():
    assert custody_state([], "ev-1") is None


def test_apply_block_does_not_change_old_state():
    before = custody_state([register()], "ev-1")
    apply_block(before, transfer("ahmed", "sara"))
    assert before["pending"] is None and before["transfer_ids"] == set()


# ---------- REGISTER ----------

def test_register_twice_rejected():
    state = custody_state([register()], "ev-1")
    assert code_of(check_register, state) == "DUPLICATE_EVIDENCE"


# ---------- TRANSFER ----------

def test_valid_transfer_passes():
    state = custody_state([register()], "ev-1")
    check_transfer(state, "ahmed", "t1", "ahmed", "sara", HASH)


def test_transfer_by_non_custodian_rejected():
    # T4 (second half): someone who doesn't hold the evidence tries to send it.
    state = custody_state([register()], "ev-1")
    assert code_of(check_transfer, state, "bilal", "t1", "bilal", "sara", HASH) == "NOT_CUSTODIAN"


def test_transfer_with_wrong_from_user_rejected():
    state = custody_state([register()], "ev-1")
    assert code_of(check_transfer, state, "ahmed", "t1", "bilal", "sara", HASH) == "NOT_CUSTODIAN"


def test_same_transfer_sent_twice_rejected():
    # T4: the same transfer is submitted again.
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert code_of(check_transfer, state, "ahmed", "t1", "ahmed", "sara", HASH) == "DUPLICATE_TRANSFER"


def test_second_transfer_while_pending_rejected():
    # T4: a new transfer while one is still waiting to be accepted.
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert code_of(check_transfer, state, "ahmed", "t2", "ahmed", "bilal", HASH) == "DUPLICATE_TRANSFER"


def test_old_transfer_id_reused_later_rejected():
    # Replay of a finished transfer's ID, even by the new custodian.
    state = custody_state([register(), transfer("ahmed", "sara"), accept("sara")], "ev-1")
    assert code_of(check_transfer, state, "sara", "t1", "sara", "ahmed", HASH) == "DUPLICATE_TRANSFER"


def test_transfer_to_self_rejected():
    state = custody_state([register()], "ev-1")
    assert code_of(check_transfer, state, "ahmed", "t1", "ahmed", "ahmed", HASH) == "INVALID_RECIPIENT"


def test_transfer_with_wrong_hash_rejected():
    state = custody_state([register()], "ev-1")
    assert code_of(check_transfer, state, "ahmed", "t1", "ahmed", "sara", "c" * 64) == "HASH_MISMATCH"


def test_transfer_of_unregistered_evidence_rejected():
    assert code_of(check_transfer, None, "ahmed", "t1", "ahmed", "sara", HASH) == "EVIDENCE_NOT_REGISTERED"


# ---------- ACCEPT ----------

def test_valid_accept_passes():
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    check_accept(state, "sara", "t1", HASH)


def test_accept_by_wrong_person_rejected():
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert code_of(check_accept, state, "bilal", "t1", HASH) == "NOT_RECEIVER"


def test_accept_twice_rejected():
    state = custody_state([register(), transfer("ahmed", "sara"), accept("sara")], "ev-1")
    assert code_of(check_accept, state, "sara", "t1", HASH) == "TRANSFER_NOT_PENDING"


def test_accept_wrong_transfer_id_rejected():
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert code_of(check_accept, state, "sara", "t9", HASH) == "TRANSFER_NOT_PENDING"


def test_accept_with_wrong_hash_rejected():
    # The receiver got a different file than the one registered.
    state = custody_state([register(), transfer("ahmed", "sara")], "ev-1")
    assert code_of(check_accept, state, "sara", "t1", "c" * 64) == "HASH_MISMATCH"
