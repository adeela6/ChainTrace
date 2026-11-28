"""Custody rules for ChainTrace (FR-3).

The custody "state" of one evidence item is worked out by replaying its
blocks in order:

    REGISTER  -> the registering analyst becomes the custodian
    TRANSFER  -> a transfer becomes pending (custody does NOT change yet)
    ACCEPT    -> the receiver becomes the custodian, nothing is pending

The same check functions are used in two places:
- before a new block is appended (the backend calls them), and
- during verification (verify.py replays the whole chain with them),
so the rules can never drift apart.
"""

from app.engine.blocks import ACCEPT, GENESIS, REGISTER, TRANSFER
from app.engine.exceptions import CustodyError


# ---------- working out the current state ----------

def custody_state(blocks: list, evidence_id: str):
    """Replay the chain and return the custody state of one evidence item.

    Returns None if the evidence has never been registered. Otherwise a dict:
        registered_sha256, registered_by, custodian,
        pending (None or {transfer_id, from_user_id, to_user_id}),
        transfer_ids (every transfer_id ever used for this evidence)
    """
    state = None

    # Go through the chain in order, only looking at this evidence's blocks.
    for block in blocks:
        if block.get("evidence_id") == evidence_id:
            state = apply_block(state, block)
    return state


def apply_block(state, block: dict):
    """Return the new state after one block (the old state is never changed)."""
    event_type = block.get("event_type")
    payload = block.get("payload") or {}

    # REGISTER: start a fresh state; the registering analyst holds the evidence.
    if event_type == REGISTER:
        return {
            "registered_sha256": payload.get("evidence_sha256"),
            "registered_by": block.get("actor_id"),
            "custodian": block.get("actor_id"),
            "pending": None,
            "transfer_ids": set(),
        }

    # Nothing else can happen to evidence that was never registered.
    if state is None:
        return None

    # Work on a copy, so the caller's state is left untouched.
    new_state = dict(state)
    new_state["transfer_ids"] = set(state["transfer_ids"])

    # TRANSFER: remember the transfer as pending; custody stays with the sender.
    if event_type == TRANSFER:
        new_state["pending"] = {
            "transfer_id": payload.get("transfer_id"),
            "from_user_id": payload.get("from_user_id"),
            "to_user_id": payload.get("to_user_id"),
        }
        new_state["transfer_ids"].add(payload.get("transfer_id"))

    # ACCEPT: custody moves to the receiver, and nothing is pending any more.
    elif event_type == ACCEPT and state["pending"] is not None:
        new_state["custodian"] = state["pending"]["to_user_id"]
        new_state["pending"] = None

    return new_state


# ---------- the rules ----------

def check_register(state) -> None:
    """A piece of evidence can only be registered once."""
    if state is not None:
        raise CustodyError("DUPLICATE_EVIDENCE", "This evidence is already registered")


def check_transfer(state, actor_id, transfer_id, from_user_id, to_user_id, evidence_sha256) -> None:
    """Rule 3 (and rule 4) from the team doc, for a new TRANSFER.

    Breaking any of these is the duplicate / invalid transfer case (T4).
    """

    # The evidence must exist in the chain.
    _require_registered(state)

    # A transfer_id can only ever be used once (stops replays).
    if transfer_id in state["transfer_ids"]:
        raise CustodyError("DUPLICATE_TRANSFER", "This transfer has already been recorded")

    # Only the current custodian can send the evidence, and they must be the sender.
    if actor_id != state["custodian"] or from_user_id != actor_id:
        raise CustodyError("NOT_CUSTODIAN", "Only the current custodian can transfer this evidence")

    # No new transfer while another one is still waiting to be accepted.
    if state["pending"] is not None:
        raise CustodyError("DUPLICATE_TRANSFER", "A transfer of this evidence is already pending")

    # The receiver can't be the sender. (A checks the rest: active analyst,
    # member of the case. Same generic message, so nothing is revealed.)
    if to_user_id == actor_id:
        raise CustodyError("INVALID_RECIPIENT", "This user cannot receive the evidence")

    # Rule 4: the hash in the transfer must be the hash recorded at REGISTER.
    if evidence_sha256 != state["registered_sha256"]:
        raise CustodyError("HASH_MISMATCH", "Evidence hash differs from the registered hash")


def check_accept(state, actor_id, transfer_id, evidence_sha256) -> None:
    """Rules for an ACCEPT: right transfer, right receiver, right hash."""

    # The evidence must exist in the chain.
    _require_registered(state)

    # The transfer being accepted must be the one that is currently pending.
    pending = state["pending"]
    if pending is None or pending["transfer_id"] != transfer_id:
        raise CustodyError("TRANSFER_NOT_PENDING", "This transfer is not waiting to be accepted")

    # Only the named receiver can accept it.
    if actor_id != pending["to_user_id"]:
        raise CustodyError("NOT_RECEIVER", "Only the receiver can accept this transfer")

    # The receiver confirms the hash of what they got matches the registered hash.
    if evidence_sha256 != state["registered_sha256"]:
        raise CustodyError("HASH_MISMATCH", "Evidence hash differs from the registered hash")


def check_block(state, block: dict) -> None:
    """Run the right rule for a block, based on its event type.

    verify.py uses this to replay a stored chain and spot custody problems.
    """
    event_type = block.get("event_type")
    payload = block.get("payload") or {}
    actor_id = block.get("actor_id")

    # GENESIS has nothing to do with custody.
    if event_type == GENESIS:
        return

    # Pick the rule that matches the event.
    if event_type == REGISTER:
        check_register(state)
    elif event_type == TRANSFER:
        check_transfer(
            state,
            actor_id,
            payload.get("transfer_id"),
            payload.get("from_user_id"),
            payload.get("to_user_id"),
            payload.get("evidence_sha256"),
        )
    elif event_type == ACCEPT:
        check_accept(state, actor_id, payload.get("transfer_id"), payload.get("evidence_sha256"))
    else:
        raise CustodyError("VALIDATION_ERROR", "Unknown event type")


# ---------- private helpers ----------

def _require_registered(state) -> None:
    """Stop if the evidence was never registered."""
    if state is None:
        raise CustodyError("EVIDENCE_NOT_REGISTERED", "This evidence has not been registered")
