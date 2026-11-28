"""Chain verification for ChainTrace (FR-5).

verify_chain() re-checks everything and returns the team doc's result schema.
It never stops at the first problem: every failure is listed, sorted by
block index, and the first one is also given as first_failure.

Check order, per block (from the team doc's spec clarification #3):
    PREV_HASH_LINK -> INDEX_SEQUENTIAL -> BLOCK_HASH_VALID
    -> SIGNATURE_VALID -> CUSTODY_CONTINUITY
then FILE_HASH_MATCH per evidence file, then CHAIN_HEAD_CONSISTENT.
"""

import math
import time

from app.engine import custody
from app.engine.blocks import (
    GENESIS,
    GENESIS_PREV_HASH,
    REGISTER,
    compute_block_hash,
    new_id,
    signing_fields,
    utc_now_iso,
)
from app.engine.exceptions import CustodyError
from app.engine.hashing import hash_file
from app.engine.keys import key_fingerprint
from app.engine.signing import verify_signature

# Stored with every result, so a decision can be reproduced later.
ENGINE_VERSION = "1.0.0"

# The order checks are reported in (used to sort failures in the same block).
CHECK_ORDER = (
    "PREV_HASH_LINK",
    "INDEX_SEQUENTIAL",
    "BLOCK_HASH_VALID",
    "SIGNATURE_VALID",
    "CUSTODY_CONTINUITY",
    "FILE_HASH_MATCH",
    "CHAIN_HEAD_CONSISTENT",
)

VALID_SCOPES = ("chain", "case", "evidence")


def verify_chain(
    blocks: list,
    public_keys: dict,
    evidence_files: dict = None,
    *,
    evidence_ids=None,
    last_head: dict = None,
    scope: str = "chain",
    target_id: str = None,
    run_by: str = None,
) -> dict:
    """Verify a chain and return the result in the team doc's schema.

    blocks          every block of the chain, in order (from the database)
    public_keys     {user_id: public_key_b64} - the trusted registry (users table)
    evidence_files  {evidence_id: path} - files to re-hash (FILE_HASH_MATCH)
    evidence_ids    only run signature/custody checks for these evidence items
                    (None = all). Link, index and hash checks always cover
                    the whole chain, because one missing block anywhere
                    breaks the chain for everyone.
    last_head       {"head_index", "head_hash"} from the previous verification,
                    used to catch deletion of the newest blocks
    """

    # Start the timer for duration_ms (the latency metric).
    start = time.perf_counter()

    # Check the scope is one of the agreed values.
    if scope not in VALID_SCOPES:
        raise ValueError("scope must be chain, case or evidence")

    # Turn the evidence filter into a set (or None for "everything").
    wanted = None if evidence_ids is None else set(evidence_ids)

    failures = []
    custody_states = {}   # evidence_id -> custody state, built as we go
    registrations = {}    # evidence_id -> (block index, registered hash)
    prev = None           # the previous block we looked at

    # ----- per-block checks -----
    for position, block in enumerate(blocks):

        # A row that isn't even a dict can't be checked further.
        if not isinstance(block, dict):
            failures.append(_failure(
                "BLOCK_HASH_VALID", position, "a block record", "not a block",
                f"Block at position {position} is not a valid block record",
            ))
            continue

        # Use the block's own index in reports (fall back to its position).
        index = block.get("index")
        label = index if isinstance(index, int) else position

        # 1. PREV_HASH_LINK: does this block point to the block before it?
        expected_prev = GENESIS_PREV_HASH if prev is None else prev.get("block_hash")
        if block.get("prev_hash") != expected_prev:
            failures.append(_failure(
                "PREV_HASH_LINK", label, expected_prev, block.get("prev_hash"),
                f"Block {label} prev_hash does not match "
                + ("the genesis value" if prev is None else f"block {prev.get('index')} hash"),
            ))

        # 2. INDEX_SEQUENTIAL: no gaps and no repeated numbers.
        if prev is None:
            expected_index = 0
        elif isinstance(prev.get("index"), int):
            expected_index = prev["index"] + 1
        else:
            expected_index = position
        if index != expected_index:
            failures.append(_failure(
                "INDEX_SEQUENTIAL", label, expected_index, index,
                f"Block at position {position} has index {index}, expected {expected_index}",
            ))

        # 3. BLOCK_HASH_VALID: recompute the hash and compare with the stored one.
        try:
            recomputed = compute_block_hash(block)
        except (TypeError, ValueError):
            recomputed = None
        if recomputed != block.get("block_hash"):
            failures.append(_failure(
                "BLOCK_HASH_VALID", label, recomputed, block.get("block_hash"),
                f"Block {label} contents do not match its stored block_hash",
            ))

        # Signature and custody checks only for the evidence we were asked about.
        evidence_id = block.get("evidence_id")
        in_scope = wanted is None or evidence_id in wanted

        # 4. SIGNATURE_VALID: was it really signed by the registered key?
        if in_scope:
            problem = _signature_problem(block, position, public_keys)
            if problem is not None:
                expected, actual, reason = problem
                failures.append(_failure("SIGNATURE_VALID", label, expected, actual, reason))

        # 5. CUSTODY_CONTINUITY: does this event follow the custody rules?
        if in_scope and block.get("event_type") != GENESIS:
            state = custody_states.get(evidence_id)
            is_register = block.get("event_type") == REGISTER
            try:
                custody.check_block(state, block)
                rule_broken = False
            except CustodyError as error:
                rule_broken = True
                failures.append(_failure(
                    "CUSTODY_CONTINUITY", label, "a valid custody event", error.code,
                    f"Block {label}: {error.message}",
                ))

            # Follow what the chain says even after a broken rule, so one bad
            # block is reported once instead of making every later block fail.
            # Exception: a second REGISTER never replaces the first one.
            if not (is_register and rule_broken):
                custody_states[evidence_id] = custody.apply_block(state, block)

            # Remember where each evidence item was registered, and its hash.
            if is_register and not rule_broken:
                payload = block.get("payload") or {}
                registrations[evidence_id] = (label, payload.get("evidence_sha256"))

        prev = block

    # ----- 6. FILE_HASH_MATCH: re-hash each evidence file -----
    for evidence_id, path in (evidence_files or {}).items():
        failures.extend(_file_problems(evidence_id, path, registrations))

    # ----- 7. CHAIN_HEAD_CONSISTENT: were the newest blocks deleted? -----
    head = _current_head(blocks)
    if last_head is not None:
        failures.extend(_head_problems(blocks, last_head))

    # Sort failures: lowest block first, then by the agreed check order.
    failures.sort(key=_sort_key)

    # Build the result in the team doc's schema.
    duration_ms = round((time.perf_counter() - start) * 1000)
    return {
        "verification_id": new_id(),
        "scope": scope,
        "target_id": target_id,
        "status": "FAIL" if failures else "PASS",
        "engine_version": ENGINE_VERSION,
        "run_by": run_by,
        "run_at": utc_now_iso(),
        "duration_ms": duration_ms,
        "blocks_checked": len(blocks),
        "head": head,
        "checks": failures,
        "first_failure": (
            {"check": failures[0]["check"], "block_index": failures[0]["block_index"]}
            if failures else None
        ),
    }


# ---------- private helpers ----------

def _failure(check: str, block_index, expected, actual, reason: str) -> dict:
    """One failed check, in the team doc's format."""
    return {
        "check": check,
        "block_index": block_index,
        "status": "FAIL",
        "expected": expected,
        "actual": actual,
        "reason": reason,
    }


def _sort_key(failure: dict):
    """Sort by block index (missing index goes last), then by check order."""
    index = failure["block_index"]
    return (index if isinstance(index, int) else math.inf, CHECK_ORDER.index(failure["check"]))


def _signature_problem(block: dict, position: int, public_keys: dict):
    """Return (expected, actual, reason) if the signature is bad, else None."""
    label = block.get("index", position)

    # GENESIS: must be the unsigned first block, and nothing else.
    if block.get("event_type") == GENESIS:
        if position == 0 and block.get("signature") is None and block.get("actor_id") is None:
            return None
        return ("unsigned GENESIS at index 0", "GENESIS elsewhere or signed",
                f"Block {label}: GENESIS is only allowed as the unsigned first block")

    # Every other block must name a signer with a registered public key.
    actor_id = block.get("actor_id")
    public_key_b64 = public_keys.get(actor_id) if actor_id is not None else None
    if public_key_b64 is None:
        return ("a registered public key", None,
                f"Block {label}: no registered public key for the signer")

    # The fingerprint in the block must match the signer's registered key.
    try:
        registered_fingerprint = key_fingerprint(public_key_b64)
    except ValueError:
        return ("a valid public key", "malformed key",
                f"Block {label}: the signer's registered public key is malformed")
    if block.get("key_fingerprint") != registered_fingerprint:
        return (registered_fingerprint, block.get("key_fingerprint"),
                f"Block {label} was signed with key {block.get('key_fingerprint')}, "
                f"but the signer's registered key is {registered_fingerprint}")

    # Finally, the signature itself must verify over the signing fields.
    if not verify_signature(signing_fields(block), block.get("signature"), public_key_b64):
        return ("valid signature", "invalid signature",
                f"Block {label}: signature does not verify against registered key {registered_fingerprint}")

    return None


def _file_problems(evidence_id: str, path, registrations: dict) -> list:
    """FILE_HASH_MATCH for one evidence file."""

    # The evidence must have a REGISTER block in the chain.
    if evidence_id not in registrations:
        return [_failure(
            "FILE_HASH_MATCH", None, "a REGISTER block", None,
            f"Evidence {evidence_id} has no valid REGISTER block in the chain",
        )]
    register_index, registered_hash = registrations[evidence_id]

    # Re-hash the file as it is on disk right now.
    try:
        current_hash = hash_file(path)
    except FileNotFoundError:
        return [_failure(
            "FILE_HASH_MATCH", register_index, registered_hash, None,
            f"Evidence {evidence_id}: stored file is missing",
        )]

    # Compare with the hash recorded in the ledger at registration.
    if current_hash != registered_hash:
        return [_failure(
            "FILE_HASH_MATCH", register_index, registered_hash, current_hash,
            f"Evidence {evidence_id}: file hash differs from the hash registered in block {register_index}",
        )]
    return []


def _current_head(blocks: list):
    """The last block's index and hash, stored with the result for next time."""
    for block in reversed(blocks):
        if isinstance(block, dict):
            return {"head_index": block.get("index"), "head_hash": block.get("block_hash")}
    return None


def _head_problems(blocks: list, last_head: dict) -> list:
    """CHAIN_HEAD_CONSISTENT: the chain must still contain the last recorded head."""
    head_index = last_head.get("head_index")
    head_hash = last_head.get("head_hash")

    # Find the block that used to be the head.
    for block in blocks:
        if isinstance(block, dict) and block.get("index") == head_index:
            # It's still there; it must still have the same hash.
            if block.get("block_hash") != head_hash:
                return [_failure(
                    "CHAIN_HEAD_CONSISTENT", head_index, head_hash, block.get("block_hash"),
                    f"Block {head_index} hash differs from the head recorded at the last verification",
                )]
            return []

    # It's gone: the chain is shorter than it was last time.
    return [_failure(
        "CHAIN_HEAD_CONSISTENT", head_index, head_hash, None,
        f"Chain is shorter than the last recorded head (block {head_index} is missing)",
    )]
