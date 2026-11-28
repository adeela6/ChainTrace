"""Safe, synthetic test data for the ChainTrace engine (T1-T6 fixtures).

Everything here is made up: fake users, small harmless files, no real
evidence, no personal data, no malware.

How it's meant to be used:
    1. build_demo_scenario() makes a known-good state (users, files, chain).
    2. Each tamper_* / helper function breaks EXACTLY ONE thing on a copy.
    3. A test runs verify_chain() and checks the right failure is reported.

Run this file directly to write the fixtures to a folder for inspection:
    python -m fixtures.engine_fixtures fixtures/generated
"""

import base64
import copy
import json
import struct
import sys
import zlib
from pathlib import Path

from app.engine.blocks import (
    ACCEPT,
    REGISTER,
    TRANSFER,
    build_block,
    compute_block_hash,
    create_genesis_block,
    new_id,
    signing_fields,
)
from app.engine.hashing import hash_file
from app.engine.keys import generate_keypair, key_fingerprint, public_key_to_b64
from app.engine.signing import sign_fields

# Fixed timestamps, so the fixtures look the same every time.
BASE_TIME = "2026-11-10T08:{minute:02d}:00.000Z"


# ---------- users ----------

def make_user(name: str) -> dict:
    """A fake analyst with a fresh key pair (test use only)."""

    # Generate a key pair and keep both halves (tests need to sign).
    private_key = generate_keypair()
    return {
        "id": new_id(),
        "name": name,
        "private_key": private_key,
        "public_key": public_key_to_b64(private_key.public_key()),
    }


# ---------- sample evidence files ----------

def write_sample_files(folder) -> dict:
    """Write four small, safe sample files and return {name: path}."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)

    # Plain-text and structured samples (all made-up content).
    samples = {
        "incident_notes.txt": b"Incident 042: laptop seized at 09:30, sealed in bag #881.\n",
        "server_access.log": (
            b"2026-11-09T22:14:03Z 10.0.0.5 GET /admin 403\n"
            b"2026-11-09T22:14:09Z 10.0.0.5 POST /login 401\n"
        ),
        "chat_export.json": json.dumps(
            {"export": "synthetic", "messages": [{"from": "user_a", "text": "meet at 6"}]}
        ).encode("utf-8"),
        "cctv_frame.png": _tiny_png(),
    }

    # Write each file and remember where it went.
    paths = {}
    for name, content in samples.items():
        path = folder / name
        path.write_bytes(content)
        paths[name] = path
    return paths


# ---------- a known-good chain ----------

def build_demo_scenario(folder) -> dict:
    """Build a valid chain: genesis, 4 registrations, and 3 completed handovers.

    Returns a dict with:
        users          {"ahmed": user, "sara": user, "bilal": user}
        blocks         the chain (list of block dicts)
        public_keys    {user_id: public_key_b64}
        evidence       {file name: {"id", "case_id", "path", "sha256"}}
        evidence_files {evidence_id: path} (ready for verify_chain)
        transfers      list of TRANSFER blocks (handy for the replay test)
    """

    # Three fake analysts.
    users = {name: make_user(name) for name in ("ahmed", "sara", "bilal")}
    ahmed, sara, bilal = users["ahmed"], users["sara"], users["bilal"]

    # Two cases, and four sample files spread across them.
    case_1, case_2 = new_id(), new_id()
    paths = write_sample_files(folder)
    evidence = {}
    for number, (name, path) in enumerate(paths.items()):
        evidence[name] = {
            "id": new_id(),
            "case_id": case_1 if number < 2 else case_2,
            "path": path,
            "sha256": hash_file(path),
            "size": path.stat().st_size,
        }

    # Start the chain with the genesis block.
    chain = _ChainBuilder()

    # Ahmed registers all four files.
    mime_types = {".txt": "text/plain", ".log": "text/plain",
                  ".json": "application/json", ".png": "image/png"}
    for name, item in evidence.items():
        chain.add(
            REGISTER, item, ahmed,
            {
                "evidence_sha256": item["sha256"],
                "size_bytes": item["size"],
                "mime_type": mime_types[Path(name).suffix],
                "original_filename": name,
            },
        )

    # Three complete handovers (each = TRANSFER signed by sender + ACCEPT by receiver).
    notes = evidence["incident_notes.txt"]
    log = evidence["server_access.log"]
    chain.handover(notes, ahmed, sara, "Sent to lab for analysis")
    chain.handover(notes, sara, bilal, "Second review by senior examiner")
    chain.handover(log, ahmed, sara, "Log review")

    return {
        "users": users,
        "blocks": chain.blocks,
        "public_keys": {user["id"]: user["public_key"] for user in users.values()},
        "evidence": evidence,
        "evidence_files": {item["id"]: item["path"] for item in evidence.values()},
        "transfers": chain.transfers,
    }


def build_long_chain(n_blocks: int, folder) -> dict:
    """A valid chain with at least n_blocks blocks (for T5 and timing).

    One file is handed back and forth between two analysts until the
    chain is long enough.
    """

    # Two analysts and one sample file.
    ahmed, sara = make_user("ahmed"), make_user("sara")
    path = write_sample_files(folder)["incident_notes.txt"]
    item = {"id": new_id(), "case_id": new_id(), "path": path, "sha256": hash_file(path)}

    # Genesis + REGISTER.
    chain = _ChainBuilder()
    chain.add(REGISTER, item, ahmed, {
        "evidence_sha256": item["sha256"],
        "size_bytes": path.stat().st_size,
        "mime_type": "text/plain",
        "original_filename": path.name,
    })

    # Hand it back and forth (2 blocks per handover) until long enough.
    holder, other = ahmed, sara
    while len(chain.blocks) < n_blocks:
        chain.handover(item, holder, other, "Routine handover")
        holder, other = other, holder

    return {
        "users": {"ahmed": ahmed, "sara": sara},
        "blocks": chain.blocks,
        "public_keys": {ahmed["id"]: ahmed["public_key"], sara["id"]: sara["public_key"]},
        "evidence_files": {item["id"]: path},
        "item": item,
        "holder": holder,
    }


# ---------- breaking exactly one thing ----------

def tamper_block_payload(blocks: list, index: int, field: str, value, rehash: bool = False) -> list:
    """T1: edit one payload field of one block (like editing the DB directly).

    rehash=False -> a careless attacker: stored block_hash left unchanged
                    (caught by BLOCK_HASH_VALID at that block).
    rehash=True  -> a smarter attacker also rewrites block_hash
                    (caught by SIGNATURE_VALID, and PREV_HASH_LINK at the next block).
    """
    tampered = copy.deepcopy(blocks)
    tampered[index]["payload"][field] = value
    if rehash:
        tampered[index]["block_hash"] = compute_block_hash(tampered[index])
    return tampered


def alter_file(path) -> None:
    """T2: change one byte of a file on disk (flips the first byte)."""
    path = Path(path)
    data = bytearray(path.read_bytes())
    data[0] ^= 0x01
    path.write_bytes(bytes(data))


def flip_signature_byte(blocks: list, index: int, rehash: bool = True) -> list:
    """T3: corrupt one byte of a stored signature.

    By default the attacker also recomputes block_hash, so the first
    failure reported is SIGNATURE_VALID at that block.
    """
    tampered = copy.deepcopy(blocks)
    raw = bytearray(base64.b64decode(tampered[index]["signature"]))
    raw[0] ^= 0x01
    tampered[index]["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    if rehash:
        tampered[index]["block_hash"] = compute_block_hash(tampered[index])
    return tampered


def resign_with_wrong_key(blocks: list, index: int, wrong_user: dict) -> list:
    """T3: re-sign a stored block with someone else's key, keeping its actor_id.

    The block still claims to be from the original signer, but the key
    fingerprint and signature now belong to wrong_user.
    """
    tampered = copy.deepcopy(blocks)
    block = tampered[index]
    block["key_fingerprint"] = key_fingerprint(wrong_user["public_key"])
    block["signature"] = sign_fields(signing_fields(block), wrong_user["private_key"])
    block["block_hash"] = compute_block_hash(block)
    return tampered


def forged_transfer_block(scenario: dict, signer_name: str, claimed_name: str) -> dict:
    """T3 (append time): a TRANSFER that claims to be from claimed_name
    but is actually signed with signer_name's private key.

    validate_new_block() must reject it with INVALID_SIGNATURE.
    """
    users = scenario["users"]
    item = scenario["evidence"]["chat_export.json"]
    claimed = users[claimed_name]
    return build_block(
        scenario["blocks"][-1],
        event_type=TRANSFER,
        case_id=item["case_id"],
        evidence_id=item["id"],
        actor_id=claimed["id"],
        payload={
            "transfer_id": new_id(),
            "from_user_id": claimed["id"],
            "to_user_id": users["sara"]["id"],
            "evidence_sha256": item["sha256"],
            "reason": "Forged transfer",
        },
        private_key=users[signer_name]["private_key"],
    )


def append_replayed_transfer(scenario: dict, transfer_index: int = 0) -> list:
    """T4: re-append an old TRANSFER (same transfer_id) at the end of the chain.

    The replay is properly signed by the original sender, so only the
    custody rules can catch it (CUSTODY_CONTINUITY).
    """
    original = scenario["transfers"][transfer_index]
    sender = _user_by_id(scenario["users"], original["actor_id"])
    blocks = copy.deepcopy(scenario["blocks"])
    replay = build_block(
        blocks[-1],
        event_type=TRANSFER,
        case_id=original["case_id"],
        evidence_id=original["evidence_id"],
        actor_id=original["actor_id"],
        payload=dict(original["payload"]),
        private_key=sender["private_key"],
    )
    blocks.append(replay)
    return blocks


def delete_block(blocks: list, index: int) -> list:
    """T5: remove one block from the middle of the chain."""
    tampered = copy.deepcopy(blocks)
    del tampered[index]
    return tampered


def truncate_head(blocks: list, how_many: int) -> list:
    """Remove the newest blocks (caught only by CHAIN_HEAD_CONSISTENT)."""
    return copy.deepcopy(blocks[:-how_many])


# ---------- writing fixtures to disk ----------

def write_fixture_files(folder) -> list:
    """Write the clean chain and each broken variant as JSON files.

    Private keys are never written. Returns the list of files created.
    """
    folder = Path(folder)
    scenario = build_demo_scenario(folder / "samples")
    blocks = scenario["blocks"]

    # One clean chain plus one file per broken case.
    variants = {
        "valid_chain.json": blocks,
        "t1_tampered_record.json": tamper_block_payload(blocks, 5, "evidence_sha256", "0" * 64),
        "t3_flipped_signature.json": flip_signature_byte(blocks, 6),
        "t3_wrong_key.json": resign_with_wrong_key(blocks, 6, scenario["users"]["bilal"]),
        "t4_replayed_transfer.json": append_replayed_transfer(scenario),
        "t5_deleted_block.json": delete_block(blocks, 4),
        "head_truncated.json": truncate_head(blocks, 2),
    }

    written = []
    for name, chain in variants.items():
        path = folder / name
        path.write_text(json.dumps(chain, indent=2), encoding="utf-8")
        written.append(path)

    # The public key registry (public keys are not secret).
    keys_path = folder / "public_keys.json"
    keys_path.write_text(json.dumps(scenario["public_keys"], indent=2), encoding="utf-8")
    written.append(keys_path)
    return written


# ---------- private helpers ----------

class _ChainBuilder:
    """Keeps the growing chain and adds blocks with fixed, readable timestamps."""

    def __init__(self):
        self.blocks = [create_genesis_block(timestamp=BASE_TIME.format(minute=0))]
        self.transfers = []

    def add(self, event_type: str, item: dict, user: dict, payload: dict) -> dict:
        minute = len(self.blocks) % 60
        block = build_block(
            self.blocks[-1],
            event_type=event_type,
            case_id=item["case_id"],
            evidence_id=item["id"],
            actor_id=user["id"],
            payload=payload,
            private_key=user["private_key"],
            timestamp=BASE_TIME.format(minute=minute),
        )
        self.blocks.append(block)
        return block

    def handover(self, item: dict, sender: dict, receiver: dict, reason: str) -> None:
        transfer_id = new_id()
        transfer = self.add(TRANSFER, item, sender, {
            "transfer_id": transfer_id,
            "from_user_id": sender["id"],
            "to_user_id": receiver["id"],
            "evidence_sha256": item["sha256"],
            "reason": reason,
        })
        self.transfers.append(transfer)
        self.add(ACCEPT, item, receiver, {
            "transfer_id": transfer_id,
            "evidence_sha256": item["sha256"],
        })


def _user_by_id(users: dict, user_id: str) -> dict:
    for user in users.values():
        if user["id"] == user_id:
            return user
    raise KeyError(user_id)


def _tiny_png() -> bytes:
    """A real, valid 1x1 grey PNG image built in code (no binary file needed)."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)   # 1x1, 8-bit greyscale
    pixels = zlib.compress(b"\x00\x80")                    # filter byte + one grey pixel
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "fixtures/generated"
    for written_path in write_fixture_files(out):
        print("wrote", written_path)
