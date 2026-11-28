"""Unit tests for app/engine/signing.py."""

import base64

import pytest

from app.engine.keys import generate_keypair, public_key_to_b64
from app.engine.signing import sign_fields, verify_signature

FIELDS = {"index": 1, "event_type": "TRANSFER", "payload": {"reason": "Sent to lab"}}


@pytest.fixture
def keypair():
    # A private key and its public key as base64 text.
    private_key = generate_keypair()
    return private_key, public_key_to_b64(private_key.public_key())


def test_signature_is_base64_of_64_bytes(keypair):
    private_key, _ = keypair
    signature = sign_fields(FIELDS, private_key)
    assert len(base64.b64decode(signature)) == 64


def test_valid_signature_verifies(keypair):
    private_key, public_b64 = keypair
    signature = sign_fields(FIELDS, private_key)
    assert verify_signature(FIELDS, signature, public_b64) is True


def test_key_order_does_not_matter(keypair):
    # Signing uses canonical JSON, so the same data in another order still verifies.
    private_key, public_b64 = keypair
    signature = sign_fields(FIELDS, private_key)
    reordered = {"payload": {"reason": "Sent to lab"}, "event_type": "TRANSFER", "index": 1}
    assert verify_signature(reordered, signature, public_b64) is True


def test_changed_data_fails(keypair):
    # Any change to the signed data breaks the signature.
    private_key, public_b64 = keypair
    signature = sign_fields(FIELDS, private_key)
    changed = {**FIELDS, "index": 2}
    assert verify_signature(changed, signature, public_b64) is False


def test_wrong_public_key_fails(keypair):
    # T3: a signature checked against someone else's key must fail.
    private_key, _ = keypair
    signature = sign_fields(FIELDS, private_key)
    other_public = public_key_to_b64(generate_keypair().public_key())
    assert verify_signature(FIELDS, signature, other_public) is False


def test_flipped_signature_byte_fails(keypair):
    # T3: one corrupted byte in the signature must fail.
    private_key, public_b64 = keypair
    raw = bytearray(base64.b64decode(sign_fields(FIELDS, private_key)))
    raw[0] ^= 0x01
    flipped = base64.b64encode(bytes(raw)).decode()
    assert verify_signature(FIELDS, flipped, public_b64) is False


@pytest.mark.parametrize("bad_signature", ["", "not base64!!", base64.b64encode(b"short").decode(), None, 123])
def test_malformed_signature_returns_false(keypair, bad_signature):
    # Bad input never crashes: it's simply not a valid signature.
    _, public_b64 = keypair
    assert verify_signature(FIELDS, bad_signature, public_b64) is False


@pytest.mark.parametrize("bad_key", ["", "not base64!!", None])
def test_malformed_public_key_returns_false(keypair, bad_key):
    private_key, _ = keypair
    signature = sign_fields(FIELDS, private_key)
    assert verify_signature(FIELDS, signature, bad_key) is False


def test_sign_rejects_non_dict(keypair):
    private_key, _ = keypair
    with pytest.raises(TypeError):
        sign_fields("not a dict", private_key)
