"""Unit tests for app/engine/keys.py."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization

from app.engine.exceptions import KeyManagementError
from app.engine.hashing import hash_bytes
from app.engine.keys import (
    decrypt_private_key,
    encrypt_private_key,
    generate_keypair,
    generate_master_key,
    key_fingerprint,
    new_user_keys,
    public_key_from_b64,
    public_key_to_b64,
)


@pytest.fixture
def master_key():
    # A fresh master key for each test that asks for one.
    return generate_master_key()


# ---------- public key encoding ----------

def test_public_key_is_base64_of_32_bytes():
    public_b64 = public_key_to_b64(generate_keypair().public_key())
    assert len(base64.b64decode(public_b64)) == 32


def test_public_key_round_trip():
    # Object -> text -> object -> text must give the same text back.
    public_b64 = public_key_to_b64(generate_keypair().public_key())
    restored = public_key_from_b64(public_b64)
    assert public_key_to_b64(restored) == public_b64


def test_two_keypairs_are_different():
    one = public_key_to_b64(generate_keypair().public_key())
    two = public_key_to_b64(generate_keypair().public_key())
    assert one != two


def test_public_key_from_b64_rejects_garbage():
    with pytest.raises(KeyManagementError):
        public_key_from_b64("not base64!!")


def test_public_key_from_b64_rejects_wrong_length():
    with pytest.raises(KeyManagementError):
        public_key_from_b64(base64.b64encode(b"short").decode())


def test_public_key_from_b64_rejects_non_string():
    with pytest.raises(KeyManagementError):
        public_key_from_b64(12345)


# ---------- fingerprint ----------

def test_fingerprint_is_first_16_hex_of_sha256():
    # The team doc's rule: first 16 hex characters of SHA-256(raw public key).
    public_b64 = public_key_to_b64(generate_keypair().public_key())
    raw = base64.b64decode(public_b64)
    assert key_fingerprint(public_b64) == hash_bytes(raw)[:16]
    assert len(key_fingerprint(public_b64)) == 16


def test_fingerprint_is_stable():
    public_b64 = public_key_to_b64(generate_keypair().public_key())
    assert key_fingerprint(public_b64) == key_fingerprint(public_b64)


# ---------- private key encryption ----------

def test_encrypt_decrypt_round_trip(master_key):
    # After encrypting and decrypting, it must still be the same key pair.
    private_key = generate_keypair()
    token = encrypt_private_key(private_key, master_key)
    restored = decrypt_private_key(token, master_key)
    assert public_key_to_b64(restored.public_key()) == public_key_to_b64(private_key.public_key())


def test_encrypted_key_does_not_contain_plain_key(master_key):
    # The stored text must not contain the private key in any readable form.
    private_key = generate_keypair()
    raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    token = encrypt_private_key(private_key, master_key)
    assert base64.b64encode(raw).decode() not in token
    assert raw.hex() not in token


def test_decrypt_with_wrong_master_key_fails(master_key):
    token = encrypt_private_key(generate_keypair(), master_key)
    with pytest.raises(KeyManagementError):
        decrypt_private_key(token, generate_master_key())


def test_decrypt_tampered_token_fails(master_key):
    # Change one character in the middle of the encrypted text.
    token = encrypt_private_key(generate_keypair(), master_key)
    middle = len(token) // 2
    swapped = "A" if token[middle] != "A" else "B"
    tampered = token[:middle] + swapped + token[middle + 1:]
    with pytest.raises(KeyManagementError):
        decrypt_private_key(tampered, master_key)


def test_invalid_master_key_rejected():
    with pytest.raises(KeyManagementError):
        encrypt_private_key(generate_keypair(), "not-a-real-key")


def test_error_message_does_not_leak_key(master_key):
    # Safe errors: the message must not contain the token or the master key.
    token = encrypt_private_key(generate_keypair(), master_key)
    with pytest.raises(KeyManagementError) as info:
        decrypt_private_key(token, generate_master_key())
    assert token not in str(info.value)
    assert master_key not in str(info.value)


# ---------- new_user_keys ----------

def test_new_user_keys_fields(master_key):
    keys = new_user_keys(master_key)
    assert set(keys) == {"public_key", "encrypted_private_key", "key_fingerprint"}
    assert keys["key_fingerprint"] == key_fingerprint(keys["public_key"])


def test_new_user_keys_private_matches_public(master_key):
    # The stored private key must be the partner of the stored public key.
    keys = new_user_keys(master_key)
    private_key = decrypt_private_key(keys["encrypted_private_key"], master_key)
    assert public_key_to_b64(private_key.public_key()) == keys["public_key"]
