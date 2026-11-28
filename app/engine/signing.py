"""Ed25519 signing and signature verification for ChainTrace (FR-3)."""

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.engine.hashing import canonical_json
from app.engine.keys import public_key_from_b64

SIGNATURE_SIZE = 64  # Ed25519 signatures are always 64 bytes


def sign_fields(fields: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign the canonical JSON of a dict and return the signature as base64."""

    # Only dicts can be signed, because only dicts have a canonical form.
    if not isinstance(fields, dict):
        raise TypeError("sign_fields expects a dict")

    # Turn the fields into their one fixed byte form, so the verifier can
    # rebuild exactly the same bytes later.
    message = canonical_json(fields)

    # Sign the bytes with the private key (gives 64 raw bytes).
    signature = private_key.sign(message)

    # Encode the signature as base64 text for database storage.
    return base64.b64encode(signature).decode("ascii")


def verify_signature(fields: dict, signature_b64: str, public_key_b64: str) -> bool:
    """Return True only if the signature is valid for these fields and this key.

    This never raises for bad input. A malformed signature or key is simply
    "not a valid signature", so callers only have to handle True or False.
    """

    # Reject wrong input types straight away.
    if not isinstance(fields, dict) or not isinstance(signature_b64, str):
        return False

    # Decode the base64 signature back into raw bytes.
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False

    # An Ed25519 signature must be exactly 64 bytes.
    if len(signature) != SIGNATURE_SIZE:
        return False

    # Rebuild the public key object from the stored base64 text.
    # (KeyManagementError is a ValueError, so this also catches bad keys.)
    try:
        public_key = public_key_from_b64(public_key_b64)
    except ValueError:
        return False

    # Rebuild the exact signed bytes and check the signature against them.
    try:
        public_key.verify(signature, canonical_json(fields))
    except (InvalidSignature, TypeError, ValueError):
        return False

    return True
