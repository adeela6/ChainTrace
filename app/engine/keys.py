import binascii
import base64



from cryptography.fernet import Fernet, InvalidToken
from app.engine.exceptions import KeyManagementError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.engine.hashing import hash_bytes

KEY_SIZE = 32
FINGERPRINT_LENGTH = 16


def generate_master_key() -> str:
    """Create a new Fernet master key (run once during setup, put in .env)."""

    #Fernet.generate_key() returns a bytes object, but we want to store 
    #it as a string in the config file, so we decode it to ascii. 
    #The key is base64-encoded, so ascii is safe.

    return Fernet.generate_key().decode("ascii")


def _fernet(master_key) -> Fernet:
    """Build a Fernet object; clear error if the master key is bad."""

    # Convert the master key to bytes if it was provided as a string.
    if isinstance(master_key, str):
        master_key = master_key.encode("ascii")
    # Either it was string or not this try block still run
    try:
        return Fernet(master_key)
    # If it was not a valid Fernet key, Fernet() will raise a ValueError.
    except (ValueError, TypeError, binascii.Error):
        raise KeyManagementError("Master key is invalid") from None
    



def generate_keypair() -> Ed25519PrivateKey:
    """Generate a new Ed25519 keypair. Returns the private key object."""
    return Ed25519PrivateKey.generate()


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    """Convert an Ed25519 public key to a base64 string."""

     # Serialize the public key into its raw 32-byte representation.
    raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)

    # Encode the raw bytes as base64 text for database storage.
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(public_key_b64: str) -> Ed25519PublicKey:
    """Convert a Base64 string back into an Ed25519 public key object."""

    # Decode the Base64 string into raw bytes.
    raw = _decode_b64(public_key_b64)

    # Ensure the decoded public key has the expected size.
    if len(raw) != KEY_SIZE:
        raise KeyManagementError("Public key must be 32 bytes")

    # Reconstruct and return the Ed25519 public key object.
    return Ed25519PublicKey.from_public_bytes(raw)




def key_fingerprint(public_key_b64: str) -> str:
    """Generate a short fingerprint from a public key using SHA-256."""

    # Decode the Base64 public key into raw bytes.
    raw = _decode_b64(public_key_b64)

    # Ensure the public key has the expected size.
    if len(raw) != KEY_SIZE:
        raise KeyManagementError("Public key must be 32 bytes")

    # Calculate the SHA-256 hash and return its first 16 hexadecimal characters.
    return hash_bytes(raw)[:FINGERPRINT_LENGTH]



def encrypt_private_key(private_key: Ed25519PrivateKey, master_key) -> str:
    """Encrypt an Ed25519 private key using the Fernet master key."""

    # Serialize the private key into its raw 32-byte representation.
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the raw private key using Fernet.
    encrypted = _fernet(master_key).encrypt(raw)

    # Convert the encrypted bytes into ASCII text for storage.
    return encrypted.decode("ascii")




def decrypt_private_key(encrypted_private_key: str, master_key) -> Ed25519PrivateKey:
    """Decrypt a stored private key and reconstruct its Ed25519 object."""

    try:
        # Convert the encrypted key text into bytes and decrypt it.
        raw = _fernet(master_key).decrypt(
            encrypted_private_key.encode("ascii")
        )

    except (InvalidToken, AttributeError, UnicodeEncodeError):
        # Raise a clear application-specific error if decryption fails.
        raise KeyManagementError("Private key could not be decrypted") from None

    # Ensure the decrypted private key has the expected size.
    if len(raw) != KEY_SIZE:
        raise KeyManagementError("Private key could not be decrypted")

    # Reconstruct and return the Ed25519 private key object.
    return Ed25519PrivateKey.from_private_bytes(raw)




def new_user_keys(master_key) -> dict:
    """Generate and return the keys and fingerprint for a new analyst."""

    # Generate a new Ed25519 private key.
    private_key = generate_keypair()

    # Derive the corresponding public key and encode it as Base64.
    public_b64 = public_key_to_b64(private_key.public_key())

    # Return the public key, encrypted private key, and fingerprint.
    return {
        "public_key": public_b64,
        "encrypted_private_key": encrypt_private_key(private_key, master_key),
        "key_fingerprint": key_fingerprint(public_b64)
    }



def _decode_b64(value: str) -> bytes:
    """Decode Base64 text into raw bytes with validation."""

    # Ensure the input is a string.
    if not isinstance(value, str):
        raise KeyManagementError("Key must be base64 text")

    try:
        # Decode Base64 text into bytes and validate the input.
        return base64.b64decode(value, validate=True)

    except (binascii.Error, ValueError):
        raise KeyManagementError("Key is not valid base64") from None