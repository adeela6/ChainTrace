from hashlib import sha256
from pathlib import Path
import json

CHUNK_SIZE = 64 * 1024 # 64kb, for hash_file function


def hash_bytes(data:bytes)-> str:
    """hashes the bytes using SHA-256 and returns the hex digest"""
    if not isinstance(data, bytes):
        raise TypeError("hash_bytes expects bytes")

    return sha256(data).hexdigest()


def hash_file(path) -> str:
    """hashes the file using SHA-256, readin it in 64kb chunks and returns the hex digest"""
    # 1. turn path into a Path; if it's not a file -> raise FileNotFoundError
    # 2. make an empty hashlib.sha256() object
    # 3. open the file in "rb" mode
    # 4. loop: read CHUNK_SIZE bytes; if empty -> stop; else .update(chunk)
    # 5. return the hexdigest

    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path.name}")

    sha256_hash = sha256()
    with file_path.open('rb') as file:
        chunk = file.read(CHUNK_SIZE)
        sha256_hash.update(chunk)
        while chunk:
            chunk = file.read(CHUNK_SIZE)
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def canonical_json(obj:dict) -> bytes:
    """One fixed byte form of a dict, so the same data always hashes the same."""
    json_str = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return json_str.encode('utf-8')


def hash_record(obj:dict) -> str:
    """SHA-256 of a dict's canonical JSON. Used for block hashes."""
    return hash_bytes(canonical_json(obj))