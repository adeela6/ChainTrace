"""Unit tests for app/engine/hashing.py."""

import pytest

from app.engine.hashing import (
    CHUNK_SIZE,
    canonical_json,
    hash_bytes,
    hash_file,
    hash_record,
)

# Official SHA-256 test values: if these match, the hashing itself is correct.
EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# ---------- hash_bytes ----------

def test_hash_bytes_empty():
    assert hash_bytes(b"") == EMPTY_HASH


def test_hash_bytes_abc():
    assert hash_bytes(b"abc") == ABC_HASH


def test_hash_bytes_is_64_lowercase_hex():
    result = hash_bytes(b"evidence")
    assert len(result) == 64
    assert result == result.lower()


def test_hash_bytes_rejects_string():
    with pytest.raises(TypeError):
        hash_bytes("abc")


def test_one_byte_change_gives_different_hash():
    assert hash_bytes(b"evidence") != hash_bytes(b"evidencf")


# ---------- hash_file ----------

def test_hash_file_matches_hash_bytes(tmp_path):
    content = b"sample evidence file contents"
    file = tmp_path / "sample.txt"
    file.write_bytes(content)
    assert hash_file(file) == hash_bytes(content)


def test_hash_file_larger_than_one_chunk(tmp_path):
    # 3.5 chunks, so the loop has to read several times
    content = b"x" * (CHUNK_SIZE * 3 + CHUNK_SIZE // 2)
    file = tmp_path / "big.bin"
    file.write_bytes(content)
    assert hash_file(file) == hash_bytes(content)


def test_hash_file_empty_file(tmp_path):
    file = tmp_path / "empty.txt"
    file.write_bytes(b"")
    assert hash_file(file) == EMPTY_HASH


def test_hash_file_detects_one_byte_change(tmp_path):
    file = tmp_path / "evidence.txt"
    file.write_bytes(b"original content")
    before = hash_file(file)
    file.write_bytes(b"original contenT")
    assert hash_file(file) != before


def test_hash_file_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "does_not_exist.txt")


def test_hash_file_rejects_folder(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path)


# ---------- canonical_json / hash_record ----------

def test_canonical_json_exact_format():
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_canonical_json_keeps_unicode():
    assert canonical_json({"name": "José"}) == '{"name":"José"}'.encode("utf-8")


def test_hash_record_ignores_key_order():
    assert hash_record({"a": 1, "b": 2}) == hash_record({"b": 2, "a": 1})


def test_hash_record_nested_key_order():
    one = {"payload": {"x": 1, "y": 2}, "index": 0}
    two = {"index": 0, "payload": {"y": 2, "x": 1}}
    assert hash_record(one) == hash_record(two)


def test_hash_record_detects_value_change():
    assert hash_record({"a": 1}) != hash_record({"a": 2})