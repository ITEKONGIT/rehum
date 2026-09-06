from __future__ import annotations

import re
from typing import Any


HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
BLOCK_TAGS = {"latest", "pending", "safe", "finalized", "earliest"}


class AbiDecodingError(ValueError):
    pass


def normalize_address(value: str) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise AbiDecodingError("address must be 0x followed by exactly 40 hex characters")
    return value.lower()


def validate_block_tag(value: str) -> str:
    if value in BLOCK_TAGS:
        return value
    if re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        return value.lower()
    raise AbiDecodingError(
        "block must be latest, pending, safe, finalized, earliest, or a canonical hex number"
    )


def hex_to_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise AbiDecodingError("calldata must start with 0x")
    payload = value[2:]
    if len(payload) % 2:
        raise AbiDecodingError("calldata must contain a whole number of bytes")
    if not HEX_RE.fullmatch(payload):
        raise AbiDecodingError("calldata contains non-hexadecimal characters")
    return bytes.fromhex(payload)


def bytes_to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def read_word(data: bytes, offset: int) -> bytes:
    if offset < 0 or offset + 32 > len(data):
        raise AbiDecodingError(f"ABI word at byte offset {offset} exceeds payload length")
    return data[offset : offset + 32]


def read_uint(data: bytes, offset: int) -> int:
    return int.from_bytes(read_word(data, offset), "big")


def decode_address_word(word: bytes) -> str:
    if len(word) != 32:
        raise AbiDecodingError("an ABI address word must contain 32 bytes")
    if any(word[:12]):
        raise AbiDecodingError("address has non-zero high padding")
    return "0x" + word[12:].hex()


def decode_static_word(type_name: str, word: bytes) -> Any:
    if type_name == "address":
        return decode_address_word(word)
    if type_name == "bool":
        value = int.from_bytes(word, "big")
        if value not in (0, 1):
            raise AbiDecodingError(f"invalid ABI boolean value {value}")
        return bool(value)
    if type_name.startswith("uint") or type_name.startswith("int"):
        return int.from_bytes(word, "big", signed=type_name.startswith("int"))
    if type_name == "bytes4":
        return "0x" + word[:4].hex()
    if type_name == "bytes32":
        return "0x" + word.hex()
    raise AbiDecodingError(f"unsupported static ABI type: {type_name}")


def decode_static_arguments(payload: bytes, types: tuple[str, ...]) -> list[Any]:
    expected = 32 * len(types)
    if len(payload) != expected:
        raise AbiDecodingError(
            f"signature expects {expected} argument bytes but calldata contains {len(payload)}"
        )
    return [decode_static_word(kind, read_word(payload, index * 32)) for index, kind in enumerate(types)]


def decode_abi_string(data: bytes) -> str | None:
    """Decode a Solidity string result, accepting legacy bytes32 strings too."""
    try:
        if len(data) == 32:
            return data.rstrip(b"\x00").decode("utf-8") or None
        offset = read_uint(data, 0)
        length = read_uint(data, offset)
        end = offset + 32 + length
        if end > len(data):
            return None
        return data[offset + 32 : end].decode("utf-8")
    except (AbiDecodingError, UnicodeDecodeError):
        return None


def padded_size(length: int) -> int:
    return ((length + 31) // 32) * 32
