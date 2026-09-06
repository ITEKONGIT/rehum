from __future__ import annotations

import json
from typing import Any

from .abi import AbiDecodingError, hex_to_bytes, read_uint
from .abi_types import decode_abi_parameters
from .keccak import function_selector
from .verified_abi import signature_for


PANIC_CODES = {
    0x00: "generic compiler panic",
    0x01: "assert(false)",
    0x11: "arithmetic overflow or underflow",
    0x12: "division or modulo by zero",
    0x21: "invalid enum conversion",
    0x22: "incorrectly encoded storage byte array",
    0x31: "pop() on an empty array",
    0x32: "array or bytes index out of bounds",
    0x41: "excessive memory allocation",
    0x51: "call to an uninitialized internal function",
}


def decode_revert_data(value: str, error_definitions: list[dict[str, Any]] | None = None) -> str | None:
    try:
        data = hex_to_bytes(value)
        if len(data) < 4:
            return None
        selector = data[:4].hex()
        if selector == "08c379a0":
            decoded = decode_abi_parameters(data[4:], [{"name": "message", "type": "string"}])
            return f"Error({decoded[0]!r})"
        if selector == "4e487b71" and len(data) >= 36:
            code = read_uint(data, 4)
            meaning = PANIC_CODES.get(code, "unknown panic code")
            return f"Panic(0x{code:x}: {meaning})"
        for definition in error_definitions or []:
            if definition.get("type") != "error" or not definition.get("name"):
                continue
            signature = signature_for(definition)
            if function_selector(signature).removeprefix("0x") != selector:
                continue
            decoded = decode_abi_parameters(data[4:], definition.get("inputs") or [])
            rendered = ", ".join(
                json.dumps(item, separators=(",", ":")) if isinstance(item, (dict, list)) else repr(item)
                for item in decoded
            )
            return f"{definition['name']}({rendered})"
        return f"custom error selector 0x{selector}"
    except (AbiDecodingError, ValueError, IndexError):
        return None
