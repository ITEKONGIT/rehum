from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .abi import AbiDecodingError, decode_address_word, read_uint, read_word


ARRAY_SUFFIX_RE = re.compile(r"\[([0-9]*)\]")
INTEGER_RE = re.compile(r"^(u?int)([0-9]*)$")
FIXED_BYTES_RE = re.compile(r"^bytes([0-9]+)$")


@dataclass(frozen=True)
class AbiType:
    kind: str
    canonical: str
    name: str = ""
    bits: int | None = None
    byte_length: int | None = None
    item: "AbiType | None" = None
    array_length: int | None = None
    components: tuple["AbiType", ...] = ()

    @property
    def is_dynamic(self) -> bool:
        if self.kind in {"string", "bytes"}:
            return True
        if self.kind == "array":
            return self.array_length is None or bool(self.item and self.item.is_dynamic)
        if self.kind == "tuple":
            return any(component.is_dynamic for component in self.components)
        return False

    @property
    def static_size(self) -> int:
        if self.is_dynamic:
            raise AbiDecodingError(f"dynamic type {self.canonical} has no inline static size")
        if self.kind == "array":
            assert self.item is not None and self.array_length is not None
            return self.array_length * self.item.static_size
        if self.kind == "tuple":
            return sum(component.static_size for component in self.components)
        return 32


def parse_abi_parameter(parameter: dict[str, Any]) -> AbiType:
    raw_type = str(parameter.get("type", ""))
    name = str(parameter.get("name", ""))
    base = raw_type.split("[", 1)[0]
    suffixes = ARRAY_SUFFIX_RE.findall(raw_type[len(base) :])
    if "".join(f"[{suffix}]" for suffix in suffixes) != raw_type[len(base) :]:
        raise AbiDecodingError(f"invalid ABI type syntax: {raw_type}")

    if base == "tuple":
        components = tuple(parse_abi_parameter(item) for item in parameter.get("components") or [])
        node = AbiType("tuple", "(" + ",".join(item.canonical for item in components) + ")", name, components=components)
    elif base == "address":
        node = AbiType("address", base, name)
    elif base == "bool":
        node = AbiType("bool", base, name)
    elif base == "string":
        node = AbiType("string", base, name)
    elif base == "bytes":
        node = AbiType("bytes", base, name)
    elif base == "function":
        node = AbiType("function", base, name, byte_length=24)
    else:
        integer = INTEGER_RE.fullmatch(base)
        fixed_bytes = FIXED_BYTES_RE.fullmatch(base)
        if integer:
            bits = int(integer.group(2) or "256")
            if bits < 8 or bits > 256 or bits % 8:
                raise AbiDecodingError(f"invalid integer width in ABI type: {base}")
            kind = "uint" if integer.group(1) == "uint" else "int"
            node = AbiType(kind, f"{kind}{bits}", name, bits=bits)
        elif fixed_bytes:
            length = int(fixed_bytes.group(1))
            if not 1 <= length <= 32:
                raise AbiDecodingError(f"invalid fixed-bytes width in ABI type: {base}")
            node = AbiType("fixed_bytes", base, name, byte_length=length)
        else:
            raise AbiDecodingError(f"unsupported ABI type: {raw_type}")

    for suffix in suffixes:
        length = None if suffix == "" else int(suffix)
        if length is not None and length < 0:
            raise AbiDecodingError(f"invalid array length in ABI type: {raw_type}")
        canonical = node.canonical + ("[]" if length is None else f"[{length}]")
        node = AbiType("array", canonical, name, item=node, array_length=length)
    return node


class AbiValueDecoder:
    def __init__(self, max_depth: int = 32, max_elements: int = 100_000) -> None:
        self.max_depth = max_depth
        self.max_elements = max_elements
        self._elements_seen = 0

    def decode_parameters(self, data: bytes, parameters: list[dict[str, Any]]) -> list[Any]:
        self._elements_seen = 0
        types = tuple(parse_abi_parameter(parameter) for parameter in parameters)
        return self._decode_sequence(data, 0, types, 0)

    def _decode_sequence(
        self,
        data: bytes,
        base: int,
        types: tuple[AbiType, ...],
        depth: int,
    ) -> list[Any]:
        self._guard_depth(depth)
        head_size = sum(32 if item.is_dynamic else item.static_size for item in types)
        if base < 0 or base + head_size > len(data):
            raise AbiDecodingError("ABI sequence head exceeds payload length")
        cursor = base
        values: list[Any] = []
        for item in types:
            self._count_element()
            if item.is_dynamic:
                relative = read_uint(data, cursor)
                if relative % 32:
                    raise AbiDecodingError(f"offset for {item.canonical} is not 32-byte aligned")
                if relative < head_size:
                    raise AbiDecodingError(f"offset for {item.canonical} overlaps its sequence head")
                values.append(self._decode_value(data, base + relative, item, depth + 1))
                cursor += 32
            else:
                values.append(self._decode_value(data, cursor, item, depth + 1))
                cursor += item.static_size
        return values

    def _decode_value(self, data: bytes, offset: int, item: AbiType, depth: int) -> Any:
        self._guard_depth(depth)
        if item.kind == "array":
            assert item.item is not None
            if item.array_length is None:
                length = read_uint(data, offset)
                self._guard_collection(length, item.canonical)
                return self._decode_sequence(data, offset + 32, (item.item,) * length, depth + 1)
            self._guard_collection(item.array_length, item.canonical)
            return self._decode_sequence(data, offset, (item.item,) * item.array_length, depth + 1)

        if item.kind == "tuple":
            values = self._decode_sequence(data, offset, item.components, depth + 1)
            names = [component.name for component in item.components]
            if names and all(names) and len(set(names)) == len(names):
                return dict(zip(names, values))
            return values

        if item.kind in {"string", "bytes"}:
            length = read_uint(data, offset)
            self._guard_collection(length, item.canonical)
            start = offset + 32
            end = start + length
            if end > len(data):
                raise AbiDecodingError(f"{item.canonical} data exceeds payload length")
            value = data[start:end]
            if item.kind == "bytes":
                return "0x" + value.hex()
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return value.decode("utf-8", errors="replace")

        word = read_word(data, offset)
        if item.kind == "address":
            return decode_address_word(word)
        if item.kind == "bool":
            value = int.from_bytes(word, "big")
            if value not in (0, 1):
                raise AbiDecodingError(f"invalid ABI boolean value {value}")
            return bool(value)
        if item.kind == "uint":
            value = int.from_bytes(word, "big")
            assert item.bits is not None
            if value >= 1 << item.bits:
                raise AbiDecodingError(f"value does not fit {item.canonical}")
            return value
        if item.kind == "int":
            assert item.bits is not None
            value = int.from_bytes(word, "big", signed=True)
            minimum = -(1 << (item.bits - 1))
            maximum = (1 << (item.bits - 1)) - 1
            if not minimum <= value <= maximum:
                raise AbiDecodingError(f"value is not correctly sign-extended for {item.canonical}")
            return value
        if item.kind in {"fixed_bytes", "function"}:
            assert item.byte_length is not None
            value = word[: item.byte_length]
            if any(word[item.byte_length :]):
                raise AbiDecodingError(f"{item.canonical} has non-zero right padding")
            return "0x" + value.hex()
        raise AbiDecodingError(f"cannot decode ABI type {item.canonical}")

    def _guard_depth(self, depth: int) -> None:
        if depth > self.max_depth:
            raise AbiDecodingError(f"ABI value nesting exceeds safety limit {self.max_depth}")

    def _guard_collection(self, length: int, type_name: str) -> None:
        if length > self.max_elements:
            raise AbiDecodingError(
                f"{type_name} contains {length} elements/bytes; safety limit is {self.max_elements}"
            )

    def _count_element(self) -> None:
        self._elements_seen += 1
        if self._elements_seen > self.max_elements:
            raise AbiDecodingError(f"decoded ABI element count exceeds safety limit {self.max_elements}")


def decode_abi_parameters(data: bytes, parameters: list[dict[str, Any]]) -> list[Any]:
    return AbiValueDecoder().decode_parameters(data, parameters)
