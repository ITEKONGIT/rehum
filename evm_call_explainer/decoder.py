from __future__ import annotations

from .abi import (
    AbiDecodingError,
    bytes_to_hex,
    decode_address_word,
    decode_static_arguments,
    hex_to_bytes,
    normalize_address,
    read_uint,
    read_word,
    validate_block_tag,
)
from .models import CallReport, Confidence, DecodedCall, Evidence
from .registry import FunctionCandidate, FunctionRegistry, MULTICALL3_ADDRESS


class CalldataDecoder:
    def __init__(
        self,
        registry: FunctionRegistry | None = None,
        max_depth: int = 12,
        max_calls: int = 4_096,
        max_payload_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self.registry = registry or FunctionRegistry()
        self.max_depth = max_depth
        self.max_calls = max_calls
        self.max_payload_bytes = max_payload_bytes

    def decode(self, to: str, data: str, block_tag: str = "latest") -> CallReport:
        target = normalize_address(to)
        raw = hex_to_bytes(data)
        block_tag = validate_block_tag(block_tag)
        if len(raw) < 4:
            raise AbiDecodingError("calldata needs at least a four-byte function selector")
        if len(raw) > self.max_payload_bytes:
            raise AbiDecodingError(
                f"calldata contains {len(raw)} bytes; safety limit is {self.max_payload_bytes}"
            )
        root = self._decode_call(target, raw, depth=0)
        return CallReport(target, bytes_to_hex(raw), block_tag, root)

    def _decode_call(self, target: str, raw: bytes, depth: int) -> DecodedCall:
        if depth > self.max_depth:
            raise AbiDecodingError(f"nested-call depth exceeds safety limit {self.max_depth}")

        selector = bytes_to_hex(raw[:4])
        call = DecodedCall(target=target, raw_data=bytes_to_hex(raw), selector=selector)

        if selector == "0x82ad56cb":
            if target == MULTICALL3_ADDRESS:
                call.signature = "aggregate3((address,bool,bytes)[])"
                call.state_mutability = "payable"
                call.confidence = Confidence.CONFIRMED
                call.evidence.extend(
                    (
                        Evidence("address", "target is the canonical Multicall3 deployment address"),
                        Evidence("selector", "0x82ad56cb is aggregate3((address,bool,bytes)[])"),
                        Evidence("structure", "dynamic array and tuple offsets are ABI-valid"),
                    )
                )
            else:
                call.signature = "aggregate3((address,bool,bytes)[])"
                call.state_mutability = "payable"
                call.confidence = Confidence.LIKELY
                call.evidence.append(Evidence("selector", "selector matches Multicall3 aggregate3"))
            call.children = self._decode_aggregate3(raw[4:], depth)
            call.arguments_decoded = True
            return call

        candidates = self._compatible_candidates(selector, raw[4:])
        if not candidates:
            call.evidence.append(Evidence("selector", "no compatible signature exists in the local registry"))
            return call

        chosen = candidates[0]
        call.signature = chosen.signature
        call.state_mutability = chosen.state_mutability
        call.argument_types = list(chosen.argument_types)
        call.arguments = decode_static_arguments(raw[4:], chosen.argument_types)
        call.arguments_decoded = True
        call.output_parameters = [{"name": "", "type": kind} for kind in chosen.return_types]
        call.confidence = chosen.confidence if len(candidates) == 1 else Confidence.AMBIGUOUS
        call.alternatives = [candidate.signature for candidate in candidates[1:]]
        if chosen.standard:
            call.evidence.append(Evidence("standard", f"selector and layout match {chosen.standard}"))
        else:
            call.evidence.append(Evidence("selector", f"local registry candidate is {chosen.signature}"))
        if len(candidates) > 1:
            call.evidence.append(Evidence("collision", "multiple signatures accept the same encoded layout"))
        return call

    def _compatible_candidates(self, selector: str, payload: bytes) -> list[FunctionCandidate]:
        compatible: list[FunctionCandidate] = []
        for candidate in self.registry.candidates(selector):
            try:
                decode_static_arguments(payload, candidate.argument_types)
            except AbiDecodingError:
                continue
            compatible.append(candidate)
        return compatible

    def _decode_aggregate3(self, args: bytes, depth: int) -> list[DecodedCall]:
        array_offset = read_uint(args, 0)
        if array_offset % 32:
            raise AbiDecodingError("aggregate3 array offset is not 32-byte aligned")
        count = read_uint(args, array_offset)
        if count > self.max_calls:
            raise AbiDecodingError(
                f"aggregate3 contains {count} calls; safety limit is {self.max_calls}"
            )
        heads = array_offset + 32
        if heads + count * 32 > len(args):
            raise AbiDecodingError("aggregate3 array head exceeds payload length")
        children: list[DecodedCall] = []

        for index in range(count):
            relative_offset = read_uint(args, heads + index * 32)
            if relative_offset % 32:
                raise AbiDecodingError(f"aggregate3 item {index} offset is not 32-byte aligned")
            if relative_offset < count * 32:
                raise AbiDecodingError(f"aggregate3 item {index} overlaps the array head")
            tuple_start = heads + relative_offset
            target = decode_address_word(read_word(args, tuple_start))
            allow_value = read_uint(args, tuple_start + 32)
            if allow_value not in (0, 1):
                raise AbiDecodingError(f"aggregate3 item {index} has invalid allowFailure boolean")
            bytes_offset = read_uint(args, tuple_start + 64)
            if bytes_offset % 32 or bytes_offset < 96:
                raise AbiDecodingError(f"aggregate3 item {index} has an invalid callData offset")
            bytes_start = tuple_start + bytes_offset
            payload_length = read_uint(args, bytes_start)
            payload_start = bytes_start + 32
            payload_end = payload_start + payload_length
            if payload_end > len(args):
                raise AbiDecodingError(f"aggregate3 item {index} callData exceeds payload length")
            payload = args[payload_start:payload_end]
            if len(payload) < 4:
                nested = DecodedCall(target, bytes_to_hex(payload), "0x", allow_failure=bool(allow_value))
                nested.evidence.append(Evidence("structure", "nested calldata is shorter than a selector"))
            else:
                nested = self._decode_call(target, payload, depth + 1)
                nested.allow_failure = bool(allow_value)
            children.append(nested)
        return children
