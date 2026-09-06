from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .abi import AbiDecodingError, decode_abi_string, hex_to_bytes
from .abi_types import decode_abi_parameters
from .models import CallReport, ContractInfo, DecodedCall, Evidence
from .reverts import decode_revert_data
from .verified_abi import SourcifyClient, VerifiedContract, apply_verified_abi


EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
MINIMAL_PROXY_RE = re.compile(r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3")


class RpcError(RuntimeError):
    def __init__(self, message: str, data: str | None = None) -> None:
        super().__init__(message)
        self.data = data


class RpcClient:
    def __init__(self, url: str, timeout: float = 15.0, max_response_bytes: int = 16 * 1024 * 1024) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("RPC URL must be an absolute http:// or https:// URL")
        self.url = url
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._next_id = 1

    def request(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "rehum/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise RpcError(f"RPC response exceeds {self.max_response_bytes} byte safety limit")
                result = json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RpcError(f"RPC request failed: {exc}") from exc
        if not isinstance(result, dict):
            raise RpcError("RPC returned a non-object JSON response")
        if "error" in result:
            message = result["error"].get("message", str(result["error"]))
            raise RpcError(
                f"RPC {method} failed: {message}",
                self._extract_error_data(result["error"].get("data")),
            )
        return result.get("result")

    @staticmethod
    def _extract_error_data(value: Any) -> str | None:
        if isinstance(value, str) and value.startswith("0x"):
            return value
        if isinstance(value, dict):
            for key in ("data", "result", "return"):
                nested = RpcClient._extract_error_data(value.get(key))
                if nested:
                    return nested
        return None

    def chain_id(self) -> int:
        return int(self.request("eth_chainId", []), 16)

    def block_number(self) -> int:
        return int(self.request("eth_blockNumber", []), 16)

    def get_code(self, address: str, block_tag: str) -> str:
        return self.request("eth_getCode", [address, block_tag])

    def get_storage_at(self, address: str, slot: str, block_tag: str) -> str:
        return self.request("eth_getStorageAt", [address, slot, block_tag])

    def call(self, to: str, data: str, block_tag: str) -> str:
        return self.request("eth_call", [{"to": to, "data": data}, block_tag])


@dataclass
class ProxyResolution:
    implementation: str | None = None
    kind: str | None = None


class RpcEvidenceResolver:
    """Adds on-chain evidence without changing state."""

    def __init__(self, client: RpcClient, use_sourcify: bool = True) -> None:
        self.client = client
        self.sourcify = SourcifyClient() if use_sourcify else None

    def enrich(self, report: CallReport, execute: bool = False) -> None:
        try:
            report.chain_id = self.client.chain_id()
        except RpcError as exc:
            report.warnings.append(str(exc))
            return

        calls = list(self._walk(report.root))
        addresses = {call.target for call in calls}
        for call in calls:
            if call.signature == "getRate(address)" and call.arguments:
                addresses.add(str(call.arguments[0]))

        for address in sorted(addresses):
            report.contracts[address] = self._inspect_contract(address, report.block_tag, report.warnings)

        self._warn_for_missing_call_targets(calls, report)

        self._apply_verified_abis(calls, report)

        for call in calls:
            info = report.contracts.get(call.target)
            if info and info.code_present:
                call.evidence.append(Evidence("bytecode", "target has deployed runtime bytecode on the configured chain"))

        if execute:
            try:
                raw_result = self.client.call(report.to, report.data, report.block_tag)
                self._attach_result(report.root, raw_result)
            except (RpcError, ValueError) as exc:
                detail = f"execution result could not be decoded: {exc}"
                if isinstance(exc, RpcError) and exc.data:
                    reason = decode_revert_data(exc.data, report.root.error_definitions)
                    if reason:
                        report.root.revert_reason = reason
                        detail += f" ({reason})"
                report.warnings.append(detail)

    def _apply_verified_abis(self, calls: list[DecodedCall], report: CallReport) -> None:
        if not self.sourcify or report.chain_id is None:
            return
        cache: dict[str, VerifiedContract | None] = {}
        for call in calls:
            info = report.contracts.get(call.target)
            lookup_address = (info.implementation if info else None) or call.target
            if lookup_address not in cache:
                try:
                    cache[lookup_address] = self.sourcify.fetch(report.chain_id, lookup_address)
                except RuntimeError as exc:
                    report.warnings.append(str(exc))
                    cache[lookup_address] = None
            contract = cache[lookup_address]
            if contract and apply_verified_abi(call, contract) and info:
                info.abi_source = contract.source
                info.verification_match = contract.match

    @staticmethod
    def _warn_for_missing_call_targets(calls: list[DecodedCall], report: CallReport) -> None:
        missing = sorted(
            {
                call.target
                for call in calls
                if int(call.target, 16) > 0xFFFF
                and report.contracts.get(call.target)
                and report.contracts[call.target].code_present is False
            }
        )
        if missing:
            report.warnings.append(
                "configured chain has no code at called target(s): "
                + ", ".join(missing)
                + "; verify that the RPC is for the call's actual network"
            )

    def _inspect_contract(self, address: str, block_tag: str, warnings: list[str]) -> ContractInfo:
        info = ContractInfo(address)
        try:
            code = self.client.get_code(address, block_tag)
            info.code_present = code not in ("0x", "0x0", None)
            if not info.code_present:
                return info
            proxy = self._resolve_proxy(address, code, block_tag)
            info.implementation = proxy.implementation
            info.proxy_kind = proxy.kind
            info.name = self._read_text(address, "0x06fdde03", block_tag)
            info.symbol = self._read_text(address, "0x95d89b41", block_tag)
            info.decimals = self._read_uint(address, "0x313ce567", block_tag)
        except RpcError as exc:
            warnings.append(f"could not inspect {address}: {exc}")
        return info

    def _resolve_proxy(self, address: str, code: str, block_tag: str) -> ProxyResolution:
        match = MINIMAL_PROXY_RE.search(code.lower().removeprefix("0x"))
        if match:
            return ProxyResolution("0x" + match.group(1), "EIP-1167 minimal proxy")

        implementation_word = self.client.get_storage_at(address, EIP1967_IMPLEMENTATION_SLOT, block_tag)
        implementation = self._storage_address(implementation_word)
        if implementation:
            return ProxyResolution(implementation, "EIP-1967 proxy")

        beacon_word = self.client.get_storage_at(address, EIP1967_BEACON_SLOT, block_tag)
        beacon = self._storage_address(beacon_word)
        if beacon:
            try:
                result = self.client.call(beacon, "0x5c60da1b", block_tag)
                implementation = self._storage_address(result)
            except RpcError:
                implementation = None
            return ProxyResolution(implementation, "EIP-1967 beacon proxy")
        return ProxyResolution()

    @staticmethod
    def _storage_address(word: str | None) -> str | None:
        if not word or len(word.removeprefix("0x")) < 40:
            return None
        address = "0x" + word.removeprefix("0x")[-40:].lower()
        return None if int(address, 16) == 0 else address

    def _read_text(self, address: str, selector: str, block_tag: str) -> str | None:
        try:
            return decode_abi_string(hex_to_bytes(self.client.call(address, selector, block_tag)))
        except (RpcError, ValueError):
            return None

    def _read_uint(self, address: str, selector: str, block_tag: str) -> int | None:
        try:
            raw = hex_to_bytes(self.client.call(address, selector, block_tag))
            return int.from_bytes(raw, "big") if raw else None
        except (RpcError, ValueError):
            return None

    def _attach_result(self, root: DecodedCall, raw_result: str) -> None:
        root.return_data = raw_result
        if root.signature != "aggregate3((address,bool,bytes)[])":
            self._decode_return_value(root, hex_to_bytes(raw_result))
            return
        data = hex_to_bytes(raw_result)
        array_offset = int.from_bytes(data[:32], "big")
        count = int.from_bytes(data[array_offset : array_offset + 32], "big")
        heads = array_offset + 32
        if count != len(root.children):
            raise ValueError(f"aggregate3 returned {count} results for {len(root.children)} calls")
        for index, child in enumerate(root.children):
            tuple_start = heads + int.from_bytes(data[heads + index * 32 : heads + (index + 1) * 32], "big")
            child.success = bool(int.from_bytes(data[tuple_start : tuple_start + 32], "big"))
            bytes_offset = int.from_bytes(data[tuple_start + 32 : tuple_start + 64], "big")
            bytes_start = tuple_start + bytes_offset
            length = int.from_bytes(data[bytes_start : bytes_start + 32], "big")
            result = data[bytes_start + 32 : bytes_start + 32 + length]
            child.return_data = "0x" + result.hex()
            if child.success:
                self._decode_return_value(child, result)
            else:
                child.revert_reason = decode_revert_data(
                    child.return_data, child.error_definitions
                )

    @staticmethod
    def _decode_return_value(call: DecodedCall, result: bytes) -> None:
        if not call.output_parameters:
            return
        try:
            values = decode_abi_parameters(result, call.output_parameters)
        except AbiDecodingError:
            return
        call.return_value = values[0] if len(values) == 1 else values
        call.return_decoded = True

    @staticmethod
    def _walk(call: DecodedCall):
        yield call
        for child in call.children:
            yield from RpcEvidenceResolver._walk(child)
