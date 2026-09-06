from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .abi import AbiDecodingError, hex_to_bytes
from .abi_types import decode_abi_parameters
from .keccak import function_selector
from .models import Confidence, DecodedCall, Evidence


@dataclass
class VerifiedContract:
    address: str
    abi: list[dict[str, Any]]
    match: str
    source: str


class SourcifyClient:
    BASE_URL = "https://sourcify.dev/server/v2/contract"

    def __init__(self, timeout: float = 12.0, max_response_bytes: int = 16 * 1024 * 1024) -> None:
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def health(self) -> bool:
        request = urllib.request.Request(
            "https://sourcify.dev/server/health",
            headers={"User-Agent": "rehum/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(4_096)
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError):
            return False

    def fetch(self, chain_id: int, address: str) -> VerifiedContract | None:
        encoded_address = urllib.parse.quote(address, safe="")
        url = f"{self.BASE_URL}/{chain_id}/{encoded_address}?fields=abi"
        request = urllib.request.Request(url, headers={"User-Agent": "rehum/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise RuntimeError(
                        f"Sourcify response exceeds {self.max_response_bytes} byte safety limit"
                    )
                payload = json.loads(raw)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(f"Sourcify lookup failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Sourcify lookup failed: {exc}") from exc
        if not isinstance(payload, dict):
            return None
        abi = payload.get("abi")
        if not isinstance(abi, list):
            return None
        return VerifiedContract(address, abi, str(payload.get("match", "verified")), url)


def canonical_type(parameter: dict[str, Any]) -> str:
    kind = str(parameter.get("type", ""))
    if not kind.startswith("tuple"):
        return kind
    suffix = kind[len("tuple") :]
    components = parameter.get("components") or []
    return "(" + ",".join(canonical_type(component) for component in components) + ")" + suffix


def signature_for(item: dict[str, Any]) -> str:
    inputs = item.get("inputs") or []
    return f"{item['name']}(" + ",".join(canonical_type(parameter) for parameter in inputs) + ")"


def matching_functions(abi: list[dict[str, Any]], selector: str) -> list[tuple[dict[str, Any], str]]:
    matches: list[tuple[dict[str, Any], str]] = []
    for item in abi:
        if item.get("type") != "function" or not item.get("name"):
            continue
        signature = signature_for(item)
        if function_selector(signature) == selector.lower():
            matches.append((item, signature))
    return matches


def apply_verified_abi(call: DecodedCall, contract: VerifiedContract) -> bool:
    matches = matching_functions(contract.abi, call.selector)
    if not matches:
        return False
    item, signature = matches[0]
    types = tuple(canonical_type(parameter) for parameter in item.get("inputs") or [])
    try:
        arguments = decode_abi_parameters(hex_to_bytes(call.raw_data)[4:], item.get("inputs") or [])
        arguments_decoded = True
    except AbiDecodingError:
        arguments = []
        arguments_decoded = False

    call.signature = signature
    call.state_mutability = str(item.get("stateMutability", "unknown"))
    call.argument_types = list(types)
    call.arguments = arguments
    call.arguments_decoded = arguments_decoded
    call.output_parameters = list(item.get("outputs") or [])
    call.error_definitions = [entry for entry in contract.abi if entry.get("type") == "error"]
    call.confidence = Confidence.CONFIRMED if len(matches) == 1 else Confidence.AMBIGUOUS
    call.alternatives = [other_signature for _, other_signature in matches[1:]]
    call.evidence.insert(
        0,
        Evidence(
            "verified ABI",
            f"Sourcify {contract.match} ABI for {contract.address} contains {signature}",
        ),
    )
    return True
