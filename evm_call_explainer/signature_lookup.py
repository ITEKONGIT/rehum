from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .abi import AbiDecodingError, hex_to_bytes
from .abi_types import decode_abi_parameters, parse_abi_parameter
from .keccak import function_selector
from .models import CallReport, Confidence, DecodedCall, Evidence


@dataclass(frozen=True)
class SignatureCandidate:
    signature: str
    inputs: list[dict[str, Any]]
    has_verified_contract: bool


def _split_top_level(value: str) -> list[str]:
    if not value:
        return []
    output: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced tuple signature")
        elif character == "," and depth == 0:
            output.append(value[start:index])
            start = index + 1
    if depth:
        raise ValueError("unbalanced tuple signature")
    output.append(value[start:])
    return output


def _parameter_from_canonical(value: str) -> dict[str, Any]:
    if not value:
        raise ValueError("empty ABI parameter type")
    if value.startswith("("):
        depth = 0
        closing = None
        for index, character in enumerate(value):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            raise ValueError("unterminated tuple type")
        suffix = value[closing + 1 :]
        if suffix and not suffix.startswith("["):
            raise ValueError("invalid tuple suffix")
        components = [
            _parameter_from_canonical(item)
            for item in _split_top_level(value[1:closing])
        ]
        parameter: dict[str, Any] = {
            "name": "",
            "type": "tuple" + suffix,
            "components": components,
        }
    else:
        parameter = {"name": "", "type": value}
    # Validate immediately; unsupported or malformed candidates are discarded.
    parse_abi_parameter(parameter)
    return parameter


def parse_function_signature(signature: str) -> tuple[str, list[dict[str, Any]]]:
    opening = signature.find("(")
    if opening <= 0 or not signature.endswith(")"):
        raise ValueError("invalid function signature")
    name = signature[:opening]
    if not name or any(character.isspace() for character in name):
        raise ValueError("invalid function name")
    inputs = [
        _parameter_from_canonical(item)
        for item in _split_top_level(signature[opening + 1 : -1])
    ]
    return name, inputs


class SignatureLookupClient:
    BASE_URL = "https://api.4byte.sourcify.dev/signature-database/v1/lookup"

    def __init__(self, timeout: float = 8.0, max_response_bytes: int = 2 * 1024 * 1024) -> None:
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def health(self) -> bool:
        request = urllib.request.Request(
            "https://api.4byte.sourcify.dev/health",
            headers={"User-Agent": "rehum/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(4_096)
                return 200 <= response.status < 300
        except (urllib.error.URLError, TimeoutError):
            return False

    def lookup(self, selectors: list[str]) -> dict[str, list[SignatureCandidate]]:
        unique = sorted(set(selector.lower() for selector in selectors))
        if not unique:
            return {}
        query = urllib.parse.urlencode({"function": ",".join(unique), "filter": "true"})
        request = urllib.request.Request(
            f"{self.BASE_URL}?{query}",
            headers={"User-Agent": "rehum/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(self.max_response_bytes + 1)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"signature lookup failed: {exc}") from exc
        if len(raw) > self.max_response_bytes:
            raise RuntimeError("signature lookup response exceeded its safety limit")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("signature lookup returned invalid JSON") from exc
        functions = (payload.get("result") or {}).get("function") or {}
        output: dict[str, list[SignatureCandidate]] = {}
        for selector in unique:
            candidates: list[SignatureCandidate] = []
            for entry in functions.get(selector) or []:
                signature = entry.get("name")
                if not isinstance(signature, str) or function_selector(signature) != selector:
                    continue
                try:
                    _, inputs = parse_function_signature(signature)
                except (ValueError, AbiDecodingError):
                    continue
                candidates.append(
                    SignatureCandidate(
                        signature,
                        inputs,
                        bool(entry.get("hasVerifiedContract", False)),
                    )
                )
            output[selector] = sorted(
                candidates,
                key=lambda item: (not item.has_verified_contract, item.signature),
            )
        return output


class SignatureEvidenceResolver:
    def __init__(self, client: SignatureLookupClient | None = None) -> None:
        self.client = client or SignatureLookupClient()

    def enrich(self, report: CallReport) -> None:
        unresolved = [
            call
            for call in self._walk(report.root)
            if call.confidence in {Confidence.UNKNOWN, Confidence.LIKELY}
        ]
        if not unresolved:
            return
        try:
            results = self.client.lookup(
                [call.selector for call in unresolved if call.selector != "0x"]
            )
        except RuntimeError as exc:
            report.warnings.append(str(exc))
            return
        for call in unresolved:
            self._apply_candidates(call, results.get(call.selector, []))

    @staticmethod
    def _apply_candidates(call: DecodedCall, candidates: list[SignatureCandidate]) -> None:
        compatible: list[tuple[SignatureCandidate, list[Any]]] = []
        arguments = hex_to_bytes(call.raw_data)[4:]
        for candidate in candidates:
            try:
                decoded = decode_abi_parameters(arguments, candidate.inputs)
            except AbiDecodingError:
                continue
            compatible.append((candidate, decoded))
        if not compatible:
            return
        chosen, decoded = compatible[0]
        call.signature = chosen.signature
        call.arguments = decoded
        call.argument_types = [parse_abi_parameter(item).canonical for item in chosen.inputs]
        call.arguments_decoded = True
        call.confidence = Confidence.LIKELY if len(compatible) == 1 else Confidence.AMBIGUOUS
        call.alternatives = [candidate.signature for candidate, _ in compatible[1:]]
        verified_note = "seen in a verified contract" if chosen.has_verified_contract else "database candidate"
        call.evidence.append(
            Evidence(
                "signature database",
                f"Sourcify 4byte candidate {chosen.signature} is structurally compatible ({verified_note})",
            )
        )
        if len(compatible) > 1:
            call.evidence.append(
                Evidence("collision", f"{len(compatible)} selector candidates fit the calldata")
            )

    @staticmethod
    def _walk(call: DecodedCall):
        yield call
        for child in call.children:
            yield from SignatureEvidenceResolver._walk(child)
