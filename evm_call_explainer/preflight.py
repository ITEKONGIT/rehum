from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from .abi import AbiDecodingError, validate_block_tag
from .abi_types import decode_abi_parameters
from .cli import load_config
from .decoder import CalldataDecoder
from .keccak import function_selector, keccak_256
from .registry import FunctionRegistry, MULTICALL3_ADDRESS
from .rpc import RpcClient, RpcError
from .signature_lookup import SignatureLookupClient
from .verified_abi import SourcifyClient


class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str


@dataclass
class PreflightReport:
    checks: list[CheckResult]

    @property
    def passed(self) -> bool:
        return not any(check.status == CheckStatus.FAIL for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "checks": [asdict(check) for check in self.checks]}


class PreflightRunner:
    def __init__(
        self,
        config: dict[str, Any] | None = None,
        rpc_url: str | None = None,
        require_rpc: bool = False,
    ) -> None:
        self.config = config or {}
        self.rpc_url = rpc_url or os.environ.get("EVM_EXPLAINER_RPC_URL") or self.config.get("rpc_url")
        self.require_rpc = require_rpc
        self.checks: list[CheckResult] = []

    def run(self) -> PreflightReport:
        self._check("Python runtime", self._python_runtime)
        self._check("Ethereum Keccak", self._keccak_vectors)
        self._check("Function registry", self._registry_integrity)
        self._check("Decoder self-test", self._decoder_self_test)
        self._check("Dynamic ABI engine", self._dynamic_abi_self_test)
        self._check("Configuration", self._configuration)
        self._signature_lookup_check()
        self._network_checks()
        return PreflightReport(self.checks)

    def _check(self, name: str, operation: Callable[[], str]) -> None:
        try:
            detail = operation()
            self.checks.append(CheckResult(name, CheckStatus.PASS, detail))
        except Exception as exc:  # preflight must report every failed boundary
            self.checks.append(CheckResult(name, CheckStatus.FAIL, str(exc)))

    @staticmethod
    def _python_runtime() -> str:
        if sys.version_info < (3, 11):
            raise RuntimeError("Python 3.11 or newer is required")
        return f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    @staticmethod
    def _keccak_vectors() -> str:
        empty_hash = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        if keccak_256(b"").hex() != empty_hash:
            raise RuntimeError("Keccak-256 empty-input vector failed")
        if function_selector("balanceOf(address)") != "0x70a08231":
            raise RuntimeError("balanceOf(address) selector vector failed")
        return "Keccak hash and selector vectors match Ethereum"

    @staticmethod
    def _registry_integrity() -> str:
        registry = FunctionRegistry()
        checked = 0
        for candidate in registry.all_candidates():
            if function_selector(candidate.signature) != candidate.selector:
                raise RuntimeError(
                    f"registry mismatch: {candidate.signature} does not produce {candidate.selector}"
                )
            checked += 1
        return f"{checked} registered signatures reproduce their selectors"

    @staticmethod
    def _decoder_self_test() -> str:
        wallet = "f13918dce6f2ae689548478cb83e4cad836adb7a"
        data = "0x70a08231" + ("00" * 12) + wallet
        report = CalldataDecoder().decode(
            "0xf50fff154e63e510e494929e9eab1e9c5047429e", data
        )
        if report.root.signature != "balanceOf(address)":
            raise RuntimeError("known ERC-20 call did not decode")
        if report.root.arguments != ["0x" + wallet]:
            raise RuntimeError("ABI address extraction did not preserve the final 20 bytes")
        return "known ERC-20 calldata decodes with the expected address"

    @staticmethod
    def _dynamic_abi_self_test() -> str:
        text = b"ready"
        word = lambda value: value.to_bytes(32, "big")
        encoded = word(32) + word(len(text)) + text + bytes((-len(text)) % 32)
        decoded = decode_abi_parameters(encoded, [{"name": "value", "type": "string"}])
        if decoded != ["ready"]:
            raise RuntimeError("dynamic string did not decode correctly")
        return "dynamic offsets and string values decode correctly"

    def _configuration(self) -> str:
        allowed = {
            "rpc_url",
            "block_tag",
            "execute",
            "sourcify",
            "signature_lookup",
            "max_calls",
            "max_payload_bytes",
        }
        unknown = sorted(set(self.config) - allowed)
        if unknown:
            raise ValueError("unknown configuration keys: " + ", ".join(unknown))
        validate_block_tag(str(self.config.get("block_tag", "latest")))
        max_calls = int(self.config.get("max_calls", 4_096))
        max_payload = int(self.config.get("max_payload_bytes", 4 * 1024 * 1024))
        if not 1 <= max_calls <= 100_000:
            raise ValueError("max_calls must be between 1 and 100000")
        if not 4 <= max_payload <= 64 * 1024 * 1024:
            raise ValueError("max_payload_bytes must be between 4 and 67108864")
        if not isinstance(self.config.get("execute", False), bool):
            raise ValueError("execute must be true or false")
        if not isinstance(self.config.get("sourcify", True), bool):
            raise ValueError("sourcify must be true or false")
        if not isinstance(self.config.get("signature_lookup", True), bool):
            raise ValueError("signature_lookup must be true or false")
        if self.rpc_url:
            RpcClient(str(self.rpc_url))
        return "configuration schema and safety limits are valid"

    def _network_checks(self) -> None:
        if not self.rpc_url:
            status = CheckStatus.FAIL if self.require_rpc else CheckStatus.WARN
            self.checks.append(
                CheckResult(
                    "RPC connectivity",
                    status,
                    "no RPC configured; static decoding works but chain evidence is unavailable",
                )
            )
            self.checks.append(
                CheckResult(
                    "Sourcify connectivity",
                    CheckStatus.WARN,
                    "skipped until an RPC identifies the chain",
                )
            )
            return

        try:
            client = RpcClient(str(self.rpc_url))
            chain_id = client.chain_id()
            block = client.block_number()
            code = client.get_code(MULTICALL3_ADDRESS, "latest")
            detail = f"chain ID {chain_id}, latest block {block}; Multicall3 code "
            detail += "present" if code not in (None, "0x", "0x0") else "not deployed"
            self.checks.append(CheckResult("RPC connectivity", CheckStatus.PASS, detail))
        except (RpcError, ValueError) as exc:
            self.checks.append(CheckResult("RPC connectivity", CheckStatus.FAIL, str(exc)))
            return

        if not self.config.get("sourcify", True):
            self.checks.append(
                CheckResult("Sourcify connectivity", CheckStatus.WARN, "disabled by configuration")
            )
        elif SourcifyClient().health():
            self.checks.append(
                CheckResult("Sourcify connectivity", CheckStatus.PASS, "Sourcify health endpoint responded")
            )
        else:
            self.checks.append(
                CheckResult(
                    "Sourcify connectivity",
                    CheckStatus.WARN,
                    "service was unreachable; RPC and local decoding remain available",
                )
            )

    def _signature_lookup_check(self) -> None:
        if not self.config.get("signature_lookup", False):
            self.checks.append(
                CheckResult(
                    "Signature lookup connectivity",
                    CheckStatus.WARN,
                    "not enabled in the loaded configuration",
                )
            )
        elif SignatureLookupClient().health():
            self.checks.append(
                CheckResult(
                    "Signature lookup connectivity",
                    CheckStatus.PASS,
                    "Sourcify 4byte health endpoint responded",
                )
            )
        else:
            self.checks.append(
                CheckResult(
                    "Signature lookup connectivity",
                    CheckStatus.WARN,
                    "service was unreachable; local and verified-ABI decoding remain available",
                )
            )


class PreflightRenderer:
    def render(self, report: PreflightReport) -> str:
        lines = ["REHUM PREFLIGHT", ""]
        symbols = {CheckStatus.PASS: "PASS", CheckStatus.WARN: "WARN", CheckStatus.FAIL: "FAIL"}
        lines.extend(f"[{symbols[item.status]}] {item.name}: {item.detail}" for item in report.checks)
        passed = sum(item.status == CheckStatus.PASS for item in report.checks)
        warned = sum(item.status == CheckStatus.WARN for item in report.checks)
        failed = sum(item.status == CheckStatus.FAIL for item in report.checks)
        lines.extend(("", f"Summary: {passed} passed, {warned} warnings, {failed} failed"))
        return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Rehum before use")
    parser.add_argument("--config", type=Path, help="JSON configuration file")
    parser.add_argument("--rpc-url", help="override configured RPC URL")
    parser.add_argument("--require-rpc", action="store_true", help="fail instead of warn when no RPC is configured")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
    except (ValueError, AbiDecodingError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = PreflightRunner(config, args.rpc_url, args.require_rpc).run()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(PreflightRenderer().render(report))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
