from __future__ import annotations

import json
from collections import Counter
from decimal import Decimal
from typing import Any

from .models import CallReport, DecodedCall
from .registry import MULTICALL3_ADDRESS


CHAIN_NAMES = {
    1: "Ethereum Mainnet",
    10: "Optimism",
    56: "BNB Smart Chain",
    137: "Polygon",
    8453: "Base",
    42161: "Arbitrum One",
    42220: "Celo Mainnet",
}


class EnglishRenderer:
    def render(self, report: CallReport) -> str:
        lines: list[str] = ["REHUM - FULL CALL OVERVIEW", ""]
        if report.chain_id is None:
            lines.append("Network: not verified (no RPC configured)")
        else:
            name = CHAIN_NAMES.get(report.chain_id, "unknown EVM network")
            lines.append(f"Network: {name} (chain ID {report.chain_id})")
        lines.append("Evidence sources: " + ", ".join(report.evidence_sources))
        lines.append(f"Block: {report.block_tag}")
        lines.append(f"Target: {self._label(report, report.to)}")
        lines.append(f"Function: {report.root.signature or report.root.selector}")
        lines.append("")
        lines.append("Purpose")
        lines.append(self._purpose(report.root))
        lines.append("")
        lines.append("Operations")
        lines.extend(self._root_summary(report))
        if report.contracts:
            lines.extend(("", "Contracts"))
            lines.extend(self._contract_lines(report))
        lines.extend(("", "Uncertainty"))
        lines.extend(self._uncertainty_lines(report.root))
        lines.append("")
        lines.append("Evidence")
        lines.append(f"Confidence: {report.root.confidence.value.upper()}")
        for item in report.root.evidence:
            lines.append(f"- {item.detail}")
        if report.warnings:
            lines.append("")
            lines.append("Warnings")
            lines.extend(f"- {warning}" for warning in report.warnings)
        lines.extend(("", "Safety"))
        if report.root.return_data is not None:
            lines.append("The RPC evaluated this through eth_call, so the simulation could not persist state changes.")
        elif report.chain_id is not None:
            lines.append("Chain evidence was fetched read-only; no eth_call execution result was requested or available.")
        else:
            lines.append("No RPC simulation ran; this is a static interpretation of the supplied calldata.")
        if self._contains_state_changing_call(report.root):
            lines.append(
                "The calldata includes a state-changing function; sending the same data as a transaction could change state."
            )
        return "\n".join(lines)

    @staticmethod
    def _purpose(root: DecodedCall) -> str:
        calls = root.children or [root]
        names = Counter(
            (call.signature or call.selector).split("(", 1)[0]
            for call in calls
        )
        if root.signature == "aggregate3((address,bool,bytes)[])":
            summary = ", ".join(f"{count} {name}" for name, count in names.items())
            return f"Batch {len(calls)} calls in one request: {summary}."
        return f"Perform one {root.signature or root.selector} call."

    def _root_summary(self, report: CallReport) -> list[str]:
        root = report.root
        if root.signature == "aggregate3((address,bool,bytes)[])":
            lines = [f"This asks Multicall3 to perform {len(root.children)} contract calls:"]
            for index, child in enumerate(root.children, 1):
                lines.append(f"{index}. {self._describe_call(report, child)}")
                suffix: list[str] = []
                if child.allow_failure:
                    suffix.append("failure allowed")
                suffix.append(f"confidence: {child.confidence.value}")
                lines[-1] += f" ({'; '.join(suffix)})"
            if any(child.allow_failure for child in root.children):
                lines.append("")
                lines.append("Calls marked 'failure allowed' may fail without cancelling the rest of the batch.")
            return lines
        return [self._describe_call(report, root)]

    @staticmethod
    def _contract_lines(report: CallReport) -> list[str]:
        lines: list[str] = []
        for address, info in sorted(report.contracts.items()):
            details: list[str] = []
            if info.label:
                details.append(info.label)
            details.append("contract code present" if info.code_present else "no contract code")
            if info.proxy_kind:
                details.append(f"{info.proxy_kind} -> {info.implementation or 'unknown implementation'}")
            if info.decimals is not None:
                details.append(f"{info.decimals} decimals")
            if info.verification_match:
                details.append(f"Sourcify {info.verification_match}")
            lines.append(f"- {address}: " + "; ".join(details))
        return lines

    @staticmethod
    def _uncertainty_lines(root: DecodedCall) -> list[str]:
        calls = list(EnglishRenderer._walk(root))
        counts = Counter(call.confidence.value for call in calls)
        lines = ["- " + ", ".join(f"{value} {level}" for level, value in sorted(counts.items()))]
        ambiguous = [call for call in calls if call.alternatives]
        for call in ambiguous:
            lines.append(
                f"- {call.selector} alternatives: " + ", ".join(call.alternatives)
            )
        if not ambiguous and not any(call.confidence.value == "unknown" for call in calls):
            lines.append("- No unresolved selector alternatives in this decode.")
        return lines

    def _describe_call(self, report: CallReport, call: DecodedCall) -> str:
        target = self._label(report, call.target)
        args = call.arguments
        if call.signature == "getRate(address)" and args:
            text = f"Ask {target} for the rate of {self._label(report, args[0])}."
        elif call.signature == "balanceOf(address)" and args:
            text = f"Read {self._label(report, call.target)} balance owned by {args[0]}."
        elif call.signature == "allowance(address,address)" and len(args) == 2:
            text = f"Read how much {args[1]} may spend for {args[0]} on {target}."
        elif call.signature == "approve(address,uint256)" and len(args) == 2:
            text = f"Simulate approving {args[0]} to spend {args[1]} units on {target}."
        elif call.signature == "transfer(address,uint256)" and len(args) == 2:
            text = f"Simulate transferring {args[1]} units of {target} to {args[0]}."
        elif call.signature and call.arguments_decoded:
            rendered = ", ".join(self._format_value(value) for value in args)
            text = f"Call {call.signature.split('(')[0]}({rendered}) on {target}."
        elif call.signature:
            text = (
                f"Call {call.signature} on {target}; its dynamic arguments are not yet "
                "decoded by this version."
            )
        else:
            text = f"Call unknown selector {call.selector} on {target}."
        if call.success is not None:
            text += " Result: " + ("success." if call.success else "failed.")
        if call.return_decoded:
            text += f" Returned: {self._format_return(report, call)}."
        if call.revert_reason:
            text += f" Revert: {call.revert_reason}."
        return text

    def _format_return(self, report: CallReport, call: DecodedCall) -> str:
        if call.signature == "balanceOf(address)" and isinstance(call.return_value, int):
            info = report.contracts.get(call.target)
            if info and info.decimals is not None:
                amount = Decimal(call.return_value) / (Decimal(10) ** info.decimals)
                label = f" {info.symbol}" if info.symbol else " tokens"
                return f"{amount.normalize()}{label} (raw {call.return_value})"
        return self._format_value(call.return_value)

    @staticmethod
    def _format_value(value: Any) -> str:
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"))
        return str(value)

    @staticmethod
    def _label(report: CallReport, address: str) -> str:
        if address == MULTICALL3_ADDRESS:
            return f"Multicall3 ({address})"
        info = report.contracts.get(address)
        if not info or not info.label:
            return address
        return f"{info.label} ({address})"

    @staticmethod
    def _walk(call: DecodedCall):
        yield call
        for child in call.children:
            yield from EnglishRenderer._walk(child)

    @staticmethod
    def _contains_state_changing_call(root: DecodedCall) -> bool:
        return any(
            call.state_mutability in {"nonpayable", "payable"}
            and call.signature != "aggregate3((address,bool,bytes)[])"
            for call in EnglishRenderer._walk(root)
        )


class JsonRenderer:
    def render(self, report: CallReport) -> str:
        return json.dumps(report.to_dict(), indent=2)
