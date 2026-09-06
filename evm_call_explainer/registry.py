from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence


MULTICALL3_ADDRESS = "0xca11bde05977b3631167028862be2a173976ca11"


@dataclass(frozen=True)
class FunctionCandidate:
    selector: str
    signature: str
    argument_types: tuple[str, ...]
    return_types: tuple[str, ...] = ()
    confidence: Confidence = Confidence.LIKELY
    standard: str | None = None
    state_mutability: str = "unknown"


class FunctionRegistry:
    """Local, auditable knowledge base. Multiple candidates may share a selector."""

    def __init__(self) -> None:
        entries = (
            FunctionCandidate("0x82ad56cb", "aggregate3((address,bool,bytes)[])", (), state_mutability="payable"),
            FunctionCandidate("0x37cef791", "getRate(address)", ("address",), confidence=Confidence.LIKELY, state_mutability="view"),
            FunctionCandidate("0x70a08231", "balanceOf(address)", ("address",), ("uint256",), Confidence.STANDARD, "ERC-20/ERC-721", "view"),
            FunctionCandidate("0xdd62ed3e", "allowance(address,address)", ("address", "address"), ("uint256",), Confidence.STANDARD, "ERC-20", "view"),
            FunctionCandidate("0x095ea7b3", "approve(address,uint256)", ("address", "uint256"), ("bool",), Confidence.STANDARD, "ERC-20", "nonpayable"),
            FunctionCandidate("0xa9059cbb", "transfer(address,uint256)", ("address", "uint256"), ("bool",), Confidence.STANDARD, "ERC-20", "nonpayable"),
            FunctionCandidate("0x23b872dd", "transferFrom(address,address,uint256)", ("address", "address", "uint256"), ("bool",), Confidence.STANDARD, "ERC-20/ERC-721", "nonpayable"),
            FunctionCandidate("0x18160ddd", "totalSupply()", (), ("uint256",), Confidence.STANDARD, "ERC-20", "view"),
            FunctionCandidate("0x313ce567", "decimals()", (), ("uint8",), Confidence.STANDARD, "ERC-20 metadata", "view"),
            FunctionCandidate("0x95d89b41", "symbol()", (), ("string",), Confidence.STANDARD, "ERC-20 metadata", "view"),
            FunctionCandidate("0x06fdde03", "name()", (), ("string",), Confidence.STANDARD, "ERC-20 metadata", "view"),
            FunctionCandidate("0x6352211e", "ownerOf(uint256)", ("uint256",), ("address",), Confidence.STANDARD, "ERC-721", "view"),
            FunctionCandidate("0x01ffc9a7", "supportsInterface(bytes4)", ("bytes4",), ("bool",), Confidence.STANDARD, "ERC-165", "view"),
        )
        self._entries: dict[str, list[FunctionCandidate]] = {}
        for entry in entries:
            self._entries.setdefault(entry.selector, []).append(entry)

    def candidates(self, selector: str) -> list[FunctionCandidate]:
        return list(self._entries.get(selector.lower(), ()))

    def add_candidate(self, candidate: FunctionCandidate) -> None:
        current = self._entries.setdefault(candidate.selector.lower(), [])
        if candidate.signature not in {item.signature for item in current}:
            current.append(candidate)

    def all_candidates(self) -> list[FunctionCandidate]:
        return [candidate for candidates in self._entries.values() for candidate in candidates]
