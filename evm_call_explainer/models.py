from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    STANDARD = "standard"
    LIKELY = "likely"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Evidence:
    kind: str
    detail: str


@dataclass
class ContractInfo:
    address: str
    code_present: bool | None = None
    implementation: str | None = None
    proxy_kind: str | None = None
    name: str | None = None
    symbol: str | None = None
    decimals: int | None = None
    abi_source: str | None = None
    verification_match: str | None = None

    @property
    def label(self) -> str | None:
        return self.symbol or self.name


@dataclass
class DecodedCall:
    target: str
    raw_data: str
    selector: str
    signature: str | None = None
    state_mutability: str = "unknown"
    arguments: list[Any] = field(default_factory=list)
    argument_types: list[str] = field(default_factory=list)
    arguments_decoded: bool = False
    output_parameters: list[dict[str, Any]] = field(default_factory=list)
    error_definitions: list[dict[str, Any]] = field(default_factory=list)
    allow_failure: bool | None = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: list[Evidence] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    children: list["DecodedCall"] = field(default_factory=list)
    return_data: str | None = None
    return_value: Any = None
    return_decoded: bool = False
    revert_reason: str | None = None
    success: bool | None = None


@dataclass
class CallReport:
    to: str
    data: str
    block_tag: str
    root: DecodedCall
    chain_id: int | None = None
    evidence_sources: list[str] = field(default_factory=lambda: ["local ABI analysis"])
    contracts: dict[str, ContractInfo] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
