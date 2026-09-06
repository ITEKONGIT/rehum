from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .abi import AbiDecodingError, validate_block_tag
from .decoder import CalldataDecoder
from .render import EnglishRenderer, JsonRenderer
from .rpc import RpcClient, RpcEvidenceResolver
from .signature_lookup import SignatureEvidenceResolver


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        default = Path.cwd() / "config.json"
        path = default if default.exists() else None
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"config {path} must contain a JSON object")
        return value
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load config {path}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rehum",
        description="Translate EVM calldata into an evidence-backed plain-English overview.",
    )
    parser.add_argument("to", help="target contract address")
    parser.add_argument("data", help="0x-prefixed calldata")
    parser.add_argument("--config", type=Path, help="JSON configuration file")
    parser.add_argument("--rpc-url", help="RPC URL; otherwise config, REHUM_RPC_URL, or EVM_EXPLAINER_RPC_URL")
    parser.add_argument("--block", help="block tag or hex block number; defaults to latest")
    parser.add_argument("--execute", action="store_true", help="execute eth_call and decode supported results")
    parser.add_argument("--no-execute", action="store_true", help="do not execute eth_call even when RPC is configured")
    parser.add_argument("--offline", action="store_true", help="disable all network lookups")
    parser.add_argument("--json", action="store_true", help="emit structured JSON instead of English")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        block = validate_block_tag(args.block or str(config.get("block_tag", "latest")))
        max_calls = int(config.get("max_calls", 4_096))
        max_payload_bytes = int(config.get("max_payload_bytes", 4 * 1024 * 1024))
        if not 1 <= max_calls <= 100_000:
            raise ValueError("max_calls must be between 1 and 100000")
        if not 4 <= max_payload_bytes <= 64 * 1024 * 1024:
            raise ValueError("max_payload_bytes must be between 4 and 67108864")
        report = CalldataDecoder(
            max_calls=max_calls, max_payload_bytes=max_payload_bytes
        ).decode(args.to, args.data, block)
        signature_lookup = bool(config.get("signature_lookup", True))
        if signature_lookup and not args.offline:
            report.evidence_sources.append("Sourcify 4byte signatures")
            SignatureEvidenceResolver().enrich(report)
        rpc_url = None if args.offline else (
            args.rpc_url
            or os.environ.get("REHUM_RPC_URL")
            or os.environ.get("EVM_EXPLAINER_RPC_URL")
            or config.get("rpc_url")
        )
        if args.no_execute:
            execute = False
        elif args.execute:
            execute = True
        else:
            execute = bool(rpc_url and config.get("execute", True))
        if rpc_url:
            use_sourcify = bool(config.get("sourcify", True))
            report.evidence_sources.append("configured chain RPC")
            if use_sourcify:
                report.evidence_sources.append("Sourcify verified ABIs")
            RpcEvidenceResolver(RpcClient(rpc_url), use_sourcify=use_sourcify).enrich(
                report, execute=execute
            )
        elif args.execute:
            report.warnings.append("--execute was requested but no RPC URL is configured")
        renderer = JsonRenderer() if args.json else EnglishRenderer()
        print(renderer.render(report))
        return 0
    except (AbiDecodingError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
