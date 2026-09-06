# Implementation Analysis

## Current baseline

The current release is a functional, dependency-free MVP rather than a universal ABI decoder.

| Capability | Status | Notes |
|---|---|---|
| `to` + `data` interface | Implemented | These are the only required per-call inputs. |
| JSON-RPC wrapper generation | Implemented | Internal RPC client generates IDs and `eth_call` envelopes. |
| Strict address/calldata validation | Implemented | Rejects malformed hex and non-20-byte targets. |
| Function selector recognition | Implemented | Auditable local registry with confidence labels. |
| Multicall3 `aggregate3` | Implemented | Recursively decodes targets, failure flags, and nested calldata. |
| Common ERC methods | Implemented | Static arguments for common ERC-20/721/165 methods. |
| Plain-English rendering | Implemented | Separates simulation semantics from function intent. |
| Structured JSON rendering | Implemented | Preserves evidence and raw values. |
| RPC chain/code evidence | Implemented | Optional, based on configured RPC. |
| Proxy resolution | Implemented | EIP-1167, EIP-1967 implementation, and beacon slots. |
| Token metadata | Implemented | Best-effort `name`, `symbol`, and `decimals` probes. |
| Verified ABI evidence | Implemented | Sourcify API v2, scoped to chain and resolved implementation. |
| Return decoding | Implemented | Verified ABI outputs, Multicall success flags, and supported nested values are decoded. |
| Generic dynamic ABI decoding | Implemented | Strings, bytes, fixed/dynamic arrays, and nested tuples have a bounded recursive decoder. |
| Standard revert decoding | Implemented | Solidity `Error(string)` and `Panic(uint256)` payloads are explained. |
| Custom error decoding | Implemented | Verified ABI error definitions are matched and their arguments decoded. |
| Trace interpretation | Not implemented | `debug_traceCall` varies between RPC providers and requires adapters. |
| Explorer ABI providers | Not implemented | Sourcify is the current authoritative ABI provider. |
| Selector database discovery | Implemented | Unknown selectors are fetched from Sourcify 4byte, structurally filtered, and never promoted beyond likely/ambiguous. |

## Key design decisions

### Python core with shell launchers

Bash is retained as an invocation surface, not the decoding engine. Python supplies real data models, bounded binary parsing, reusable providers, unit testing, and consistent behavior on Windows and Unix-like systems.

### Static-first operation

The decoder always produces the strongest offline result before attempting network enrichment. RPC or provider failure cannot erase a valid structural decode.

### Evidence before language

The English renderer consumes an evidence-bearing intermediate representation. It does not independently guess selectors or addresses, preventing prose from becoming more certain than the decoder.

### Honest collision handling

Selector matches are candidates until target-specific evidence confirms them. Behavioral simulation may strengthen an interpretation but cannot prove a missing source-level function name.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Malicious offsets or huge batches | Memory/CPU exhaustion or parser errors | Size, depth, count, alignment, and bounds checks. |
| Wrong network | Incorrect labels and ABI | Network comes from configured RPC and is printed in output. |
| Proxy ABI applied to wrong code | Incorrect confirmation | Resolve implementation first; scope ABI by chain/address. |
| Selector collision | Misleading function name | Alternatives and confidence retained; verified ABI required for confirmation. |
| `eth_call` mistaken for transaction safety | User may submit dangerous calldata | Explain simulated function intent separately from non-persistence. |
| Stale `latest` state | Results change over time | Support explicit hex block tags and report the chosen block. |
| RPC/provider failure | Missing evidence | Preserve static decode and report a warning. |
| Oversized external response | Resource exhaustion | 16 MiB response cap and timeouts. |

## Recommended implementation sequence

### Phase 1 — Baseline reliability (current)

- Static recursive decoding
- Evidence/confidence model
- RPC and verified ABI enrichment
- Input and network boundaries
- Unit tests and preflight gate

### Phase 2 — General ABI engine

- Parse canonical ABI type trees — implemented
- Decode dynamic inputs and outputs — implemented
- Decode arrays and nested tuples generically — implemented
- Decode standard revert reasons — implemented
- Decode verified custom errors — implemented
- Add property/fuzz testing for offsets and malformed inputs

### Phase 3 — Protocol containers

- Safe multisend
- ERC-4337 and smart-account batches
- DEX universal routers
- Permit and typed authorization structures
- Trace adapters for major RPC clients

### Phase 4 — Service packaging

- Stable HTTP API accepting `{to,data}`
- Local ABI/provider cache
- Rate limits and request cancellation
- Chain profiles and health endpoints
- Signed release artifacts and CI gates

## Preflight policy

Local development may proceed with RPC warnings. A connected deployment must run:

```powershell
.\preflight.ps1 --require-rpc
```

Any `FAIL` blocks implementation or release. `WARN` is permitted only for explicitly optional capabilities.
