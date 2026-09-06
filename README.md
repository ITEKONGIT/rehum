# Rehum

Rehum is a small, dependency-free EVM call reader. Give it only a contract address (`to`) and calldata (`data`); it decodes the request, actively gathers available chain evidence, and explains the call in plain English.

The name comes from Rehum in Ezra 4:8, associated with recording, interpreting, and transmitting official correspondence. This tool plays a similar translator role for encoded EVM dispatches.

## Does the PowerShell file work everywhere?

Not by itself. A `.ps1` file requires Windows PowerShell or PowerShell 7 (`pwsh`). PowerShell 7 can run on Windows, macOS, and Linux, but it must be installed there.

The portable core is `rehum.py`. The `.ps1`, `.cmd`, and `.sh` files are convenience launchers:

| Environment | Command |
|---|---|
| Any OS with Python 3 | `python rehum.py <TO> <DATA>` |
| Windows PowerShell | `.\rehum.ps1 <TO> <DATA>` |
| PowerShell 7 on any OS | `pwsh -File ./rehum.ps1 <TO> <DATA>` |
| Windows Command Prompt | `rehum.cmd <TO> <DATA>` |
| macOS or Linux shell | `bash rehum.sh <TO> <DATA>` |

Python 3.11 or newer is required. Rehum has no third-party Python dependencies.

To install the `rehum` and `rehum-preflight` commands from a cloned repository:

```text
python -m pip install .
rehum --help
```

## Quick start

From this directory, run:

```powershell
python rehum.py `
  0x471ece3750da237f93b8e339c536989b8978a438 `
  0x70a08231000000000000000000000000f13918dce6f2ae689548478cb83e4cad836adb7a
```

That example reads as `balanceOf(0xf13918dce6f2ae689548478cb83e4cad836adb7a)` on the target contract. Add `--offline` if you want local decoding without any network requests.

## Parameters

Only the first two are required:

| Parameter | Required | Meaning |
|---|---:|---|
| `to` | Yes | The `0x`-prefixed, 20-byte contract address receiving the call. |
| `data` | Yes | The `0x`-prefixed calldata: a 4-byte function selector followed by ABI-encoded arguments. |
| `--rpc-url URL` | No | Use this Ethereum-compatible JSON-RPC endpoint for chain evidence and simulation. |
| `--block TAG` | No | Read at `latest`, `safe`, `finalized`, `pending`, `earliest`, or a hex block number. |
| `--json` | No | Emit a structured JSON report instead of English. |
| `--offline` | No | Disable signature, ABI, metadata, and RPC requests. |
| `--no-execute` | No | Gather chain evidence but do not run `eth_call`. |
| `--execute` | No | Request `eth_call`; an RPC URL must also be configured. |
| `--config FILE` | No | Load a different JSON configuration file. |

See all options with `python rehum.py --help`.

## One-time RPC setup

Calldata does not contain a chain ID or RPC URL, so Rehum cannot safely infer the network from `to` and `data` alone. Copy the public template to the ignored local configuration file:

```powershell
Copy-Item config.example.json config.json
```

On macOS or Linux, use `cp config.example.json config.json`. Then put the correct endpoint in `config.json`:

```json
{
  "rpc_url": "https://your-chain-rpc.example",
  "block_tag": "latest",
  "execute": true,
  "sourcify": true,
  "signature_lookup": true,
  "max_calls": 4096,
  "max_payload_bytes": 4194304
}
```

Alternatively, pass `--rpc-url URL` or set `REHUM_RPC_URL`. The older `EVM_EXPLAINER_RPC_URL` name remains supported for compatibility.

Keep a private or authenticated RPC URL out of source control.

## How it establishes meaning

Rehum builds one report from several layers of evidence:

1. It validates the address, calldata length, ABI offsets, nesting, and batch bounds.
2. It matches known standard selectors and recursively opens supported containers such as Multicall3 `aggregate3`.
3. For an unknown selector, it fetches signature candidates from Sourcify's 4byte service and rejects candidates that cannot decode the supplied arguments.
4. With an RPC, it detects the chain, checks deployed bytecode, resolves common proxies, and probes token metadata.
5. It looks for an ABI verified for that exact chain and address through Sourcify.
6. It optionally executes the read-only `eth_call` and decodes returned values or revert data.
7. It renders the purpose, nested operations, contracts, result, evidence, warnings, and confidence together.

Active requests are read-only. Rehum has no private key and cannot broadcast a transaction. An `eth_call` simulation also does not prove that submitting the same calldata later is safe or will return the same result.

## Confidence labels

- `CONFIRMED`: a target-specific verified ABI or canonical deployment establishes the interpretation.
- `STANDARD`: the selector and structure match an established interface standard.
- `LIKELY`: one structurally valid signature candidate was found.
- `AMBIGUOUS`: multiple candidates fit the same selector and payload.
- `UNKNOWN`: no compatible interpretation was found.

A 4-byte selector is not globally unique. Rehum therefore reports collisions and evidence instead of presenting a database guess as certainty.

## What it currently understands

- Multicall3 `aggregate3`, recursively including `allowFailure`
- Common ERC-20, ERC-721, and ERC-165 functions
- Dynamic strings and bytes, arrays, nested tuples, and tuple arrays
- EIP-1167 and EIP-1967 proxy implementations
- Verified ABI inputs, outputs, and custom errors
- Solidity `Error(string)` and `Panic(uint256)` reverts
- Token metadata and formatted token balances when the chain exposes them

Some protocol-specific bytecode programs, routers, compressed payloads, and RPC trace formats need dedicated decoder modules. Rehum will preserve those bytes and label the interpretation incomplete rather than inventing a meaning.

## Preflight and tests

```powershell
.\preflight.ps1 --require-rpc
python -m unittest discover -s tests -v
```

Use `--require-rpc` for a connected deployment. Local/offline development may run preflight without it.

Architecture details are in [DESIGN.md](DESIGN.md), and the implementation status is in [IMPLEMENTATION_ANALYSIS.md](IMPLEMENTATION_ANALYSIS.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes and [SECURITY.md](SECURITY.md) for private vulnerability reporting guidance.
