# Rehum

Rehum translates an EVM contract call into a plain-English overview. Supply only the destination contract (`to`) and calldata (`data`).

Named after Rehum in Ezra 4:8: a recorder and interpreter of official dispatches.

## Requirements

- Python 3.11+
- No third-party runtime packages
- An Ethereum-compatible RPC URL for live chain evidence

## Run

```text
python rehum.py <TO> <DATA>
```

Convenience launchers:

```text
PowerShell:  .\rehum.ps1 <TO> <DATA>
Windows CMD: rehum.cmd <TO> <DATA>
macOS/Linux: bash rehum.sh <TO> <DATA>
```

Example:

```text
python rehum.py 0x471ece3750da237f93b8e339c536989b8978a438 0x70a08231000000000000000000000000f13918dce6f2ae689548478cb83e4cad836adb7a --offline
```

This decodes as `balanceOf(0xf13918dce6f2ae689548478cb83e4cad836adb7a)`.

## Live evidence

Calldata does not identify its blockchain. Pass the correct RPC directly:

```text
python rehum.py <TO> <DATA> --rpc-url https://your-chain-rpc.example
```

For a reusable local setup, copy `config.example.json` to the ignored `config.json` and set `rpc_url`. You can also set `REHUM_RPC_URL`.

With an RPC, Rehum checks the chain, contract bytecode, common proxies, token metadata, verified Sourcify ABIs, and optionally executes the read-only `eth_call`. Without one, it still performs local selector, ABI, and Multicall3 decoding.

## Options

```text
--rpc-url URL   use a chain RPC
--block TAG     latest, safe, finalized, pending, earliest, or hex block
--json          output structured JSON
--offline       disable all network lookups
--no-execute    fetch evidence without executing eth_call
--execute       request eth_call execution
--config FILE   use another configuration file
```

Run `python rehum.py --help` for command help.

## Confidence

Results are labelled `CONFIRMED`, `STANDARD`, `LIKELY`, `AMBIGUOUS`, or `UNKNOWN`. Function selectors can collide, so signature-database matches are not treated as proof without target-specific evidence.

Rehum never signs or broadcasts transactions. A successful `eth_call` is a read-only simulation, not proof that submitting the calldata is safe.

## Install and test

```text
python -m pip install .
rehum --help
python -m unittest discover -s tests -v
rehum-preflight
```
