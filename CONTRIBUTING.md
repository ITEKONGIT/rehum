# Contributing to Rehum

Thanks for helping Rehum translate EVM calls more accurately.

## Development setup

Rehum requires Python 3.11 or newer and has no third-party runtime dependencies.

```text
cd rehum
python -m pip install -e .
python -m unittest discover -s tests -v
```

Run the local preflight before submitting a change:

```text
python -m evm_call_explainer.preflight
```

Network warnings are expected when no RPC is configured. Do not put authenticated RPC URLs, API keys, private keys, or wallet seed material in tests, issues, commits, or `config.example.json`.

## Pull requests

- Keep decoding bounded: validate offsets, lengths, counts, and recursion depth before allocating or iterating.
- Preserve raw calldata and uncertainty when evidence is incomplete.
- Do not promote selector-database candidates to `CONFIRMED` without target-specific evidence.
- Add focused tests for valid calldata and malformed boundary cases.
- Keep runtime code within Python's standard library unless a dependency has a clear security and maintenance justification.
- Update `README.md` and `IMPLEMENTATION_ANALYSIS.md` when user-facing behavior or capability status changes.

Pull requests should pass the cross-platform GitHub Actions workflow.
