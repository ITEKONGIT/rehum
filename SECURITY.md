# Security Policy

## Reporting a vulnerability

Please use GitHub's private security-advisory feature for the repository. Do not disclose an unpatched vulnerability in a public issue.

Include the affected version, a minimal reproduction, expected impact, and any suggested mitigation. Never include private keys, seed phrases, authenticated RPC URLs, or real user data.

## Scope and trust model

Rehum parses untrusted calldata and may contact user-selected RPC and Sourcify endpoints. Reports are analytical evidence, not transaction approval or financial advice. `eth_call` is read-only, but a transaction made from the same calldata may change state, behave differently at another block, or interact with a different deployed contract on another chain.

The project intentionally performs no signing and stores no wallet credentials.
