# Verifiable evidence pointer demo

This directory contains an offline, synthetic demonstration for Slice B.

Run `python examples/verifiable-evidence/verify.py` from the repository root.
The script generates a fictional record, a fictional issuer, and an ephemeral
HMAC key. It hashes the record, signs the canonical claim, validates the pointer
with `tools/validate.py`, and verifies the digest and signature end to end.

The demo uses HMAC only to avoid external dependencies. Production claims should
use an asymmetric signature such as Ed25519 with a published verification method.
