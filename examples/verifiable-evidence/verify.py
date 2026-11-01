#!/usr/bin/env python3
'''Offline synthetic demonstration of a verifiable EvidenceRecord pointer.'''
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.validate import validate_evidence_pointer


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def make_demo() -> tuple[bytes, bytes, dict]:
    record = b'''Synthetic heat-treatment certificate for example alloy.\nIssuer: Example Aerospace Supplier.\nBatch: DEMO-001.\n'''
    key = secrets.token_bytes(32)
    digest = hashlib.sha256(record).hexdigest()
    claim = {
        'type': 'EvidenceRecordPointer',
        'version': '0.3.0-draft',
        'issuer': 'did:example:acme-supplier',
        'record_type': 'heat-treatment-certificate',
        'hash_algorithm': 'sha256',
        'digest': digest,
        'signature_ref': 'urn:example:signature:demo-1',
    }
    signature = hmac.new(key, canonical_bytes(claim), hashlib.sha256).hexdigest()
    pointer = dict(claim)
    pointer['signature'] = {
        'type': 'demo-hmac-sha256',
        'key_id': 'urn:example:key:demo-1',
        'value': signature,
    }
    return record, key, pointer


def verify(pointer: dict, record: bytes, key: bytes) -> bool:
    validate_evidence_pointer(pointer, 'example.claim')
    if pointer['digest'] != hashlib.sha256(record).hexdigest():
        return False
    claim = {name: value for name, value in pointer.items() if name != 'signature'}
    expected = hmac.new(key, canonical_bytes(claim), hashlib.sha256).hexdigest()
    return hmac.compare_digest(pointer['signature']['value'], expected)


def main() -> int:
    record, key, pointer = make_demo()
    if not verify(pointer, record, key):
        print('FAIL: synthetic evidence pointer did not verify.', file=sys.stderr)
        return 1
    print(json.dumps(pointer, indent=2, sort_keys=True))
    print('OK: synthetic evidence pointer verified without embedding the record.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
