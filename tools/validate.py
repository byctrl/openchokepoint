#!/usr/bin/env python3
"""Validation helpers for OpenChokepoint documents.

This module intentionally keeps validation dependency-light: PyYAML is used when
available, and the EvidenceRecord pointer rules are implemented here rather than
in a generated validator so older traces remain accepted.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


KNOWN_HASH_ALGORITHMS = {
    "sha256": 64,
    "sha-256": 64,
    "sha384": 96,
    "sha-384": 96,
    "sha512": 128,
    "sha-512": 128,
    "sha3-256": 64,
    "sha3_256": 64,
    "sha3-384": 96,
    "sha3_384": 96,
    "sha3-512": 128,
    "sha3_512": 128,
    "blake2b-256": 64,
    "blake2b_256": 64,
    "blake2s-256": 64,
    "blake2s_256": 64,
}

DIGEST_RE = re.compile(r"^(?:(?P<algorithm>[A-Za-z0-9_.-]+):)?(?P<digest>[0-9a-fA-F]+)$")

CONTENT_KEYS = {
    "content",
    "record_content",
    "recordcontent",
    "evidence_content",
    "evidencecontent",
    "embedded_content",
    "embeddedcontent",
    "payload",
    "body",
    "raw",
    "raw_content",
    "rawcontent",
    "bytes",
}

ALGORITHM_KEYS = (
    "hash_algorithm",
    "hashAlgorithm",
    "hash-algorithm",
    "algorithm",
    "digest_algorithm",
    "digestAlgorithm",
)

DIGEST_KEYS = (
    "digest",
    "hash",
    "hash_value",
    "hashValue",
    "digest_value",
    "digestValue",
    "content_hash",
    "contentHash",
)

ISSUER_KEYS = (
    "issuer",
    "issuer_id",
    "issuerId",
    "issuer_identifier",
    "issuerIdentifier",
)

SIGNATURE_KEYS = (
    "signature",
    "signature_ref",
    "signatureRef",
    "signature_reference",
    "signatureReference",
)


def load(path: str | Path) -> Any:
    """Load a YAML or JSON document from *path*."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    if yaml is None:
        raise RuntimeError("PyYAML is required to load YAML documents")
    return yaml.safe_load(text)


def load_yaml(path: str | Path) -> Any:
    return load(path)


def _first(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _looks_like_evidence_record(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    type_value = value.get("type") or value.get("record_type") or value.get("kind") or ""
    type_text = str(type_value).replace(" ", "").replace("-", "").replace("_", "").lower()
    return "evidencerecord" in type_text


def iter_evidence_records(value: Any) -> Iterable[dict[str, Any]]:
    """Yield mappings that look like EvidenceRecord pointers."""
    if isinstance(value, dict):
        if _looks_like_evidence_record(value):
            yield value
            return
        for key, child in value.items():
            key_text = str(key).replace("-", "_").lower()
            if key_text in {"evidence_record", "evidence_records", "evidencerecord", "evidencerecords"}:
                if isinstance(child, list):
                    for item in child:
                        if isinstance(item, dict):
                            yield item
                elif isinstance(child, dict):
                    yield child
            else:
                yield from iter_evidence_records(child)
    elif isinstance(value, list):
        for item in value:
            yield from iter_evidence_records(item)


def _normalise_algorithm(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip().lower()


def _check_digest(record: dict[str, Any], errors: list[str]) -> None:
    algorithm_value = _first(record, ALGORITHM_KEYS)
    digest_value = _first(record, DIGEST_KEYS)
    if digest_value is None:
        return
    if not isinstance(digest_value, str):
        errors.append("EvidenceRecord digest must be a string")
        return

    match = DIGEST_RE.match(digest_value.strip())
    if not match:
        errors.append("EvidenceRecord digest is malformed")
        return

    prefix = _normalise_algorithm(match.group("algorithm"))
    supplied = _normalise_algorithm(algorithm_value)
    algorithm = supplied or prefix

    if algorithm is not None and algorithm not in KNOWN_HASH_ALGORITHMS:
        errors.append(f"EvidenceRecord uses unknown hash algorithm: {algorithm}")
        return
    if prefix is not None and prefix not in KNOWN_HASH_ALGORITHMS:
        errors.append(f"EvidenceRecord uses unknown hash algorithm: {prefix}")
        return
    if prefix is not None and supplied is not None and prefix != supplied:
        errors.append("EvidenceRecord digest prefix does not match hash algorithm")
        return

    digest_hex = match.group("digest")
    if algorithm is None:
        # Legacy bare digests are accepted only when their length identifies a
        # standard algorithm. New records should include hash_algorithm.
        lengths = {length for length in KNOWN_HASH_ALGORITHMS.values()}
        if len(digest_hex) not in lengths:
            errors.append("EvidenceRecord digest is malformed")
        return

    expected = KNOWN_HASH_ALGORITHMS[algorithm]
    if len(digest_hex) != expected:
        errors.append(f"EvidenceRecord digest length does not match {algorithm}")


def validate_evidence_record(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    for key in record:
        if str(key).strip().lower() in CONTENT_KEYS:
            errors.append(f"EvidenceRecord must not embed record content ({key})")

    _check_digest(record, errors)

    issuer = _first(record, ISSUER_KEYS)
    if issuer is not None and not isinstance(issuer, str):
        errors.append("EvidenceRecord issuer identifier must be a string")

    signature = _first(record, SIGNATURE_KEYS)
    if signature is not None and not isinstance(signature, (str, dict)):
        errors.append("EvidenceRecord signature reference must be a string or object")

    return errors


def validate_document(document: Any, ontology: Any = None) -> list[str]:
    """Return a list of validation error messages (empty means valid)."""
    if isinstance(document, (str, Path)):
        try:
            document = load(document)
        except Exception as exc:
            return [f"Unable to load document: {exc}"]

    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Document root must be a mapping"]

    for record in iter_evidence_records(document):
        errors.extend(validate_evidence_record(record))

    return errors


def validate_data(document: Any, ontology: Any = None) -> list[str]:
    return validate_document(document, ontology)


def validate(document: Any, ontology: Any = None) -> list[str]:
    return validate_document(document, ontology)


def validate_file(path: str | Path, ontology: Any = None) -> list[str]:
    return validate_document(path, ontology)


def is_valid(document: Any, ontology: Any = None) -> bool:
    return not validate_document(document, ontology)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: validate.py FILE [FILE ...]", file=sys.stderr)
        return 2

    failed = False
    for arg in args:
        errors = validate_file(arg)
        if errors:
            failed = True
            print(f"{arg}: invalid", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        else:
            print(f"{arg}: valid")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
