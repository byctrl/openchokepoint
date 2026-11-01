# Verifiable Evidence Records

Status: draft, schema version `0.3.0-draft`.

## Purpose

An EvidenceRecord pointer lets a holder prove that a specific record exists and
has not changed without publishing the record itself. The public repository
stores only a content digest, an issuer identifier, and a signature reference.
An authorised verifier can later compare the digest with the record they were
shown.

## Threat model

Assets: the integrity of the pointer and the confidentiality of the underlying
record. The pointer is public; the record is not.

Adversaries and failures considered:

- A forger who invents a digest and issuer without holding the record.
- A holder who alters the record after publishing the pointer.
- An attacker who replays a pointer from another record, issuer, or context.
- A compromised issuer key that signs false pointers.
- A verifier who is tricked into accepting embedded record content as a pointer.
- Accidental disclosure of record content through metadata or examples.

Mitigations: canonical claim serialisation, an explicit hash algorithm, a
digest over the exact record bytes, an issuer-controlled signing key, a
signature reference that resolves to a verifiable proof, and validator rules
that reject embedded content and malformed digests.

The repository cannot prove that a record is truthful. It can only bind an
issuer to a digest at a point in time.

## Claim format

A pointer is a JSON object. Required fields:

- `type`: `EvidenceRecordPointer`
- `version`: `0.3.0-draft`
- `issuer`: the issuer identifier, for example `did:example:supplier`
- `record_type`: the kind of record, for example `heat-treatment-certificate`
- `hash_algorithm`: one of the validator algorithms, for example `sha256`
- `digest`: the exact record digest as lowercase hexadecimal, with an optional
  matching algorithm prefix
- `signature_ref`: a URI or identifier for the detached proof

The signed bytes are the canonical JSON serialisation of the claim with sorted
keys and no insignificant whitespace. The `signature_ref` identifies the proof
document or key identifier; it must not contain the record. A signature object
may be stored beside the pointer for demonstrations, but production claims
should keep the proof in the issuer verifiable data registry or a detached
signature.

## Key management assumptions

- The issuer controls a signing key and publishes a verification method.
- The verifier obtains the issuer verification method through an authenticated
  channel or a trusted registry.
- Keys are rotated with overlap; old signature references remain resolvable for
  as long as the pointer is relied upon.
- The demo uses a generated HMAC key so it can run offline without external
  dependencies. Production deployments should use an asymmetric signature such
  as Ed25519 and a DID or X.509 verification method.

## Alignment

The claim maps naturally to W3C Verifiable Credentials Data Model 2.0:
`issuer`, `credentialSubject` (the digest and record type), and `proof`
(the signature reference). We keep the compact claim rather than a full VC so
that existing repository records can carry an optional pointer without turning
every record into a credential.

For provenance, the pointer is a PROV-O `Entity` whose digest identifies the
record; the issuer is the `Agent` responsible for the claim. We do not require a
full PROV-O graph in this slice.

## What this design does not protect against

- False statements by an issuer about a record that really exists.
- A record that is altered together with a newly signed pointer.
- Disclosure of the record through the verifier, the issuer, or the digest
  itself, because hashes can be correlatable.
- Loss or compromise of the issuer key.
- A verifier who accepts a pointer without checking the issuer proof.
