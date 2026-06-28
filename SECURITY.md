# Security policy

`MillWorks.Cryptography` is a shared house-standard over the .NET BCL's own vetted primitives — **not**
a from-scratch cryptographic implementation. It exists so consumers stop hand-rolling AEAD frames,
canonicalization, comparisons, and key plumbing. This document states what it does and does not
defend against, so adopters can reason about it honestly.

## Algorithms & FIPS posture

| Concern | Algorithm | Source |
| --- | --- | --- |
| Authenticated encryption | AES-256-GCM | `System.Security.Cryptography.AesGcm` |
| Hashing | SHA-256, SHA-512 | `SHA256`/`SHA512` |
| MAC | HMAC-SHA-256 | `HMACSHA256` |
| Key derivation | HKDF-SHA-256 | `HKDF` |
| Canonical JSON | RFC 8785 (JCS) | implemented over `Utf8`/`System.Text.Json` parsing |

Every algorithm above is FIPS-approved, and every implementation is the .NET BCL's — this library
calls them, it does not reimplement them. **FIPS 140 posture therefore inherits from the underlying
platform/OS crypto provider**; running on a FIPS-enabled host yields FIPS-validated primitives with no
change to this library.

## What it defends against

- **Tamper / forgery** of ciphertext, via AES-GCM authentication (any change fails decryption).
- **Serialization drift** breaking signatures, via deterministic RFC 8785 canonicalization (byte-identical
  output across implementations).
- **Timing leaks** in secret/MAC comparison, via `ConstantTime` over `CryptographicOperations.FixedTimeEquals`.
- **Silent value corruption** before signing — the canonicalizer rejects integers beyond the IEEE-754
  safe range and duplicate object keys rather than emitting ambiguous bytes.
- **Key misuse** — signing and encryption key providers are disjoint; key material is wrapped at rest
  (file backend) or stored in Key Vault; resolution is fail-closed; tenants are isolated by scope.

## What it does NOT defend against (scope boundaries)

- **AES-GCM random-nonce usage limit.** A fresh random 96-bit nonce is drawn per message; the cipher
  holds no counter. Per **NIST SP 800-38D**, rotate a key well before **~2³² encryptions** under it,
  beyond which random-nonce collision probability is no longer negligible. Tie key rotation (C1) to this
  bound for any high-volume key.
- **Key commitment.** AES-GCM is not key-committing: a ciphertext can verify under more than one key.
  This is irrelevant for single-key field encryption but matters for password-derived or multi-recipient
  keys. Committing AEAD is out of scope for v1 (the frame version byte is reserved to evolve into it).
- **Large / streaming payloads.** AEAD is one-shot: the whole plaintext is held in memory and no
  plaintext is released until the tag verifies. There is no chunked/STREAM framing — do not use it to
  encrypt very large blobs. (See `docs/Roadmap-PostV1.md`.)
- **Password hashing.** No PBKDF2/Argon2/scrypt/bcrypt. Credential hashing belongs to the application /
  identity layer, not this library.
- **Asymmetric encryption / key agreement** (e.g. X25519). Not in v1. Signing (HMAC/RSA-PSS/…) arrives in
  phase C2.
- **Side channels beyond constant-time compare.** This is not a side-channel-hardened or memory-locked
  implementation; it relies on the BCL's primitives and the host.
- **Guaranteed memory erasure.** `KeyMaterial.Dispose` zeroes its buffer, but the managed GC may have
  relocated (copied) the bytes beforehand, so zeroization is **best-effort**, not a guarantee.

## Recommended usage conventions

- **Bind associated data (AAD) to context.** When using `IAeadCipher`, fold key id, tenant, field name,
  and/or record id into the AAD so a ciphertext cannot be replayed in a different context
  (confused-deputy). Keep the binding stable and supply the identical AAD on decrypt.
- **Keep `KeyMaterial` lifetimes short.** Use it inside a `using` and never copy the bytes out except into
  another zeroing owner.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainer rather than via a public issue.
_Contact: `<security-contact-to-be-filled-in>`._ Please include a description, affected version, and a
reproduction. We aim to acknowledge within a few business days.
