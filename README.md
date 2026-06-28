# MillWorks.Cryptography

Shared, key-agnostic cryptographic primitives for the MillWorks platform. Every consumer
(AuditCore, Reporting, Tokens, Identity, Git, …) converges on these instead of hand-rolling its
own — one AES-GCM frame, one hasher, one canonicalizer, with published known-answer test coverage.

> **Standalone, publishable library.** It becomes AuditCore's first upstream MillWorks dependency,
> so it carries no project-specific assumptions and zero third-party crypto dependencies — pure .NET
> BCL (`System.Security.Cryptography`, `System.Text.Json`).

- **Target framework:** `net10.0` (SDK pinned in `global.json`) · **Version:** 0.1.0 · **License:** MIT
- **Tests:** 132 passing — known-answer vectors (NIST AES-GCM, FIPS SHA-2, RFC 4231 HMAC, RFC 8785 JCS), not just round-trips

## What you get

| Area | Type | Notes |
| --- | --- | --- |
| **AEAD** | `IAeadCipher` / `AesGcmCipher` / `AeadFormat` | AES-256-GCM over one canonical, versioned frame. Key passed in per call. |
| **Hashing / HMAC** | `IHasher` / `Sha2Hasher` | SHA-256, SHA-512, HMAC-SHA-256. BCL one-shots (LOH-safe). |
| **Secure random** | `ISecureRandom` / `SecureRandom` | OS CSPRNG; the interface is injectable for deterministic tests. |
| **JSON canonicalization** | `IJsonCanonicalizer` / `Rfc8785JsonCanonicalizer` | RFC 8785 / JCS byte-identical output for cross-language signing & hashing. |
| **Encoding** | `CryptoEncoding` (static) | Lowercase hex, Base64, URL-safe Base64 (no padding). |
| **Constant-time compare** | `ConstantTime` (static) | Wraps `CryptographicOperations.FixedTimeEquals` for bytes / UTF-8 / Base64. |
| **Key management** | `KeyMaterial`, `FieldKeyDerivation`, `KeyScope`, `KeyDescriptor`, `IEncryptionKeyProvider`, `ISigningKeyProvider` | Zeroing key buffers, HKDF-SHA256 field derivation, tenant scoping, and the disjoint provider contracts. |
| **DI** | `AddMillWorksCryptography()` | Registers the four primitives as singletons (stateless, thread-safe). |

## Layout

| Project | Role | Dependencies |
| --- | --- | --- |
| `src/MillWorks.Cryptography.Abstractions` | Interfaces, DTOs, format constants, exceptions, and the pure statics (`CryptoEncoding`, `ConstantTime`, `FieldKeyDerivation`, `KeyMaterial`). | BCL only — **zero** packages. |
| `src/MillWorks.Cryptography` | Implementations (`AesGcmCipher`, `Sha2Hasher`, `SecureRandom`, `Rfc8785JsonCanonicalizer`) + the DI extension. | BCL + `Microsoft.Extensions.DependencyInjection.Abstractions` (registration only). |
| `src/MillWorks.Cryptography.FileSystem` | File-system / air-gapped key-provider backend. **Scaffold** — package shape is in place; providers land in C1. | Abstractions + DI.Abstractions. |
| `tests/MillWorks.Cryptography.Tests` | NUnit. Known-answer vectors, not just round-trips. | — |

The split is deliberate: a consumer can reference **`.Abstractions`** for the contracts (and the
statics) without pulling in the implementation, and substitute its own implementation if it needs to.

## Quick start

```csharp
using Microsoft.Extensions.DependencyInjection;

// Registers ISecureRandom, IAeadCipher, IHasher, IJsonCanonicalizer as singletons.
services.AddMillWorksCryptography();
```

### Authenticated encryption

```csharp
public sealed class SecretBox(IAeadCipher cipher)
{
    // key is exactly 32 bytes (AES-256). The primitive holds no key material —
    // you own the key's lifetime and where it comes from.
    public byte[] Seal(byte[] key, byte[] plaintext, byte[] aad)
        => cipher.Encrypt(key, plaintext, aad);    // -> [version][nonce][tag][ciphertext]

    public byte[] Open(byte[] key, byte[] framed, byte[] aad)
        => cipher.Decrypt(key, framed, aad);       // throws CryptographyException on any failure
}
```

A fresh random nonce is generated per `Encrypt`, so the same plaintext yields a different frame each
time. Associated data is authenticated but **not** stored in the frame — supply the identical value
to `Decrypt`. Any failure (wrong key size, malformed/truncated frame, unknown version, wrong AAD,
tampering) surfaces as a single `CryptographyException` that carries no plaintext or key material.

### Hashing, encoding, constant-time compare

```csharp
byte[] digest = hasher.Sha256("payload"u8);
string hex    = CryptoEncoding.ToHexLower(digest);   // lowercase, allocation-light
bool ok       = ConstantTime.Equals(macA, macB);     // constant-time for equal-length inputs
```

### Canonical JSON for signing / hashing

```csharp
// Two independent implementations produce byte-identical output for the same value,
// so a signature or hash over it verifies across languages and services.
byte[] canonical = canonicalizer.CanonicalizeToUtf8(jsonElement);
byte[] toSign    = hasher.Sha256(canonical);
```

## The canonical AEAD frame

All authenticated encryption uses one binary frame, AES-256-GCM:

```
[version:1][nonce:12][tag:16][ciphertext:N]
```

| Field | Size | |
| --- | --- | --- |
| `version` | 1 byte | `0x01`. Lets the frame evolve without breaking older readers. |
| `nonce` | 12 bytes | 96-bit GCM nonce, freshly random per encryption. |
| `tag` | 16 bytes | 128-bit GCM authentication tag. |
| `ciphertext` | N bytes | May be empty (GCM permits a zero-length plaintext). |

The key is supplied per call; the primitive holds no key material and no domain logic. This is
greenfield — there is no legacy-blob compatibility requirement, so the format was chosen on merit
and the version byte starts at 1.

## Key management

The abstractions and the pure key helpers ship now; the concrete provider backends follow in C1.

- **`KeyMaterial`** — owns a secret byte buffer and zeroes it on `Dispose`. Use it inside a `using`.
- **`FieldKeyDerivation`** — derives per-field 256-bit keys from a master key via **HKDF-SHA256**, with
  domain-separated, length-prefixed inputs so distinct `(field, version)` tuples can never collide.
- **`KeyScope`** — the tenant dimension of a lookup: `Global` or `ForTenant(id)`.
- **`IEncryptionKeyProvider` / `ISigningKeyProvider`** — deliberately disjoint contracts (a signing key
  never resolves through the encryption provider, and vice-versa), versioned for rotation, with
  retired keys still resolvable to decrypt/verify older data.

## Security model & limits

The primitives are thin, opinionated wrappers over the .NET BCL's own implementations; the security
posture follows from how you operate them. Read this before adopting platform-wide.

**AES-GCM nonce ceiling — rotate before 2³² messages.** Each `Encrypt` draws a fresh random 96-bit
nonce (the recommended GCM practice). Per **NIST SP 800-38D**, a single key must not exceed **2³²
encryptions** under random nonces before nonce-collision probability becomes non-negligible — and a
GCM nonce collision is catastrophic (reuse leaks the authentication key and enables forgery). Size
your C1 key-rotation cadence to stay well under that. The `version` byte exists so the frame can
later adopt a nonce-misuse-resistant or committing suite without breaking older readers.

**Bind context into the associated data.** AAD is authenticated but not stored in the frame. Pass the
binding context — key id, tenant, field name, record id — as AAD so a ciphertext can't be replayed
into a different context (confused-deputy / ciphertext-swap). The cipher enables this; applying the
convention is the caller's job (a C1 helper will fold `KeyDescriptor` / `KeyScope` in automatically).

**Explicit non-goals — don't reach for these here:**

- **Key commitment.** AES-GCM is not key-committing: a frame can verify under more than one key.
  Irrelevant for single-key field encryption, but it matters for password-derived or multi-recipient
  keys (partitioning-oracle attacks). Out of scope until a committing frame variant lands.
- **Streaming / large objects.** Encryption is one-shot: the whole plaintext is held in memory and no
  plaintext is released until the tag verifies. There is no chunked streaming AEAD. Encrypt large
  objects in your own chunked framing rather than as one multi-gigabyte frame.
- **Password hashing.** No PBKDF2 / Argon2 / bcrypt. `FieldKeyDerivation` is HKDF — key derivation
  from high-entropy keys, not password stretching. Credential hashing belongs to Identity.

**Best-effort secret erasure.** `KeyMaterial.Dispose` zeroes its buffer, but the managed GC may copy
or relocate the array beforehand, so zeroization is best-effort — not a guarantee against memory
disclosure. The library is not side-channel hardened beyond `ConstantTime` comparison.

**FIPS posture.** Every algorithm here — AES-256-GCM, SHA-256/512, HMAC-SHA-256, HKDF-SHA256 — is
FIPS-140 approved, and only the BCL implementations are called, so FIPS validation inherits from the
host platform (Windows CNG / Linux OpenSSL) with no additional surface to certify.

## Comparison & prior art

This is **not** a from-scratch crypto library and isn't trying to compete with one — it's an
opinionated, dependency-free *house standard* over the .NET BCL's own vetted primitives. The honest
landscape:

| Option | Relationship | When you'd reach for it instead |
| --- | --- | --- |
| **.NET BCL** `System.Security.Cryptography` | The substrate this wraps (`AesGcm`, `HKDF`, `HMACSHA256`, `RandomNumberGenerator`, `FixedTimeEquals`). | Always available — but it gives you no canonical AEAD frame, no RFC 8785 canonicalizer, no injectable RNG seam, and no single blessed way. This library adds exactly those. |
| **ASP.NET Core Data Protection** | Nearest mainstream peer: a versioned AEAD envelope over BCL primitives. | You want a **managed key ring** with automatic rotation/storage and purpose strings inside one app. MillWorks inverts this — the key is an explicit per-call argument, for cross-service interop, multi-tenant scoping, and a wire format you fully control. |
| **Inferno** (SecurityDriven.NET) | Closest philosophical sibling: pure-managed, misuse-resistant, single blessed construction. | You prefer Encrypt-then-MAC (AES-CTR + HMAC) over AES-GCM. Inferno has no JSON canonicalization, DI, or key-management story. |
| **Bouncy Castle** | Different problem — from-scratch breadth (PGP, CMS, TLS, broad post-quantum). | You need an algorithm or format the BCL lacks. Heavy where this is thin. |
| **libsodium bindings** (NSec, Geralt, Sodium.Core) | Different substrate — native libsodium via P/Invoke. | You specifically want libsodium primitives (XChaCha20-Poly1305, Ed25519/X25519, Argon2id) and accept a native binary dependency. |
| **`jsoncanonicalizer`** (NuGet) | The lone existing .NET RFC 8785 package — a frozen, single-purpose community repackage of the reference C# source. | You want *only* JCS and nothing else. .NET JCS support is otherwise thin, which is why bundling a tested canonicalizer here is a real differentiator. |

**What's distinctive:** zero third-party / zero native dependencies (pure managed BCL); a first-class,
vector-tested **RFC 8785 canonicalizer** (scarce in .NET); and an explicit per-call-key, versioned
AES-GCM interop frame (a niche most teams hand-roll). The value is *consolidation + interop + tested
vectors*, not new cryptography.

**What this is not / known gaps:** a deliberately small algorithm set (AES-256-GCM, SHA-2,
HMAC-SHA256, HKDF only) — **no** public-key crypto, **no** alternative AEADs, **no** post-quantum (use
the BCL's .NET 10 ML-KEM/ML-DSA directly), and **no** password hashing (pair with Argon2/bcrypt for
credential storage). Much of the surface is thin convenience over BCL calls; that's the point, but
it isn't a moat.

## Roadmap

**Phase C0 — foundation (complete):**

- [x] **AEAD cipher** — `IAeadCipher` / `AesGcmCipher` / `AeadFormat`, with GCM-spec AES-256-GCM vectors.
- [x] **Hashing + HMAC** — `IHasher` / `Sha2Hasher` (FIPS 180-4 / RFC 4231 vectors).
- [x] **Secure random** — `ISecureRandom` / `SecureRandom` (injectable for deterministic tests).
- [x] **Encoding + constant-time** — `CryptoEncoding`, `ConstantTime`.
- [x] **RFC 8785 JSON canonicalizer** — `IJsonCanonicalizer` / `Rfc8785JsonCanonicalizer` (published JCS
      vectors + golden hash). Rejects unsafe integers and duplicate keys rather than emitting ambiguous bytes.
- [x] `AddMillWorksCryptography` DI extension.

**Phase C1 — key management (in progress):** the tenant-capable key contract is in place —
`ISigningKeyProvider` / `IEncryptionKeyProvider` (disjoint), `KeyScope`, `KeyDescriptor`, `KeyMaterial`,
`KeyProviderException`, and the HKDF-SHA256 `FieldKeyDerivation` primitive. The file-system and Key Vault
backends are landing next.

**Phase C2 (later):** signing (HMAC / RSA-PSS / Ed25519) and JWKS. No consumer wiring lives in this repo yet.

## Build & test

```bash
dotnet build MillWorks.Cryptography.sln
dotnet test  MillWorks.Cryptography.sln       # 132 tests

./build-and-publish.sh                        # pack to ~/LocalNuGetPackages (-v to override version)
```

A crypto foundation is only trustworthy if it matches published vectors, so the suite leans on
known-answer tests rather than self-consistent round-trips: NIST/GCM-spec AES-256-GCM KATs (plus AAD
mismatch, tamper, truncation, and wrong-key-size rejection); FIPS 180-4 SHA-256/512 and RFC 4231
HMAC vectors; the RFC 8785 / JCS number-formatting cases the BCL gets wrong, with a golden SHA-256
over a fixed sample as the cross-language anchor.
