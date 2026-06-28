# MillWorks.Cryptography — C0 Foundation Subplan (file-by-file)

**Status:** Ready to build. Implementation task for phase **C0** of `CryptographyConsolidation-Orchestration.md`.
**Created:** 2026-06-28.
**Home:** author here for now; **relocate to `MillWorks.Cryptography/docs/plans/` when the repo is created.**
**Constraint for this doc:** plan only — signature sketches are illustrative, not code to commit.

## Goal

Stand up the `MillWorks.Cryptography` foundation: the **Abstractions** surface + the **pure, key-agnostic primitives** that
every consumer (AuditCore, Reporting, Tokens, Identity, Git, …) will share — with exhaustive known-answer tests. No keys, no
signing, no consumers yet. This is the walking skeleton that proves repo → package → publish before the bigger surface lands.

## Layering & what C0 is / isn't

| In C0 | Deferred |
| --- | --- |
| `MillWorks.Cryptography.Abstractions` (interfaces, DTOs, format constants, exceptions) | key providers + KeyVault/file backends → **C1** |
| `MillWorks.Cryptography` (impl: AEAD cipher, hasher, secure random, RFC 8785 canonicalizer) | signing (HMAC/RSA-PSS/Ed25519) + JWKS → **C2** |
| Pure unit tests incl. **official test vectors** | any consumer wiring (AuditCore A1, Reporting R1, …) |
| `AddMillWorksCryptography` DI extension | the DataProtection-wrapper factory (`.DataProtection`) |

**Key-agnostic invariant:** every primitive takes key/parameters **in** (or, later, resolves via C1's provider). C0 holds
**no key material and no domain logic.** Tenant scoping is a C1 concern (key provider), not C0.

**Greenfield format freedom:** no production data anywhere ⇒ C0 **defines** the one canonical AEAD frame
(`[version:1][nonce:12][tag:16][ciphertext]`, AES-256-GCM) as *the* format. Consumers re-encrypt under it; there is **no
legacy-blob compatibility requirement.** Pick the best format on merit, version byte = 1.

## Package & repo layout

```
MillWorks.Cryptography/                      (new repo)
├── src/
│   ├── MillWorks.Cryptography.Abstractions/  (pure .NET — net10.0, no deps)
│   └── MillWorks.Cryptography/               (impl — net10.0; + DI.Abstractions for the registration extension)
├── tests/
│   └── MillWorks.Cryptography.Tests/         (NUnit — matches AuditCore/Ai test convention)
└── docs/plans/                               (move this file here)
```

`.csproj` shape (both src projects): `net10.0`, `ImplicitUsings`, `Nullable`, `LangVersion latest`,
`GenerateDocumentationFile`. **Standalone publishable quality** — this becomes AuditCore's first upstream MillWorks dep.
Dependencies: Abstractions = BCL only; impl = BCL (`System.Security.Cryptography`, `System.Text.Json`) +
`Microsoft.Extensions.DependencyInjection.Abstractions` (for `AddMillWorksCryptography` only). **No third-party crypto.**

## Files to create

### `MillWorks.Cryptography.Abstractions`

1. **`Hashing/IHasher.cs`** — raw byte hashing + HMAC (encoding is separate, §`CryptoEncoding`):
   ```csharp
   byte[] Sha256(ReadOnlySpan<byte> data);
   byte[] Sha512(ReadOnlySpan<byte> data);
   byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);
   ```
2. **`Aead/IAeadCipher.cs`** — AES-256-GCM over the canonical frame; key passed in:
   ```csharp
   byte[] Encrypt(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);
   byte[] Decrypt(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> framed, ReadOnlySpan<byte> associatedData = default);
   ```
3. **`Aead/AeadFormat.cs`** — frame constants (`Version = 1`, `NonceSize = 12`, `TagSize = 16`, `KeySize = 32`); the single
   source of truth for the layout the ×7 hand-rolled ciphers will converge on.
4. **`Random/ISecureRandom.cs`** — `void Fill(Span<byte>)`, `byte[] GetBytes(int n)` (interface so tests inject determinism).
5. **`Canonicalization/IJsonCanonicalizer.cs`** — RFC 8785/JCS **byte** primitive (versioned projection stays in consumers):
   ```csharp
   byte[] CanonicalizeToUtf8(JsonElement value);     // + a JsonNode overload
   ```
6. **`CryptoEncoding.cs`** (static) — `ToHexLower`, `ToBase64`, `ToBase64Url` (+ decoders). Pure; no interface (no reason to
   swap base64). Consolidates the scattered `Convert.ToHexString().ToLowerInvariant()` / `Base64UrlEncoder` call sites.
7. **`ConstantTime.cs`** (static) — `bool Equals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)`, `bool EqualsBase64(string?, string?)`;
   wraps `CryptographicOperations.FixedTimeEquals` with the length-mismatch dummy-compare guard. Consolidates Tokens
   `FixedTimeComparer` + Identity `SecureCompare`.
8. **`CryptographyException.cs`** — base for format/validation failures (e.g. wrong key size, truncated frame).

### `MillWorks.Cryptography` (impl)

9. **`Hashing/Sha2Hasher.cs : IHasher`** — `SHA256.HashData` / `SHA512.HashData` / `HMACSHA256.HashData`. Use
   `IncrementalHash` for large inputs (mirrors AuditCore `TamperDetectionService`'s LOH-safe pattern).
10. **`Aead/AesGcmCipher.cs : IAeadCipher`** — `new AesGcm(key, TagSize)`; random nonce via `ISecureRandom`; writes
    `[version][nonce][tag][ct]`; `CryptographicOperations.ZeroMemory` on transient plaintext. Validates key size + version
    byte; throws `CryptographyException` on a malformed/truncated frame. **Reconcile from** Tokens `AesTokenEncryptionService`
    (cleanest existing copy) — same frame already.
11. **`Random/SecureRandom.cs : ISecureRandom`** — `RandomNumberGenerator`. (A deterministic test double lives in the test
    project, **not** shipped.)
12. **`Canonicalization/Rfc8785JsonCanonicalizer.cs : IJsonCanonicalizer`** — `Utf8JsonWriter`, object keys sorted by UTF-16
    code unit (`StringComparer.Ordinal`), RFC 8785 §3.2.2.3 number serialization, no insignificant whitespace, null sections
    omitted. **Reconcile from** Reporting Plan 09 `EvidenceCanonicalizer` (the reference design). ⚠ The BCL `JsonSerializer`
    number format does **not** satisfy RFC 8785 — the writer must implement the number rule explicitly (this is the whole
    reason the primitive is shared, not `StableJsonOptions`).
13. **`Extensions/CryptographyServiceExtensions.cs`** — `AddMillWorksCryptography(this IServiceCollection)` registering
    `IHasher`, `IAeadCipher`, `ISecureRandom`, `IJsonCanonicalizer` (singletons — all stateless/thread-safe).

## Sequencing within C0 (walking skeleton first)

1. **AEAD cipher** (`IAeadCipher` + `AesGcmCipher` + `AeadFormat`) — the worst triplicate (×7); proves the repo→package loop.
2. **Hashing + HMAC** (`IHasher` + `Sha2Hasher`).
3. **Secure random** (`ISecureRandom` + `SecureRandom`).
4. **Encoding + constant-time** statics (`CryptoEncoding`, `ConstantTime`).
5. **RFC 8785 canonicalizer** (`IJsonCanonicalizer` + `Rfc8785JsonCanonicalizer`) — the highest-correctness-risk piece.
6. **DI extension** + package metadata + local-feed publish.

## Test plan — `MillWorks.Cryptography.Tests` (NUnit), **known-answer tests, not just round-trips**

A crypto foundation is only trustworthy if it matches published vectors.

- **`AesGcmCipherTests`** — encrypt→decrypt round-trip; **NIST CAVP AES-256-GCM KATs** (known key/nonce/pt/ct/tag); AAD
  mismatch fails decryption; truncated/oversized frame throws `CryptographyException`; wrong key size throws; tampered tag
  fails; nonce is unique across encryptions (statistical); `ZeroMemory` invoked (behavioral).
- **`Sha2HasherTests`** — **FIPS 180-4 SHA-256/512 vectors** + **RFC 4231 HMAC-SHA256 vectors**; empty-input vector; large
  input via `IncrementalHash` equals one-shot.
- **`Rfc8785JsonCanonicalizerTests`** — the **published RFC 8785 / JCS test suite** (the canonical pass/fail set), incl. the
  number-formatting cases the BCL serializer gets wrong (`1.0`→`1`, exponents, `-0`); key sort order; null-section omission;
  Unicode escaping; **golden SHA-256 over a fixed sample** (the cross-language verifiability anchor).
- **`CryptoEncodingTests`** — hex/base64/base64url round-trips + known vectors; base64url has no padding/`+`/`/`.
- **`ConstantTimeTests`** — equal/unequal; length-mismatch returns false without throwing; (timing is not asserted, but the
  dummy-compare branch is exercised).
- **`SecureRandomTests`** — length correctness; distinct outputs; the deterministic test double is wired only in tests.
- **`MeterCapture`-style fidelity:** none in C0 (no metrics yet); add when consumers wire in.

## Reconciliation map (what each primitive is lifted from)

| C0 primitive | Cleanest existing source to reconcile from |
| --- | --- |
| `AesGcmCipher` | Tokens `AesTokenEncryptionService` (same `[ver][nonce][tag][ct]` frame) — cross-check Identity `TokenCryptoService`, AuditCore `FieldEncryptionService` |
| `Sha2Hasher` (+HMAC, IncrementalHash) | AuditCore `TamperDetectionService` hashing helpers |
| `ConstantTime` | Tokens `FixedTimeComparer` + Identity `SecureCompare` |
| `SecureRandom` / encoding | Tokens `KeyGeneratorHelper` + the inline `RandomNumberGenerator` sites |
| `Rfc8785JsonCanonicalizer` | Reporting Plan 09 `EvidenceCanonicalizer` (RFC 8785 reference) |

## Non-goals (explicit C0 boundary)

No key providers / KeyVault / file backends (C1) · no signing / RSA-PSS / Ed25519 / JWKS (C2) · no tenant scoping (C1's
provider) · no DataProtection wrappers (`.DataProtection`, later) · **no consumers wired** (AuditCore A1 / Reporting R1 come
after C2) · no metrics.

## Done when

- [ ] `MillWorks.Cryptography.Abstractions` + `MillWorks.Cryptography` build clean (net10.0, 0 warnings) and publish to the local feed.
- [ ] All primitives pass **published known-answer vectors** (NIST AES-GCM, FIPS SHA, RFC 4231 HMAC, RFC 8785 JCS suite), not just round-trips.
- [ ] The canonicalizer produces a stable **golden SHA-256** over a fixed sample (the cross-language verifiability anchor).
- [ ] `AddMillWorksCryptography` registers all four interfaces; statics need no registration.
- [ ] Zero third-party crypto dependencies; Abstractions has zero deps.
- [ ] No keys, no signing, no consumers present (verified by the non-goals list).

## Build discipline
- One build at a time. New repo → you create/init it; I produce structure + plan, you handle git.
- NUnit (matches AuditCore/Ai). KATs are mandatory — a crypto lib without published vectors is not done.
- This is C0 only; C1 (key providers, tenant-capable) and C2 (signing + JWKS) are separate subplans.
