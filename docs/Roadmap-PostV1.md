# MillWorks.Cryptography — post-v1 backlog

Deferred features and scope decisions surfaced by review. Nothing here is dropped — each is an explicit,
tracked decision. Phases C0 and C1 are complete; C2 (signing + JWKS) is next.

## Decisions to lock before / during C2

### Ed25519 / X25519 dependency strategy (blocks C2 signing design)
.NET 10's BCL does **not** expose Ed25519 or X25519 (it added PQC — ML-KEM/ML-DSA/SLH-DSA — but not the
Edwards/Montgomery curves). RSA-PSS and ECDSA (P-256/P-384) **are** in the BCL and stay dependency-free.
**Recommendation:** keep the core `MillWorks.Cryptography` dependency-free with RSA-PSS + ECDSA, and ship
Ed25519/X25519 as an **optional `MillWorks.Cryptography.Ed25519` package** (e.g. NSec-backed) behind the
signing interface — a registerable override, consistent with the platform's "abstract swappable packages"
rule. This preserves the "zero third-party crypto in the core" selling point. Alternative: drop Ed25519.

## Higher-security enhancement (deferred by decision)

**KeyVault-native non-exportable RSA keys.** C2 ships RSA-PSS via the unified algorithm-aware
`ISigningKeyProvider` (RSA PKCS#8 stored wrapped on the file backend / as a Key Vault secret), which is
portable across both backends. A higher-security cloud option is to use Azure Key Vault's **Keys** API
(`KeyClient` + `CryptographyClient`) so the RSA private key is generated in the vault and never leaves it
(signing happens server-side). Deferred deliberately; add as a Key-Vault-only option once needed.

## Features (demand-gated)

| Item | Why | Recommendation |
| --- | --- | --- |
| **Streaming / chunked AEAD** | One-shot AEAD holds the whole plaintext in memory and releases none until the tag verifies — unsuitable for large blobs/files. | Add a STREAM-style chunked construction (à la Tink Streaming AEAD / age) **if** large-payload encryption enters scope. Until then, the one-shot limit is documented in `SECURITY.md`. |
| **Committing AEAD** | AES-GCM is not key-committing (partitioning-oracle risk for password-derived / multi-key use). | Reserve frame `version = 0x02` for a committing variant (e.g. AEAD + commitment tag). Build when password-derived or multi-recipient keys appear. |
| **AAD context-binding helper** | Best practice is to fold key id / tenant / field / record id into AAD to prevent confused-deputy ciphertext swaps. Convention is documented; a helper would make it the easy default. | Add an `AeadContext` helper (length-prefixed binding of `KeyScope`/`KeyDescriptor`/field) once consumer wiring starts. |
| **Project Wycheproof vectors** | KATs (NIST/FIPS/RFC) are covered; Wycheproof adds edge-case vectors (AEAD, HMAC, ECDSA) that catch subtler bugs — ideal for a "trust this" library. | Vendor the official Wycheproof JSON into the test project and iterate all cases for AES-GCM + HMAC (+ ECDSA in C2). |
| **Algorithm completeness** | No SHA-384, HMAC-SHA-384/512, or SHA-3; some standards (JWS HS384/HS512) want them. | Add to `IHasher` on demand — all BCL one-shots, cheap, dependency-free. |

## Explicit non-goals (decided)

- **Password hashing** (PBKDF2/Argon2/scrypt/bcrypt) — belongs to the application / identity layer.
- **Reimplementing primitives** — this library wraps the BCL's vetted implementations; it is not a
  from-scratch crypto library.
