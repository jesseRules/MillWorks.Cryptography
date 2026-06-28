# MillWorks.Cryptography — Project Wycheproof Subplan (file-by-file)

**Status:** Ready to author code once the vector files are present (see Step 0).
**Phase:** post-v1 hardening (see `docs/Roadmap-PostV1.md`). Test-only — **no production code changes.**
**Created:** 2026-06-28.

## Goal

Raise test assurance above the NIST/FIPS/RFC known-answer vectors already in place by adding **Project
Wycheproof** edge-case vectors — the next rung for a "trust this instead of your own copy" library.
Wycheproof catches the subtle failures KATs miss (malformed tags, truncated MACs, special-case RSA-PSS
signatures, boundary nonces). This is a pure test addition in `MillWorks.Cryptography.Tests`.

## Step 0 — obtain the vector files (the only blocker)

Wycheproof vectors are large JSON files that this environment cannot fetch. Vendor them deterministically:

- **Source:** `https://github.com/C2SP/wycheproof` (formerly `google/wycheproof`), directory `testvectors_v1/`
  (fall back to `testvectors/` for the legacy schema).
- **Pin a commit.** Record the exact commit SHA in this file and in a `vectors/SOURCE.md` so the suite is
  reproducible; do **not** track a moving `main`.
- **Files to vendor** (only the ones that map to our surface):
  - `aes_gcm_test.json`
  - `hmac_sha256_test.json`, `hmac_sha384_test.json`, `hmac_sha512_test.json`
  - `rsa_pss_2048_sha256_test.json` (and `rsa_pss_3072_sha256_test.json` if present)
- Commit them under `tests/MillWorks.Cryptography.Tests/Wycheproof/vectors/` and include them in the test
  `.csproj` as `<EmbeddedResource>` (avoids output-path fragility).

## Schema (Wycheproof v1)

```
{ "algorithm", "schema", "numberOfTests",
  "testGroups": [ { "type", "keySize", "ivSize", "tagSize", "keySize"/"sha"/...,
                    "tests": [ { "tcId", "comment", "flags": [...],
                                 "key"/"iv"/"aad"/"msg"/"ct"/"tag" (hex),
                                 "result": "valid" | "invalid" | "acceptable" } ] } ] }
```

`result` policy:
- **valid** → the operation must succeed and match (encrypt: ct+tag equal; decrypt/verify: accepts).
- **invalid** → the operation must **fail** (decrypt/verify rejects).
- **acceptable** → borderline (legacy/edge). Policy: our primitives are **opinionated**, so most
  `acceptable` cases fall outside our supported parameters and are **filtered out** (see below). For any
  `acceptable` case that *is* in-parameter, treat it as **valid** (must round-trip) and note it.

## Parameter filtering (load-bearing — our cipher is opinionated)

`AesGcmCipher` only supports **256-bit key / 96-bit nonce / 128-bit tag** over the canonical frame, so the
harness must select only the matching Wycheproof `testGroups` and **`log()` the count it skips** (no silent
caps). Concretely:
- AES-GCM: keep groups where `keySize == 256 && ivSize == 96 && tagSize == 128`; skip the rest (count
  reported in the test output / an explicit assertion on the skipped tally).
- HMAC: our `IHasher` returns the full digest; Wycheproof truncates per `tagSize` — compare the **first
  `tagSize/8` bytes** of our MAC against the vector tag.

## Files to create — `tests/MillWorks.Cryptography.Tests/Wycheproof/`

1. **`Schema/WycheproofFile.cs`** — `System.Text.Json` DTOs (`WycheproofFile`, `WycheproofGroup<TTest>`,
   the per-algorithm test records) + a loader that reads an embedded-resource JSON by name and deserializes.
   Hex fields decoded with `Convert.FromHexString`.
2. **`Schema/WycheproofLoader.cs`** — `IEnumerable<T> Load<T>(string resourceName)`; flattens groups→tests,
   carrying group-level parameters (keySize/ivSize/tagSize) onto each case; skips out-of-parameter groups and
   exposes the skipped count.
3. **`AesGcmWycheproofTests.cs`** — reconstruct the canonical frame from the vector `iv|tag|ct`; for **valid**
   cases also Encrypt with the vector iv injected via the existing `FixedSecureRandom` and assert the frame's
   ct+tag equal the vector; for **invalid** cases assert `Decrypt` throws `CryptographyException`. Asserts the
   skipped-group count is reported (not silently dropped).
4. **`HmacWycheproofTests.cs`** — one fixture per SHA size; `IHasher.HmacSha256/384/512(key, msg)`; compare the
   truncated MAC to the vector tag; valid→equal, invalid→not-equal.
5. **`RsaPssWycheproofTests.cs`** — verify against the raw BCL RSA-PSS that `RsaPssSigner` is built on:
   `RSA.ImportSubjectPublicKeyInfo(publicKey)` + `VerifyData(msg, sig, SHA256, RSASignaturePadding.Pss)`;
   valid→true, invalid→false. (Exercises the verification semantics our signer relies on; the provider seam is
   already covered by `RsaPssSignerTests`.)
6. **`vectors/*.json`** + **`vectors/SOURCE.md`** — vendored files + pinned commit.

## Test plan / Done when

- [ ] Vector files vendored, pinned to a recorded Wycheproof commit, embedded in the test project.
- [ ] AES-GCM (256/96/128 subset) — all in-parameter `valid` round-trip; all `invalid` rejected; the
      skipped-group count is asserted/reported, not hidden.
- [ ] HMAC-SHA-256/384/512 — `valid` match (truncated to the group tag size); `invalid` mismatch.
- [ ] RSA-PSS-SHA256 — `valid` verify true; `invalid` verify false.
- [ ] Zero production-code changes; the whole suite stays green and warning-free.

## Non-goals
No new primitives; no parameters our cipher doesn't already support (we don't loosen the frame to chase
Wycheproof coverage — out-of-parameter groups are reported as skipped, not enabled). ECDSA/Ed25519 vectors
only once those signers exist.

## Build discipline
NUnit; one build at a time; embedded-resource JSON so tests are deterministic and offline. The vendored
vectors are third-party **test data**, not a runtime dependency — the zero-third-party-crypto invariant is
unaffected.
