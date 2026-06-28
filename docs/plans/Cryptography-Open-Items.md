# MillWorks.Cryptography — Open Items (decisions + code, not docs)

**Status:** Tracking. The *documentation* gaps from the surface review are closed (see the **Security
model & limits** section of the root `README.md` — nonce ceiling, key-commitment/streaming/password
non-goals, best-effort erasure, FIPS posture). The three items below need a **decision or code**, not
prose, and are parked here so they aren't lost between C0 and C1/C2.
**Created:** 2026-06-28.

---

## 1. Ed25519 vs. the "zero third-party crypto" invariant — **decide before C2**

**Problem.** The C2 plan lists `Ed25519` signing, but as of **.NET 10 the BCL still does not expose
Ed25519 or X25519** (it added PQC — ML-KEM / ML-DSA / SLH-DSA — but not the Edwards/Montgomery
curves). So shipping Ed25519 forces either a third-party crypto dependency or dropping the algorithm —
directly contradicting the library's headline "zero third-party crypto dependencies" claim.

**Options.**
- **A — RSA-PSS + ECDSA only (stay pure-BCL).** Both are in the BCL and FIPS-approved; drop Ed25519
  from C2. Cleanest fit with the invariant. *Recommended* unless a consumer specifically requires EdDSA.
- **B — Add Ed25519 via a dependency** (NSec/libsodium native, or BouncyCastle managed), isolated in a
  separate package (e.g. `MillWorks.Cryptography.Ed25519`) so the core stays dependency-free and the
  invariant is only relaxed for consumers who opt in.
- **C — Defer Ed25519** to a later phase and ship C2 with RSA-PSS/ECDSA, revisiting if a real need
  (e.g. JWKS interop with an EdDSA-only peer) appears.

**Action:** pick A/B/C before C2 work starts; update the C2 subplan and the README's dependency claim
to match. Watch for BCL EdDSA support in a future .NET release, which would collapse this to a no-op.

## 2. Project Wycheproof test vectors — **test hardening, do any time**

**What.** Add Google **Project Wycheproof** vectors on top of the existing NIST/FIPS/RFC KATs. Wycheproof
targets the edge cases plain KATs miss (truncated/oversized tags, special-case points, biased nonces,
boundary lengths) and is the next rung of "trust this instead of your own copy."

**Scope:** AES-GCM and HMAC vectors now; ECDSA/RSA-PSS vectors land with C2 signing. Wire them as
data-driven NUnit `TestCaseSource` cases alongside the current KAT suite.

**Action:** no blocker, no dependency decision — schedule whenever. Highest value-per-effort of the three.

## 3. Streaming / chunked AEAD — **only if large-object encryption is in scope**

**Problem.** `AesGcmCipher` is one-shot: the whole plaintext is buffered in memory and no plaintext is
released until the tag verifies. Fine for fields/tokens; a problem if the `FileSystem` provider (or any
consumer) encrypts large blobs.

**Decision gate:** does any planned consumer encrypt objects too large to hold in memory comfortably?
- **No →** nothing to build. The README non-goal already documents the limit; leave it.
- **Yes →** design a chunked framing (STREAM-style: per-chunk nonce derived from a base + counter, final
  chunk flagged) as a **separate** primitive/frame version — do **not** overload the single-frame
  `AeadFormat`. Reuse the `version` byte to distinguish the streaming frame.

**Action:** confirm the FileSystem provider's payload sizes during C1 design; only then decide to build.

---

### Priority if picking up one at a time
1. **#1 (Ed25519 decision)** — unblocks C2 and protects the dependency claim.
2. **#2 (Wycheproof)** — cheap, strengthens the C0 foundation everyone builds on.
3. **#3 (streaming)** — gated on a real C1 requirement; may never be needed.
