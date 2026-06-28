# MillWorks.Cryptography — DataProtection Factory Subplan (file-by-file)

**Status:** Ready to build the library piece; consumer migrations are a tracked follow-on sweep.
**Phase:** Track-tier net-new package (audit `PrimitivePromotionAudit.md` #4; Orchestration §6.6).
**Created:** 2026-06-28. **Home:** `MillWorks.Cryptography/docs/plans/`.

## Goal

Consolidate the **~9 thin ASP.NET DataProtection wrapper services** scattered across the platform into one
factory in a new `MillWorks.Cryptography.DataProtection` package, with **tenant-segmented purpose strings**.

**Hard rule (Orchestration §1):** *wrap, never reimplement.* ASP.NET Core Data Protection
(`IDataProtectionProvider`/`IDataProtector`/`IPersonalDataProtector`) is **framework crypto** — this package
standardizes the **wrapper pattern** (purpose construction, tenant segmentation, the `ENC:` marker,
protect/unprotect ergonomics) over the framework provider. It performs **no** AES/crypto of its own.

## Why this is part library, part consumer-sweep

The factory itself is small. The bulk is migrating the ~9 existing wrappers (each in a consumer repo) onto it —
that behaves like the A1/T2/I2 consumer sweeps, one PR per repo. This subplan covers **(1) the package** in
full and **(2) a migration matrix** for the consumers; the per-repo migrations are tracked, not done here.

## The ~9 wrappers being consolidated (from audit #4)

| Wrapper service | Repo |
| --- | --- |
| `SsoSecretProtectionService`, `LdapBindSecretProtectionService` | Identity |
| `CredentialEncryptionService` | Security |
| `ConnectionStringProtectionService` | (ApiOrchestration / shared) |
| `AiModelTokenProtectionService` | Ai |
| `DataProtectionCredentialProtectionService` | Accessible |
| (ClientEmail credential wrapper), (SqlBuilder credential wrapper) | ClientEmail, SqlBuilder |

Common shape: wrap `IDataProtectionProvider.CreateProtector(purpose)` → `Protect`/`Unprotect` with a purpose
string + an `ENC:` prefix marker. Variance to reconcile: sync vs async, `string` vs `byte[]`, and a
return-type split the audit flagged (`Task<IAsyncDisposable?>` nullable vs `Task<IDisposable>` throwing).

> **Out of scope here:** the Api `DataProtectionPersonalDataProtector` wraps `IPersonalDataProtector` — a
> *different* framework seam (GDPR personal-data). Decide separately whether it converges; default **leave it**
> (it's not a credential wrapper).

## Decisions to ratify (before building)

1. **Tenant isolation default (§6.6).** Per-tenant **purpose segmentation** (framework-supported: chain the
   tenant into the purpose) vs per-tenant **key material** (a DataProtection key-ring per tenant — heavier).
   **Recommend: purpose segmentation** — the framework path the audit endorses; per-tenant material is a
   threat-model upgrade, not the default.
2. **Unprotect failure contract.** Reconcile the nullable-vs-throwing split: `Unprotect` returns **null** for a
   value that is not protected or fails to unprotect (don't throw on tampered/foreign input); `Protect` always
   succeeds. (Recommend this; it matches the nullable variant and fails safe.)
3. **`ENC:` marker.** Keep one shared prefix constant so protected values are identifiable (and double-protect
   is detectable), or drop it. **Recommend keep** — matches all ~9 wrappers and enables `IsProtected`.
4. **Surface.** `string`-primary (base64 protected payload) + a `byte[]` overload. (Recommend both.)

## Package & layout

```
src/MillWorks.Cryptography.DataProtection/   (new package)
```
`.csproj`: `net10.0`, `IsPackable=true`; references **`Microsoft.AspNetCore.DataProtection.Abstractions`**
(framework) + `Microsoft.Extensions.DependencyInjection.Abstractions` (for the registration extension).
**Does NOT reference `MillWorks.Cryptography.Abstractions`** unless it needs `KeyScope` — if it does, reference
it; otherwise keep this package independent. The DataProtection interfaces live **here**, not in the core
`.Abstractions`, so the core stays BCL-only / zero-third-party.

## Files to create

1. **`ICredentialProtector.cs`** — `string Protect(string plaintext)`, `string? Unprotect(string protectedValue)`,
   `bool IsProtected(string? value)` (+ `byte[]` overloads). Per-instance; bound to a resolved purpose.
2. **`ICredentialProtectorFactory.cs`** — `ICredentialProtector Create(string purpose, KeyScope scope = default)`;
   tenant-segments the purpose for a non-global scope.
3. **`DataProtectionMarker.cs`** — the `ENC:` prefix constant + add/detect/strip helpers (one source of truth).
4. **`PurposeBuilder.cs`** — composes the framework purpose: `{purpose}` for Global, `{purpose}` chained with
   `tenant:{guidN}` for a tenant scope (use `IDataProtectionProvider.CreateProtector(purpose, subPurpose…)`,
   the framework-supported segmentation — no string concatenation footguns).
5. **`DataProtectionCredentialProtector.cs : ICredentialProtector`** — wraps one `IDataProtector`; `Protect` =
   marker + `protector.Protect`; `Unprotect` = strip-marker + `protector.Unprotect`, returning null on
   `CryptographicException`/missing marker.
6. **`CredentialProtectorFactory.cs : ICredentialProtectorFactory`** — wraps `IDataProtectionProvider`;
   `Create` resolves the purpose (via `PurposeBuilder`) and returns a `DataProtectionCredentialProtector`.
7. **`Extensions/DataProtectionServiceExtensions.cs`** — `AddMillWorksCredentialProtection(this IServiceCollection)`
   registering `ICredentialProtectorFactory` (singleton; resolves the app's `IDataProtectionProvider`). Requires
   the host to have configured Data Protection (`AddDataProtection()`).

## Tests — `MillWorks.Cryptography.DataProtection.Tests` (NUnit)

Use the framework's `EphemeralDataProtectionProvider` (in-memory, no key persistence) as the provider.

- `CredentialProtectorTests` — protect→unprotect round-trips; `IsProtected` true after protect; `Unprotect` of a
  non-marked / foreign value returns null (no throw); double-protect is detectable.
- `TenantPurposeIsolationTests` — a protector for tenant A **cannot** unprotect a value protected for tenant B or
  Global (different purpose ⇒ unprotect fails ⇒ null). The load-bearing isolation guarantee.
- `MarkerTests` — `ENC:` add/detect/strip; non-marked input.
- `ServiceExtensionsTests` — `AddMillWorksCredentialProtection` registers the factory; resolved factory works.
- **DO-NOT-REIMPLEMENT guard** — assert the package contains no `AesGcm`/`SymmetricAlgorithm` usage (it only
  delegates to `IDataProtector`).

## Consumer-migration matrix (tracked follow-on, one PR per repo)

For each wrapper: replace its bespoke `IDataProtectionProvider` wrapping with an injected
`ICredentialProtectorFactory.Create(purpose, scope)`; keep its domain purpose string; thread tenant scope where
the consumer is multi-tenant. **Order (low-risk first):** Accessible → SqlBuilder → ClientEmail → Ai →
ConnectionString → Security → Identity (×2). Greenfield: re-protect under the new purpose; no backfill. Each
migration retires one duplicate and is **not** part of standing up the package.

## Done when

- [ ] `MillWorks.Cryptography.DataProtection` ships the factory + protector + marker + DI; **wraps, never
      reimplements** (guard test proves no symmetric-crypto usage).
- [ ] Tenant-segmented purpose isolation proven (A cannot unprotect B/Global).
- [ ] Package builds clean (net10.0, 0 warnings) and publishes to the local feed; added to `build-and-publish.sh`.
- [ ] Consumer-migration matrix authored; the ~9 wrappers tracked for convergence (migrations are separate PRs).

## Non-goals
Reimplementing Data Protection / `IPersonalDataProtector` · per-tenant key *material* unless ratified (§6.6) ·
the personal-data-protector convergence (separate seam) · doing the consumer migrations as part of the package build.

## Build discipline
One build at a time; NUnit; per-project design factory for any EF work (none expected here); no AutoMapper;
greenfield (re-protect, never backfill). `MillWorks.Cryptography.DataProtection` is a published product — held
to the same standalone-quality bar as the rest of the family.
