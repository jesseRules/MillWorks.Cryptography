namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Resolves <b>signing</b> key material, scoped by tenant and versioned for rotation. Deliberately
/// disjoint from <see cref="IEncryptionKeyProvider"/>: a content-encryption key must never resolve
/// through this type, and a signing key must never resolve through the encryption provider.
/// </summary>
public interface ISigningKeyProvider
{
    /// <summary>Resolves the active signing key for <paramref name="scope"/> with its descriptor.</summary>
    Task<(KeyDescriptor Descriptor, KeyMaterial Key)> GetActiveAsync(
        KeyScope scope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a specific signing key by id within <paramref name="scope"/>, or <c>null</c> if it is
    /// unknown. Retired keys remain resolvable so existing signatures can still be verified.
    /// </summary>
    Task<KeyMaterial?> GetByIdAsync(string keyId, KeyScope scope, CancellationToken cancellationToken = default);

    /// <summary>Lists the active signing keys for <paramref name="scope"/> (used to publish a JWKS in C2).</summary>
    Task<IReadOnlyList<KeyDescriptor>> ListActiveAsync(KeyScope scope, CancellationToken cancellationToken = default);

    /// <summary>Generates a new signing key version for <paramref name="scope"/> and makes it active.</summary>
    Task<KeyDescriptor> RotateAsync(KeyScope scope, CancellationToken cancellationToken = default);
}
