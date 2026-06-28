namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Resolves <b>encryption</b> (content-encryption) key material, scoped by tenant and derived
/// per field, with versioning for rotation. Deliberately disjoint from <see cref="ISigningKeyProvider"/>.
/// </summary>
public interface IEncryptionKeyProvider
{
    /// <summary>Resolves the current encryption key for <paramref name="fieldName"/> within <paramref name="scope"/>.</summary>
    Task<KeyMaterial> GetEncryptionKeyAsync(
        string fieldName,
        KeyScope scope,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves the encryption key for <paramref name="fieldName"/> at a specific
    /// <paramref name="keyVersion"/> within <paramref name="scope"/> (to decrypt data written under an
    /// older version).
    /// </summary>
    Task<KeyMaterial> GetEncryptionKeyAsync(
        string fieldName,
        string keyVersion,
        KeyScope scope,
        CancellationToken cancellationToken = default);

    /// <summary>Returns the current encryption key version for <paramref name="scope"/>.</summary>
    Task<string> GetCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken = default);

    /// <summary>Advances the encryption key version for <paramref name="scope"/> and returns the new version.</summary>
    Task<string> RotateAsync(KeyScope scope, CancellationToken cancellationToken = default);
}
