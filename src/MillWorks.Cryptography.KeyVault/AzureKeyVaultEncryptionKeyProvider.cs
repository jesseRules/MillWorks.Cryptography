using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault.Internal;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.KeyVault;

/// <summary>
/// Azure Key Vault <see cref="IEncryptionKeyProvider"/>: stores a per-version master key as a secret and
/// derives per-field encryption keys from it via HKDF-SHA256.
/// </summary>
public sealed class AzureKeyVaultEncryptionKeyProvider : IEncryptionKeyProvider, IDisposable
{
    private readonly KeyVaultSecretStore _store;

    /// <summary>Creates the provider over the given Key Vault secret client.</summary>
    public AzureKeyVaultEncryptionKeyProvider(
        SecretClient client, ISecureRandom secureRandom, TimeProvider timeProvider, TimeSpan cacheTtl)
    {
        _store = new KeyVaultSecretStore(
            client, "enc", secureRandom, timeProvider, cacheTtl, () => secureRandom.GetBytes(32));
    }

    /// <inheritdoc />
    public async Task<KeyMaterial> GetEncryptionKeyAsync(
        string fieldName, KeyScope scope, CancellationToken cancellationToken = default)
    {
        var version = await _store.GetCurrentVersionAsync(scope, cancellationToken).ConfigureAwait(false);
        return await GetEncryptionKeyAsync(fieldName, version, scope, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<KeyMaterial> GetEncryptionKeyAsync(
        string fieldName, string keyVersion, KeyScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        var master = await _store.ReadVersionKeyAsync(keyVersion, scope, cancellationToken).ConfigureAwait(false);
        return new KeyMaterial(FieldKeyDerivation.DeriveFieldKey(master, fieldName, keyVersion));
    }

    /// <inheritdoc />
    public Task<string> GetCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken = default) =>
        _store.GetCurrentVersionAsync(scope, cancellationToken);

    /// <inheritdoc />
    public Task<string> RotateAsync(KeyScope scope, CancellationToken cancellationToken = default) =>
        _store.RotateAsync(scope, cancellationToken);

    /// <summary>Zeroes any cached key material.</summary>
    public void Dispose() => _store.Dispose();
}
