using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault.Internal;
using MillWorks.Cryptography.Random;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.KeyVault;

/// <summary>
/// Azure Key Vault <see cref="ISigningKeyProvider"/>: each stored per-version secret is itself the
/// signing key. The version string is the key id (<c>kid</c>).
/// </summary>
public sealed class AzureKeyVaultSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly KeyVaultSecretStore _store;
    private readonly string _algorithm;

    /// <summary>Creates the provider over the given Key Vault secret client.</summary>
    public AzureKeyVaultSigningKeyProvider(
        SecretClient client,
        ISecureRandom secureRandom,
        TimeProvider timeProvider,
        TimeSpan cacheTtl,
        SignatureAlgorithm signingAlgorithm = SignatureAlgorithm.HmacSha256,
        int rsaKeySize = SigningKeyFactory.DefaultRsaKeySize)
    {
        _algorithm = SigningKeyFactory.AlgorithmName(signingAlgorithm);
        _store = new KeyVaultSecretStore(
            client, "sig", secureRandom, timeProvider, cacheTtl,
            () => SigningKeyFactory.GenerateKeyMaterial(signingAlgorithm, secureRandom, rsaKeySize));
    }

    /// <inheritdoc />
    public async Task<(KeyDescriptor Descriptor, KeyMaterial Key)> GetActiveAsync(
        KeyScope scope, CancellationToken cancellationToken = default)
    {
        var version = await _store.GetCurrentVersionAsync(scope, cancellationToken).ConfigureAwait(false);
        var key = await _store.ReadVersionKeyAsync(version, scope, cancellationToken).ConfigureAwait(false);
        return (Describe(version, KeyStatus.Active), KeyMaterial.CopyOf(key));
    }

    /// <inheritdoc />
    public async Task<KeyMaterial?> GetByIdAsync(string keyId, KeyScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        var key = await _store.ReadVersionKeyOrNullAsync(keyId, scope, cancellationToken).ConfigureAwait(false);
        return key is null ? null : KeyMaterial.CopyOf(key);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<KeyDescriptor>> ListActiveAsync(KeyScope scope, CancellationToken cancellationToken = default)
    {
        var current = await _store.TryGetCurrentVersionAsync(scope, cancellationToken).ConfigureAwait(false);
        var versions = await _store.ListVersionsAsync(scope, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<KeyDescriptor> descriptors = versions
            .Select(version => Describe(
                version,
                string.Equals(version, current, StringComparison.Ordinal) ? KeyStatus.Active : KeyStatus.Retired))
            .ToList();

        return descriptors;
    }

    /// <inheritdoc />
    public async Task<KeyDescriptor> RotateAsync(KeyScope scope, CancellationToken cancellationToken = default)
    {
        var version = await _store.RotateAsync(scope, cancellationToken).ConfigureAwait(false);
        return Describe(version, KeyStatus.Active);
    }

    /// <summary>Zeroes any cached key material.</summary>
    public void Dispose() => _store.Dispose();

    private KeyDescriptor Describe(string version, KeyStatus status) =>
        new(version, version, status, KeyVersion.ParseCreatedAt(version), _algorithm);
}
