using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem.Internal;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.FileSystem;

/// <summary>
/// File-system <see cref="ISigningKeyProvider"/>: each stored per-version key is itself the signing key
/// (wrapped at rest with the AEAD cipher). The version string is the key id (<c>kid</c>).
/// </summary>
public sealed class FileSigningKeyProvider : ISigningKeyProvider, IDisposable
{
    private readonly FileKeyStore _store;
    private readonly string _algorithm;

    /// <summary>Creates the provider over the configured key store.</summary>
    public FileSigningKeyProvider(
        IAeadCipher cipher,
        ISecureRandom secureRandom,
        TimeProvider timeProvider,
        FileSystemKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var signingAlgorithm = options.SigningAlgorithm;
        var rsaKeySize = options.RsaKeySize;
        _algorithm = SigningKeyFactory.AlgorithmName(signingAlgorithm);
        _store = new FileKeyStore(
            options.KeyStorePath, "signing", cipher, secureRandom, timeProvider,
            options.DecodeMasterKey(), options.AllowAutoKeyGeneration,
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

        // Unknown id returns null; a present-but-unwrappable (tampered) key still fails closed.
        if (!_store.KeyExists(keyId, scope))
        {
            return null;
        }

        var key = await _store.ReadVersionKeyAsync(keyId, scope, cancellationToken).ConfigureAwait(false);
        return KeyMaterial.CopyOf(key);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<KeyDescriptor>> ListActiveAsync(KeyScope scope, CancellationToken cancellationToken = default)
    {
        _store.TryGetCurrentVersion(scope, out var current);

        IReadOnlyList<KeyDescriptor> descriptors = _store.ListVersions(scope)
            .Select(version => Describe(
                version,
                string.Equals(version, current, StringComparison.Ordinal) ? KeyStatus.Active : KeyStatus.Retired))
            .ToList();

        return Task.FromResult(descriptors);
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
