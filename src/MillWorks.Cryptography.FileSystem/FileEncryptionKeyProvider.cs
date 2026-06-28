using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem.Internal;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.FileSystem;

/// <summary>
/// File-system <see cref="IEncryptionKeyProvider"/>: stores a per-version master key (wrapped at rest
/// with the AEAD cipher) and derives per-field encryption keys from it via HKDF-SHA256.
/// </summary>
public sealed class FileEncryptionKeyProvider : IEncryptionKeyProvider, IDisposable
{
    private readonly FileKeyStore _store;

    /// <summary>Creates the provider over the configured key store.</summary>
    public FileEncryptionKeyProvider(
        IAeadCipher cipher,
        ISecureRandom secureRandom,
        TimeProvider timeProvider,
        FileSystemKeyProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _store = new FileKeyStore(
            options.KeyStorePath, "encryption", cipher, secureRandom, timeProvider,
            options.DecodeMasterKey(), options.AllowAutoKeyGeneration,
            () => secureRandom.GetBytes(AeadFormat.KeySize));
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
