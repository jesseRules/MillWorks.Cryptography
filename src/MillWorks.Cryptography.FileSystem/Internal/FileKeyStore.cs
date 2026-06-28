using System.Collections.Concurrent;
using System.Security.Cryptography;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.FileSystem.Internal;

/// <summary>
/// Shared on-disk key store for the file-system providers. Keys are laid out per usage and per tenant
/// scope, each version's material is wrapped at rest with the AES-256-GCM AEAD cipher, and a
/// current-version pointer tracks the active version.
/// </summary>
/// <remarks>
/// Internal contract: <see cref="ReadVersionKeyAsync"/> returns the store's own cached buffer. Callers
/// must treat it as read-only and must not dispose it — the store owns it and zeroes it on
/// <see cref="Dispose"/>. Copy or derive from it into a caller-owned <see cref="KeyMaterial"/>.
/// </remarks>
internal sealed class FileKeyStore : IDisposable
{
    private const string CurrentVersionFile = "current-version.txt";
    private const string KeyFileSearchPattern = "key-*.encrypted";
    private const string KeyFilePrefix = "key-";

    private readonly string _root;
    private readonly string _usage;
    private readonly IAeadCipher _cipher;
    private readonly ISecureRandom _secureRandom;
    private readonly TimeProvider _timeProvider;
    private readonly byte[] _masterKey;
    private readonly bool _allowAutoGenerate;
    private readonly Func<byte[]> _generateKey;
    private readonly ConcurrentDictionary<(KeyScope Scope, string Version), byte[]> _cache = new();

    public FileKeyStore(
        string keyStorePath,
        string usage,
        IAeadCipher cipher,
        ISecureRandom secureRandom,
        TimeProvider timeProvider,
        byte[] masterKey,
        bool allowAutoGenerate,
        Func<byte[]> generateKey)
    {
        ArgumentNullException.ThrowIfNull(generateKey);
        ArgumentException.ThrowIfNullOrEmpty(keyStorePath);
        ArgumentException.ThrowIfNullOrEmpty(usage);
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(secureRandom);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.Length != AeadFormat.KeySize)
        {
            throw new KeyProviderException(
                $"Master key must be {AeadFormat.KeySize} bytes (256-bit); got {masterKey.Length}.");
        }

        _root = keyStorePath;
        _usage = usage;
        _cipher = cipher;
        _secureRandom = secureRandom;
        _timeProvider = timeProvider;
        _masterKey = masterKey;
        _allowAutoGenerate = allowAutoGenerate;
        _generateKey = generateKey;
    }

    /// <summary>Returns the active version, auto-generating an initial key if configured, else fails closed.</summary>
    public async Task<string> GetCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        if (TryGetCurrentVersion(scope, out var version))
        {
            return version;
        }

        if (!_allowAutoGenerate)
        {
            throw new KeyProviderException(
                $"No {_usage} key exists for the requested scope and automatic key generation is disabled.");
        }

        return await RotateAsync(scope, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the current-version pointer without generating or throwing.</summary>
    public bool TryGetCurrentVersion(KeyScope scope, out string version)
    {
        var pointer = Path.Combine(ScopeDirectory(scope), CurrentVersionFile);
        if (File.Exists(pointer))
        {
            version = File.ReadAllText(pointer).Trim();
            if (version.Length > 0)
            {
                return true;
            }
        }

        version = string.Empty;
        return false;
    }

    public bool KeyExists(string version, KeyScope scope) =>
        IsValidVersion(version) && File.Exists(KeyFilePath(scope, version));

    /// <summary>Reads and unwraps the per-version key. The returned buffer is store-owned (see remarks).</summary>
    public async Task<byte[]> ReadVersionKeyAsync(string version, KeyScope scope, CancellationToken cancellationToken)
    {
        ValidateVersion(version);

        if (_cache.TryGetValue((scope, version), out var cached))
        {
            return cached;
        }

        var path = KeyFilePath(scope, version);
        if (!File.Exists(path))
        {
            throw new KeyProviderException($"{_usage} key version '{version}' was not found.");
        }

        var framed = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        byte[] key;
        try
        {
            key = _cipher.Decrypt(_masterKey, framed);
        }
        catch (CryptographyException ex)
        {
            throw new KeyProviderException(
                $"Failed to unwrap {_usage} key version '{version}': the file may be corrupt or tampered, "
                + "or the master key is wrong.", ex);
        }

        var stored = _cache.GetOrAdd((scope, version), key);
        if (!ReferenceEquals(stored, key))
        {
            // Lost a benign race with a concurrent reader; zero our now-redundant copy.
            CryptographicOperations.ZeroMemory(key);
        }

        return stored;
    }

    /// <summary>Generates a fresh key version, wraps it, writes it, and points current at it.</summary>
    public async Task<string> RotateAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        var directory = ScopeDirectory(scope);
        Directory.CreateDirectory(directory);

        var key = _generateKey();
        try
        {
            var version = AllocateVersion(scope);
            var framed = _cipher.Encrypt(_masterKey, key);
            await File.WriteAllBytesAsync(KeyFilePath(scope, version), framed, cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(Path.Combine(directory, CurrentVersionFile), version, cancellationToken)
                .ConfigureAwait(false);
            return version;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public IReadOnlyList<string> ListVersions(KeyScope scope)
    {
        var directory = ScopeDirectory(scope);
        if (!Directory.Exists(directory))
        {
            return [];
        }

        var versions = new List<string>();
        foreach (var file in Directory.EnumerateFiles(directory, KeyFileSearchPattern))
        {
            // file name is key-{version}.encrypted; version contains no '.', so strip the one extension.
            var name = Path.GetFileNameWithoutExtension(file);
            versions.Add(name[KeyFilePrefix.Length..]);
        }

        return versions;
    }

    private string ScopeDirectory(KeyScope scope) =>
        Path.Combine(_root, _usage, scope.IsGlobal ? "global" : $"tenant-{scope.TenantId!.Value:N}");

    private string KeyFilePath(KeyScope scope, string version) =>
        Path.Combine(ScopeDirectory(scope), $"{KeyFilePrefix}{version}.encrypted");

    private string AllocateVersion(KeyScope scope)
    {
        for (var attempt = 0; attempt < 16; attempt++)
        {
            var version = KeyVersion.New(_timeProvider, _secureRandom);
            if (!File.Exists(KeyFilePath(scope, version)))
            {
                return version;
            }
        }

        throw new KeyProviderException("Unable to allocate a unique key version.");
    }

    // Versions are written by this store as 'v' + digits + lowercase hex. Rejecting anything else also
    // blocks path traversal via a caller-supplied version string.
    private static bool IsValidVersion(string version) =>
        !string.IsNullOrEmpty(version) && version[0] == 'v' && version.All(char.IsAsciiLetterOrDigit);

    private static void ValidateVersion(string version)
    {
        if (!IsValidVersion(version))
        {
            throw new KeyProviderException($"Invalid key version '{version}'.");
        }
    }

    public void Dispose()
    {
        foreach (var key in _cache.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }

        _cache.Clear();
    }
}
