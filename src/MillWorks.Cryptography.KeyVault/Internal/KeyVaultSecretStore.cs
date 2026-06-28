using System.Collections.Concurrent;
using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.KeyVault.Internal;

/// <summary>
/// Shared Key Vault secret store for the Azure key providers. Each version's key is a secret
/// (base64) — Key Vault provides encryption at rest, so no additional wrapping is applied — and a
/// pointer secret tracks the current version, per usage and tenant scope.
/// </summary>
/// <remarks>
/// Reads are cached with a TTL and coalesced with an in-flight de-duplicator to avoid redundant Key
/// Vault calls. <see cref="ReadVersionKeyAsync"/> returns the store's own cached buffer (read-only;
/// the store owns and zeroes it on <see cref="Dispose"/>) — callers copy or derive from it.
/// </remarks>
internal sealed class KeyVaultSecretStore : IDisposable
{
    private readonly SecretClient _client;
    private readonly string _usage;
    private readonly ISecureRandom _secureRandom;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _cacheTtl;
    private readonly Func<byte[]> _generateKey;

    private readonly ConcurrentDictionary<(KeyScope Scope, string Version), CacheEntry<byte[]>> _keyCache = new();
    private readonly ConcurrentDictionary<KeyScope, CacheEntry<string>> _currentCache = new();
    private readonly ConcurrentDictionary<(KeyScope Scope, string Version), Lazy<Task<byte[]?>>> _keyInflight = new();
    private readonly ConcurrentDictionary<KeyScope, Lazy<Task<string?>>> _currentInflight = new();

    public KeyVaultSecretStore(
        SecretClient client, string usage, ISecureRandom secureRandom, TimeProvider timeProvider, TimeSpan cacheTtl,
        Func<byte[]> generateKey)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrEmpty(usage);
        ArgumentNullException.ThrowIfNull(secureRandom);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(generateKey);

        _client = client;
        _usage = usage;
        _secureRandom = secureRandom;
        _timeProvider = timeProvider;
        _cacheTtl = cacheTtl > TimeSpan.Zero ? cacheTtl : TimeSpan.FromHours(1);
        _generateKey = generateKey;
    }

    public async Task<string> GetCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken) =>
        await TryGetCurrentVersionAsync(scope, cancellationToken).ConfigureAwait(false)
        ?? throw new KeyProviderException($"No {_usage} key exists for the requested scope.");

    public async Task<string?> TryGetCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        if (TryFromCache(_currentCache, scope, out var cached))
        {
            return cached;
        }

        return await DedupAsync(_currentInflight, scope, () => LoadCurrentVersionAsync(scope, cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<byte[]> ReadVersionKeyAsync(string version, KeyScope scope, CancellationToken cancellationToken) =>
        await ReadVersionKeyOrNullAsync(version, scope, cancellationToken).ConfigureAwait(false)
        ?? throw new KeyProviderException($"{_usage} key version '{version}' was not found.");

    public async Task<byte[]?> ReadVersionKeyOrNullAsync(string version, KeyScope scope, CancellationToken cancellationToken)
    {
        ValidateVersion(version);

        if (TryFromCache(_keyCache, (scope, version), out var cached))
        {
            return cached;
        }

        return await DedupAsync(_keyInflight, (scope, version), () => LoadKeyAsync(version, scope, cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<string> RotateAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        var key = _generateKey();
        try
        {
            var version = KeyVersion.New(_timeProvider, _secureRandom);
            await SetSecretAsync(KeyVaultSecretNaming.KeySecretName(_usage, scope, version),
                Convert.ToBase64String(key), cancellationToken).ConfigureAwait(false);
            await SetSecretAsync(KeyVaultSecretNaming.CurrentVersionSecretName(_usage, scope),
                version, cancellationToken).ConfigureAwait(false);

            _currentCache[scope] = new CacheEntry<string>(version, _timeProvider.GetUtcNow());
            return version;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public async Task<IReadOnlyList<string>> ListVersionsAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        var versions = new List<string>();
        try
        {
            await foreach (var properties in _client.GetPropertiesOfSecretsAsync(cancellationToken).ConfigureAwait(false))
            {
                var version = KeyVaultSecretNaming.TryExtractVersion(_usage, scope, properties.Name);
                if (version is not null)
                {
                    versions.Add(version);
                }
            }
        }
        catch (RequestFailedException ex)
        {
            throw new KeyProviderException($"Failed to list {_usage} key versions from Key Vault ({ex.Status}).", ex);
        }

        return versions;
    }

    private async Task<string?> LoadCurrentVersionAsync(KeyScope scope, CancellationToken cancellationToken)
    {
        var value = await GetSecretValueOrNullAsync(
            KeyVaultSecretNaming.CurrentVersionSecretName(_usage, scope), cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        _currentCache[scope] = new CacheEntry<string>(value, _timeProvider.GetUtcNow());
        return value;
    }

    private async Task<byte[]?> LoadKeyAsync(string version, KeyScope scope, CancellationToken cancellationToken)
    {
        var value = await GetSecretValueOrNullAsync(
            KeyVaultSecretNaming.KeySecretName(_usage, scope, version), cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new KeyProviderException($"{_usage} key version '{version}' is not valid Base64.", ex);
        }

        _keyCache[(scope, version)] = new CacheEntry<byte[]>(key, _timeProvider.GetUtcNow());
        return key;
    }

    private async Task<string?> GetSecretValueOrNullAsync(string name, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _client.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
            return response.Value.Value;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
        catch (RequestFailedException ex) when (ex.Status == 403)
        {
            throw new KeyProviderException($"Access denied reading Key Vault secret '{name}'.", ex);
        }
        catch (RequestFailedException ex)
        {
            throw new KeyProviderException($"Failed to read Key Vault secret '{name}' ({ex.Status}).", ex);
        }
    }

    private async Task SetSecretAsync(string name, string value, CancellationToken cancellationToken)
    {
        try
        {
            await _client.SetSecretAsync(name, value, cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException ex)
        {
            throw new KeyProviderException($"Failed to write Key Vault secret '{name}' ({ex.Status}).", ex);
        }
    }

    private bool TryFromCache<TKey, T>(ConcurrentDictionary<TKey, CacheEntry<T>> cache, TKey key, out T value)
        where TKey : notnull
    {
        if (cache.TryGetValue(key, out var entry) && _timeProvider.GetUtcNow() - entry.CachedAt < _cacheTtl)
        {
            value = entry.Value;
            return true;
        }

        value = default!;
        return false;
    }

    private static async Task<T> DedupAsync<TKey, T>(
        ConcurrentDictionary<TKey, Lazy<Task<T>>> inflight, TKey key, Func<Task<T>> load)
        where TKey : notnull
    {
        var lazy = inflight.GetOrAdd(
            key, _ => new Lazy<Task<T>>(load, LazyThreadSafetyMode.ExecutionAndPublication));
        try
        {
            return await lazy.Value.ConfigureAwait(false);
        }
        finally
        {
            inflight.TryRemove(key, out _);
        }
    }

    // Versions are written by this store as 'v' + digits + lowercase hex; reject anything else so a
    // caller-supplied version cannot produce an unexpected secret name.
    private static void ValidateVersion(string version)
    {
        if (string.IsNullOrEmpty(version) || version[0] != 'v' || !version.All(char.IsAsciiLetterOrDigit))
        {
            throw new KeyProviderException($"Invalid key version '{version}'.");
        }
    }

    public void Dispose()
    {
        foreach (var entry in _keyCache.Values)
        {
            CryptographicOperations.ZeroMemory(entry.Value);
        }

        _keyCache.Clear();
        _currentCache.Clear();
    }

    private sealed record CacheEntry<T>(T Value, DateTimeOffset CachedAt);
}
