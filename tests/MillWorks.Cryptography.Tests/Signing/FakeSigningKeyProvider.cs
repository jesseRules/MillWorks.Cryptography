using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.Signing;

/// <summary>In-memory <see cref="ISigningKeyProvider"/> for signing tests.</summary>
internal sealed class FakeSigningKeyProvider(string algorithm = "HMAC-SHA256") : ISigningKeyProvider
{
    private readonly Dictionary<string, byte[]> _keys = new(StringComparer.Ordinal);
    private string _current = string.Empty;

    public string AddKey(string keyId, byte[] key)
    {
        _keys[keyId] = key;
        _current = keyId;
        return keyId;
    }

    public Task<(KeyDescriptor Descriptor, KeyMaterial Key)> GetActiveAsync(
        KeyScope scope, CancellationToken cancellationToken = default) =>
        Task.FromResult((Describe(_current, KeyStatus.Active), KeyMaterial.CopyOf(_keys[_current])));

    public Task<KeyMaterial?> GetByIdAsync(string keyId, KeyScope scope, CancellationToken cancellationToken = default) =>
        Task.FromResult(_keys.TryGetValue(keyId, out var key) ? KeyMaterial.CopyOf(key) : null);

    public Task<IReadOnlyList<KeyDescriptor>> ListActiveAsync(KeyScope scope, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<KeyDescriptor> descriptors = _keys.Keys
            .Select(id => Describe(id, string.Equals(id, _current, StringComparison.Ordinal) ? KeyStatus.Active : KeyStatus.Retired))
            .ToList();
        return Task.FromResult(descriptors);
    }

    public Task<KeyDescriptor> RotateAsync(KeyScope scope, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException();

    private KeyDescriptor Describe(string keyId, KeyStatus status) =>
        new(keyId, keyId, status, DateTimeOffset.UnixEpoch, algorithm);
}
