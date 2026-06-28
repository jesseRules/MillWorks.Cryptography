using MillWorks.Cryptography.Hashing;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// HMAC-SHA-256 <see cref="ISigner"/> / <see cref="IVerifier"/>. Resolves the symmetric signing key via
/// <see cref="ISigningKeyProvider"/>; verification is constant-time.
/// </summary>
public sealed class HmacSha256Signer : ISigner, IVerifier
{
    private readonly ISigningKeyProvider _keyProvider;
    private readonly IHasher _hasher;

    /// <summary>Creates the signer over the given key provider and hasher.</summary>
    public HmacSha256Signer(ISigningKeyProvider keyProvider, IHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        ArgumentNullException.ThrowIfNull(hasher);
        _keyProvider = keyProvider;
        _hasher = hasher;
    }

    /// <inheritdoc />
    public SignatureAlgorithm Algorithm => SignatureAlgorithm.HmacSha256;

    /// <inheritdoc />
    public async Task<SignatureEnvelope> SignAsync(
        ReadOnlyMemory<byte> data, KeyScope scope, CancellationToken cancellationToken = default)
    {
        var (descriptor, key) = await _keyProvider.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        using (key)
        {
            var mac = _hasher.HmacSha256(key.Span, data.Span);
            return new SignatureEnvelope(SignatureAlgorithm.HmacSha256, descriptor.KeyId, mac);
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(
        ReadOnlyMemory<byte> data, SignatureEnvelope signature, KeyScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Alg != SignatureAlgorithm.HmacSha256)
        {
            return false;
        }

        using var key = await _keyProvider.GetByIdAsync(signature.KeyId, scope, cancellationToken).ConfigureAwait(false);
        if (key is null)
        {
            return false;
        }

        var expected = _hasher.HmacSha256(key.Span, data.Span);
        return ConstantTime.Equals(expected, signature.Value);
    }
}
