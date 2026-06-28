using System.Security.Cryptography;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// RSASSA-PSS over SHA-256 <see cref="ISigner"/> / <see cref="IVerifier"/>. The signing key is an RSA
/// private key (PKCS#8) resolved via <see cref="ISigningKeyProvider"/>.
/// </summary>
public sealed class RsaPssSigner : ISigner, IVerifier
{
    private readonly ISigningKeyProvider _keyProvider;

    /// <summary>Creates the signer over the given key provider.</summary>
    public RsaPssSigner(ISigningKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        _keyProvider = keyProvider;
    }

    /// <inheritdoc />
    public SignatureAlgorithm Algorithm => SignatureAlgorithm.RsaPssSha256;

    /// <inheritdoc />
    public async Task<SignatureEnvelope> SignAsync(
        ReadOnlyMemory<byte> data, KeyScope scope, CancellationToken cancellationToken = default)
    {
        var (descriptor, key) = await _keyProvider.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        using (key)
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key.Span, out _);
            var signature = rsa.SignData(data.ToArray(), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            return new SignatureEnvelope(SignatureAlgorithm.RsaPssSha256, descriptor.KeyId, signature);
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(
        ReadOnlyMemory<byte> data, SignatureEnvelope signature, KeyScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Alg != SignatureAlgorithm.RsaPssSha256)
        {
            return false;
        }

        using var key = await _keyProvider.GetByIdAsync(signature.KeyId, scope, cancellationToken).ConfigureAwait(false);
        if (key is null)
        {
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key.Span, out _);
            return rsa.VerifyData(data.Span, signature.Value, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            return false; // malformed key material or signature
        }
    }
}
