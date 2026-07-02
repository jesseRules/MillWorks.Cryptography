using System.Security.Cryptography;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// Exports the active <b>public</b> signing keys as a <see cref="JwksDocument"/>. It resolves only
/// through <see cref="ISigningKeyProvider"/> (never the encryption provider) and emits only public key
/// components — symmetric (HMAC) keys, which have no public half, are skipped.
/// </summary>
public sealed class JwksExporter
{
    private const string RsaPssAlgorithm = "RSA-PSS-SHA256";
    private const string EcdsaP256Algorithm = "ECDSA-P256-SHA256";

    private readonly ISigningKeyProvider _signingKeyProvider;

    /// <summary>Creates the exporter over the signing key provider.</summary>
    public JwksExporter(ISigningKeyProvider signingKeyProvider)
    {
        ArgumentNullException.ThrowIfNull(signingKeyProvider);
        _signingKeyProvider = signingKeyProvider;
    }

    /// <summary>Exports the active signing keys for <paramref name="scope"/> as a JWK Set.</summary>
    public async Task<JwksDocument> ExportAsync(KeyScope scope, CancellationToken cancellationToken = default)
    {
        var descriptors = await _signingKeyProvider.ListActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        var keys = new List<Jwk>();

        foreach (var descriptor in descriptors)
        {
            // Only asymmetric keys have a public half to publish; HMAC keys (and any other algorithm
            // without a public JWK representation here) are skipped.
            var isRsa = string.Equals(descriptor.Algorithm, RsaPssAlgorithm, StringComparison.Ordinal);
            var isEcdsa = string.Equals(descriptor.Algorithm, EcdsaP256Algorithm, StringComparison.Ordinal);
            if (!isRsa && !isEcdsa)
            {
                continue;
            }

            using var key = await _signingKeyProvider.GetByIdAsync(descriptor.KeyId, scope, cancellationToken)
                .ConfigureAwait(false);
            if (key is null)
            {
                continue;
            }

            keys.Add(isRsa ? RsaJwk(descriptor.KeyId, key.Span) : EcdsaJwk(descriptor.KeyId, key.Span));
        }

        return new JwksDocument { Keys = keys };
    }

    private static Jwk RsaJwk(string keyId, ReadOnlySpan<byte> pkcs8PrivateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
        var publicParameters = rsa.ExportParameters(includePrivateParameters: false);

        return new Jwk
        {
            Kty = "RSA",
            Kid = keyId,
            Use = "sig",
            Alg = "PS256",
            N = CryptoEncoding.ToBase64Url(publicParameters.Modulus!),
            E = CryptoEncoding.ToBase64Url(publicParameters.Exponent!),
        };
    }

    private static Jwk EcdsaJwk(string keyId, ReadOnlySpan<byte> pkcs8PrivateKey)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
        var publicParameters = ecdsa.ExportParameters(includePrivateParameters: false);

        return new Jwk
        {
            Kty = "EC",
            Kid = keyId,
            Use = "sig",
            Alg = "ES256",
            Crv = "P-256",
            X = CryptoEncoding.ToBase64Url(publicParameters.Q.X!),
            Y = CryptoEncoding.ToBase64Url(publicParameters.Q.Y!),
        };
    }
}
