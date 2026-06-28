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
            // Only asymmetric keys have a public half to publish; HMAC keys are skipped.
            if (!string.Equals(descriptor.Algorithm, RsaPssAlgorithm, StringComparison.Ordinal))
            {
                continue;
            }

            using var key = await _signingKeyProvider.GetByIdAsync(descriptor.KeyId, scope, cancellationToken)
                .ConfigureAwait(false);
            if (key is null)
            {
                continue;
            }

            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key.Span, out _);
            var publicParameters = rsa.ExportParameters(includePrivateParameters: false);

            keys.Add(new Jwk
            {
                Kty = "RSA",
                Kid = descriptor.KeyId,
                Use = "sig",
                Alg = "PS256",
                N = CryptoEncoding.ToBase64Url(publicParameters.Modulus!),
                E = CryptoEncoding.ToBase64Url(publicParameters.Exponent!),
            });
        }

        return new JwksDocument { Keys = keys };
    }
}
