using System.Security.Cryptography;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// ECDSA over NIST P-256 with SHA-256 (JOSE <c>ES256</c>) <see cref="ISigner"/> / <see cref="IVerifier"/>.
/// The signing key is an EC private key (PKCS#8) resolved via <see cref="ISigningKeyProvider"/>.
/// </summary>
/// <remarks>
/// Signatures use the fixed-length IEEE P1363 format (raw <c>r || s</c>, 64 bytes for P-256), which is
/// the JOSE/JWS encoding for ES256 — so an envelope produced here verifies against the same key published
/// via <see cref="JwksExporter"/> under <c>ES256</c>, and vice versa.
/// </remarks>
public sealed class EcdsaSha256Signer : ISigner, IVerifier
{
    private readonly ISigningKeyProvider _keyProvider;

    /// <summary>Creates the signer over the given key provider.</summary>
    public EcdsaSha256Signer(ISigningKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        _keyProvider = keyProvider;
    }

    /// <inheritdoc />
    public SignatureAlgorithm Algorithm => SignatureAlgorithm.EcdsaP256Sha256;

    /// <inheritdoc />
    public async Task<SignatureEnvelope> SignAsync(
        ReadOnlyMemory<byte> data, KeyScope scope, CancellationToken cancellationToken = default)
    {
        var (descriptor, key) = await _keyProvider.GetActiveAsync(scope, cancellationToken).ConfigureAwait(false);
        using (key)
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(key.Span, out _);
            var signature = ecdsa.SignData(
                data.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new SignatureEnvelope(SignatureAlgorithm.EcdsaP256Sha256, descriptor.KeyId, signature);
        }
    }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(
        ReadOnlyMemory<byte> data, SignatureEnvelope signature, KeyScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Alg != SignatureAlgorithm.EcdsaP256Sha256)
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
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(key.Span, out _);
            return ecdsa.VerifyData(
                data.Span, signature.Value, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false; // malformed key material or signature
        }
    }
}
