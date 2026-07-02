using System.Security.Cryptography;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// Generates signing key material for a <see cref="SignatureAlgorithm"/> and names it for a
/// <see cref="KeyManagement.KeyDescriptor"/>. Used by the signing key providers so a provider can be
/// configured per algorithm (a 32-byte HMAC key, or an RSA PKCS#8 private key).
/// </summary>
public static class SigningKeyFactory
{
    /// <summary>Default RSA modulus size, in bits.</summary>
    public const int DefaultRsaKeySize = 3072;

    /// <summary>The descriptor algorithm name for <paramref name="algorithm"/>.</summary>
    public static string AlgorithmName(SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.HmacSha256 => "HMAC-SHA256",
        SignatureAlgorithm.RsaPssSha256 => "RSA-PSS-SHA256",
        SignatureAlgorithm.EcdsaP256Sha256 => "ECDSA-P256-SHA256",
        _ => throw new NotSupportedException($"Signing key generation is not supported for '{algorithm}'."),
    };

    /// <summary>
    /// Generates fresh signing key material: a 32-byte key for HMAC, a PKCS#8-encoded private key for
    /// RSA-PSS, or a PKCS#8-encoded NIST P-256 private key for ECDSA (ES256).
    /// </summary>
    public static byte[] GenerateKeyMaterial(SignatureAlgorithm algorithm, ISecureRandom secureRandom, int rsaKeySize)
    {
        ArgumentNullException.ThrowIfNull(secureRandom);

        if (algorithm == SignatureAlgorithm.HmacSha256)
        {
            return secureRandom.GetBytes(32);
        }

        if (algorithm == SignatureAlgorithm.RsaPssSha256)
        {
            using var rsa = RSA.Create(rsaKeySize);
            return rsa.ExportPkcs8PrivateKey();
        }

        if (algorithm == SignatureAlgorithm.EcdsaP256Sha256)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return ecdsa.ExportPkcs8PrivateKey();
        }

        throw new NotSupportedException($"Signing key generation is not supported for '{algorithm}'.");
    }
}
