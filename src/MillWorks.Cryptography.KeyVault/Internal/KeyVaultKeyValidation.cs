using System.Security.Cryptography;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.KeyVault.Internal;

/// <summary>
/// Validates the shape of key material read back from a Key Vault secret before it is cached or used.
/// Key Vault applies no additional wrapping, so — unlike the AEAD-wrapped file backend, whose unwrap
/// fails closed on a corrupt file — a mis-provisioned or corrupted secret would otherwise flow straight
/// into HKDF derivation, HMAC, or RSA as arbitrary-length bytes. These checks fail such secrets closed.
/// Each validator returns <c>null</c> when the material is well-formed, or a human-readable reason.
/// </summary>
internal static class KeyVaultKeyValidation
{
    /// <summary>Expected size of a symmetric master/HMAC key, in bytes (256-bit).</summary>
    public const int SymmetricKeySize = 32;

    /// <summary>Validates the 256-bit HKDF master key an encryption provider derives field keys from.</summary>
    public static string? ValidateEncryptionMasterKey(byte[] key) =>
        key.Length == SymmetricKeySize
            ? null
            : $"expected a {SymmetricKeySize}-byte key but got {key.Length}";

    /// <summary>Returns the validator for a signing algorithm's stored key material.</summary>
    public static Func<byte[], string?> ForSigningAlgorithm(SignatureAlgorithm algorithm) => algorithm switch
    {
        SignatureAlgorithm.HmacSha256 => static key =>
            key.Length == SymmetricKeySize
                ? null
                : $"expected a {SymmetricKeySize}-byte HMAC key but got {key.Length}",
        SignatureAlgorithm.RsaPssSha256 => ValidateRsaPrivateKey,
        SignatureAlgorithm.EcdsaP256Sha256 => ValidateEcdsaPrivateKey,
        _ => throw new NotSupportedException($"No key validation is defined for '{algorithm}'."),
    };

    private static string? ValidateRsaPrivateKey(byte[] key)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key, out var bytesRead);
            return bytesRead == key.Length ? null : "trailing data after the PKCS#8 RSA private key";
        }
        catch (CryptographicException)
        {
            return "expected an importable PKCS#8 RSA private key";
        }
    }

    private static string? ValidateEcdsaPrivateKey(byte[] key)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(key, out var bytesRead);
            if (bytesRead != key.Length)
            {
                return "trailing data after the PKCS#8 EC private key";
            }

            var keySizeBits = ecdsa.KeySize;
            return keySizeBits == 256 ? null : $"expected a P-256 EC private key but got a {keySizeBits}-bit curve";
        }
        catch (CryptographicException)
        {
            return "expected an importable PKCS#8 EC private key";
        }
    }
}
