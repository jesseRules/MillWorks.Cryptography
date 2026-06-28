using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.FileSystem;

/// <summary>
/// Configuration for the file-system key providers.
/// </summary>
public sealed class FileSystemKeyProviderOptions
{
    /// <summary>Root directory under which keys are stored (per usage and tenant scope).</summary>
    public string KeyStorePath { get; set; } = string.Empty;

    /// <summary>Base64-encoded 256-bit master key used to wrap stored key material at rest.</summary>
    public string MasterKeyBase64 { get; set; } = string.Empty;

    /// <summary>
    /// When true, an initial key is generated on first use if none exists. Default false (fail-closed):
    /// missing keys throw. Enable only for dev/bootstrap.
    /// </summary>
    public bool AllowAutoKeyGeneration { get; set; }

    /// <summary>The algorithm the signing provider generates keys for. Default HMAC-SHA-256.</summary>
    public SignatureAlgorithm SigningAlgorithm { get; set; } = SignatureAlgorithm.HmacSha256;

    /// <summary>RSA modulus size (bits) when <see cref="SigningAlgorithm"/> is RSA-PSS.</summary>
    public int RsaKeySize { get; set; } = SigningKeyFactory.DefaultRsaKeySize;

    /// <summary>Decodes and validates the master key.</summary>
    /// <exception cref="KeyProviderException">The key is missing, not Base64, or not 32 bytes.</exception>
    internal byte[] DecodeMasterKey()
    {
        if (string.IsNullOrEmpty(MasterKeyBase64))
        {
            throw new KeyProviderException("A Base64-encoded 256-bit master key is required (MasterKeyBase64).");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(MasterKeyBase64);
        }
        catch (FormatException ex)
        {
            throw new KeyProviderException("MasterKeyBase64 is not valid Base64.", ex);
        }

        if (key.Length != 32)
        {
            throw new KeyProviderException($"Master key must decode to 32 bytes (256-bit); got {key.Length}.");
        }

        return key;
    }
}
