using Azure.Core;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.KeyVault;

/// <summary>
/// Configuration for the Azure Key Vault key providers.
/// </summary>
public sealed class KeyVaultKeyProviderOptions
{
    /// <summary>Absolute URI of the Key Vault (e.g. <c>https://my-vault.vault.azure.net/</c>).</summary>
    public string VaultUri { get; set; } = string.Empty;

    /// <summary>How long resolved keys and version pointers are cached. Default one hour.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Credential used to authenticate to Key Vault. When null, <c>DefaultAzureCredential</c> is used.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>The algorithm the signing provider generates keys for. Default HMAC-SHA-256.</summary>
    public SignatureAlgorithm SigningAlgorithm { get; set; } = SignatureAlgorithm.HmacSha256;

    /// <summary>RSA modulus size (bits) when <see cref="SigningAlgorithm"/> is RSA-PSS.</summary>
    public int RsaKeySize { get; set; } = SigningKeyFactory.DefaultRsaKeySize;
}
