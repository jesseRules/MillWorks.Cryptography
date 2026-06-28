using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault;
using MillWorks.Cryptography.Random;

// ReSharper disable once CheckNamespace -- DI extensions live in the Microsoft namespace by convention.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions for the Azure Key Vault key providers.
/// </summary>
public static class KeyVaultServiceExtensions
{
    /// <summary>
    /// Registers <see cref="ISigningKeyProvider"/> and <see cref="IEncryptionKeyProvider"/> backed by Azure
    /// Key Vault. Requires <c>AddMillWorksCryptography()</c> for the secure random source.
    /// </summary>
    public static IServiceCollection AddMillWorksCryptographyKeyVault(
        this IServiceCollection services, Action<KeyVaultKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new KeyVaultKeyProviderOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.VaultUri) ||
            !Uri.TryCreate(options.VaultUri, UriKind.Absolute, out var vaultUri))
        {
            throw new KeyProviderException("A valid absolute VaultUri is required.");
        }

        var client = new SecretClient(vaultUri, options.Credential ?? new DefaultAzureCredential());
        var cacheTtl = options.CacheTtl;
        var signingAlgorithm = options.SigningAlgorithm;
        var rsaKeySize = options.RsaKeySize;

        services.TryAddSingleton<IEncryptionKeyProvider>(serviceProvider => new AzureKeyVaultEncryptionKeyProvider(
            client, serviceProvider.GetRequiredService<ISecureRandom>(), ResolveTimeProvider(serviceProvider), cacheTtl));

        services.TryAddSingleton<ISigningKeyProvider>(serviceProvider => new AzureKeyVaultSigningKeyProvider(
            client, serviceProvider.GetRequiredService<ISecureRandom>(), ResolveTimeProvider(serviceProvider), cacheTtl,
            signingAlgorithm, rsaKeySize));

        return services;
    }

    private static TimeProvider ResolveTimeProvider(IServiceProvider serviceProvider) =>
        serviceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
}
