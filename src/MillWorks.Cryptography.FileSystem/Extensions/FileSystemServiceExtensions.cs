using Microsoft.Extensions.DependencyInjection.Extensions;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

// ReSharper disable once CheckNamespace -- DI extensions live in the Microsoft namespace by convention.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions for the file-system key providers.
/// </summary>
public static class FileSystemServiceExtensions
{
    /// <summary>
    /// Registers <see cref="ISigningKeyProvider"/> and <see cref="IEncryptionKeyProvider"/> backed by the
    /// file system. Requires <c>AddMillWorksCryptography()</c> for the AEAD cipher and secure random.
    /// </summary>
    public static IServiceCollection AddMillWorksCryptographyFileSystem(
        this IServiceCollection services, Action<FileSystemKeyProviderOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new FileSystemKeyProviderOptions();
        configure(options);
        _ = options.DecodeMasterKey(); // fail fast at registration on invalid configuration

        services.TryAddSingleton<IEncryptionKeyProvider>(serviceProvider => new FileEncryptionKeyProvider(
            serviceProvider.GetRequiredService<IAeadCipher>(),
            serviceProvider.GetRequiredService<ISecureRandom>(),
            ResolveTimeProvider(serviceProvider),
            options));

        services.TryAddSingleton<ISigningKeyProvider>(serviceProvider => new FileSigningKeyProvider(
            serviceProvider.GetRequiredService<IAeadCipher>(),
            serviceProvider.GetRequiredService<ISecureRandom>(),
            ResolveTimeProvider(serviceProvider),
            options));

        return services;
    }

    private static TimeProvider ResolveTimeProvider(IServiceProvider serviceProvider) =>
        serviceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
}
