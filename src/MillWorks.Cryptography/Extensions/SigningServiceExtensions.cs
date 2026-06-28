using Microsoft.Extensions.DependencyInjection.Extensions;
using MillWorks.Cryptography.Hashing;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Signing;

// ReSharper disable once CheckNamespace -- DI extensions live in the Microsoft namespace by convention.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions for signing, verification, and JWKS export.
/// </summary>
public static class SigningServiceExtensions
{
    /// <summary>
    /// Registers an <see cref="ISigner"/> / <see cref="IVerifier"/> for <paramref name="algorithm"/> plus a
    /// <see cref="JwksExporter"/>, all resolving keys via the registered <see cref="ISigningKeyProvider"/>
    /// (configure it for the matching algorithm). Requires <c>AddMillWorksCryptography()</c>.
    /// </summary>
    public static IServiceCollection AddMillWorksCryptographySigning(
        this IServiceCollection services, SignatureAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(services);

        switch (algorithm)
        {
            case SignatureAlgorithm.HmacSha256:
                services.TryAddSingleton(serviceProvider => new HmacSha256Signer(
                    serviceProvider.GetRequiredService<ISigningKeyProvider>(), serviceProvider.GetRequiredService<IHasher>()));
                services.TryAddSingleton<ISigner>(serviceProvider => serviceProvider.GetRequiredService<HmacSha256Signer>());
                services.TryAddSingleton<IVerifier>(serviceProvider => serviceProvider.GetRequiredService<HmacSha256Signer>());
                break;

            case SignatureAlgorithm.RsaPssSha256:
                services.TryAddSingleton(serviceProvider => new RsaPssSigner(
                    serviceProvider.GetRequiredService<ISigningKeyProvider>()));
                services.TryAddSingleton<ISigner>(serviceProvider => serviceProvider.GetRequiredService<RsaPssSigner>());
                services.TryAddSingleton<IVerifier>(serviceProvider => serviceProvider.GetRequiredService<RsaPssSigner>());
                break;

            default:
                throw new NotSupportedException($"Signing is not supported for '{algorithm}'.");
        }

        services.TryAddSingleton(serviceProvider => new JwksExporter(serviceProvider.GetRequiredService<ISigningKeyProvider>()));
        return services;
    }
}
