using Microsoft.Extensions.DependencyInjection.Extensions;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.Canonicalization;
using MillWorks.Cryptography.Hashing;
using MillWorks.Cryptography.Random;

// ReSharper disable once CheckNamespace -- DI extensions live in the Microsoft namespace by convention,
// so AddMillWorksCryptography is discoverable wherever IServiceCollection is already in scope.
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration extensions for the MillWorks Cryptography primitives.
/// </summary>
public static class CryptographyServiceExtensions
{
    /// <summary>
    /// Registers the cryptographic primitives — <see cref="ISecureRandom"/>, <see cref="IAeadCipher"/>,
    /// <see cref="IHasher"/>, and <see cref="IJsonCanonicalizer"/> — as singletons (all are stateless and
    /// thread-safe). Existing registrations are preserved, so a consumer can override any primitive.
    /// The static helpers (<c>CryptoEncoding</c>, <c>ConstantTime</c>) need no registration.
    /// </summary>
    public static IServiceCollection AddMillWorksCryptography(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ISecureRandom, SecureRandom>();
        services.TryAddSingleton<IAeadCipher, AesGcmCipher>();
        services.TryAddSingleton<IHasher, Sha2Hasher>();
        services.TryAddSingleton<IJsonCanonicalizer, Rfc8785JsonCanonicalizer>();

        return services;
    }
}
