using System.Text;
using Microsoft.Extensions.DependencyInjection;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.Canonicalization;
using MillWorks.Cryptography.Hashing;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests;

[TestFixture]
public sealed class CryptographyServiceExtensionsTests
{
    [Test]
    public void AddMillWorksCryptography_registers_all_four_primitives()
    {
        using var provider = new ServiceCollection().AddMillWorksCryptography().BuildServiceProvider();

        provider.GetService<ISecureRandom>().Should().BeOfType<SecureRandom>();
        provider.GetService<IAeadCipher>().Should().BeOfType<AesGcmCipher>();
        provider.GetService<IHasher>().Should().BeOfType<Sha2Hasher>();
        provider.GetService<IJsonCanonicalizer>().Should().BeOfType<Rfc8785JsonCanonicalizer>();
    }

    [Test]
    public void Primitives_are_registered_as_singletons()
    {
        using var provider = new ServiceCollection().AddMillWorksCryptography().BuildServiceProvider();

        provider.GetRequiredService<IAeadCipher>().Should().BeSameAs(provider.GetRequiredService<IAeadCipher>());
        provider.GetRequiredService<IHasher>().Should().BeSameAs(provider.GetRequiredService<IHasher>());
        provider.GetRequiredService<IJsonCanonicalizer>().Should()
            .BeSameAs(provider.GetRequiredService<IJsonCanonicalizer>());
    }

    [Test]
    public void AddMillWorksCryptography_does_not_overwrite_a_prior_registration()
    {
        var custom = new SecureRandom();
        var services = new ServiceCollection();
        services.AddSingleton<ISecureRandom>(custom);

        services.AddMillWorksCryptography();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISecureRandom>().Should().BeSameAs(custom);
    }

    [Test]
    public void Resolved_cipher_round_trips()
    {
        using var provider = new ServiceCollection().AddMillWorksCryptography().BuildServiceProvider();
        var cipher = provider.GetRequiredService<IAeadCipher>();
        var key = provider.GetRequiredService<ISecureRandom>().GetBytes(AeadFormat.KeySize);

        var frame = cipher.Encrypt(key, "wired"u8.ToArray());

        Encoding.UTF8.GetString(cipher.Decrypt(key, frame)).Should().Be("wired");
    }

    [Test]
    public void AddMillWorksCryptography_null_services_throws()
    {
        var act = () => ((IServiceCollection)null!).AddMillWorksCryptography();

        act.Should().Throw<ArgumentNullException>();
    }
}
