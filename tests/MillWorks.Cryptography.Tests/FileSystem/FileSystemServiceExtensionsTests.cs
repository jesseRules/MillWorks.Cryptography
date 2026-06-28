using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using MillWorks.Cryptography.FileSystem;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.FileSystem;

[TestFixture]
public sealed class FileSystemServiceExtensionsTests : FileSystemTestBase
{
    [Test]
    public void Registers_both_file_providers()
    {
        using var serviceProvider = new ServiceCollection()
            .AddMillWorksCryptography()
            .AddMillWorksCryptographyFileSystem(options =>
            {
                options.KeyStorePath = Root;
                options.MasterKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                options.AllowAutoKeyGeneration = true;
            })
            .BuildServiceProvider();

        serviceProvider.GetService<IEncryptionKeyProvider>().Should().BeOfType<FileEncryptionKeyProvider>();
        serviceProvider.GetService<ISigningKeyProvider>().Should().BeOfType<FileSigningKeyProvider>();
    }

    [Test]
    public void Invalid_master_key_fails_fast_at_registration()
    {
        var act = () => new ServiceCollection().AddMillWorksCryptographyFileSystem(options =>
        {
            options.KeyStorePath = Root;
            options.MasterKeyBase64 = "not-valid-base64!!";
        });

        act.Should().Throw<KeyProviderException>();
    }
}
