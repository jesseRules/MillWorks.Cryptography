using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.Tests.Signing;

[TestFixture]
public sealed class SigningServiceExtensionsTests
{
    [Test]
    public async Task Registers_rsa_signing_verification_and_jwks_end_to_end()
    {
        var root = Path.Combine(Path.GetTempPath(), "mwcrypto-sign-di-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var serviceProvider = new ServiceCollection()
                .AddMillWorksCryptography()
                .AddMillWorksCryptographyFileSystem(options =>
                {
                    options.KeyStorePath = root;
                    options.MasterKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                    options.AllowAutoKeyGeneration = true;
                    options.SigningAlgorithm = SignatureAlgorithm.RsaPssSha256;
                    options.RsaKeySize = 2048;
                })
                .AddMillWorksCryptographySigning(SignatureAlgorithm.RsaPssSha256)
                .BuildServiceProvider();

            var signer = serviceProvider.GetRequiredService<ISigner>();
            var verifier = serviceProvider.GetRequiredService<IVerifier>();
            var jwksExporter = serviceProvider.GetRequiredService<JwksExporter>();

            signer.Should().BeOfType<RsaPssSigner>();

            var data = "wired"u8.ToArray();
            var envelope = await signer.SignAsync(data, KeyScope.Global);
            (await verifier.VerifyAsync(data, envelope, KeyScope.Global)).Should().BeTrue();

            var document = await jwksExporter.ExportAsync(KeyScope.Global);
            document.Keys.Should().ContainSingle().Which.Kid.Should().Be(envelope.KeyId);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}
