using System.Security.Cryptography;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.Tests.Signing;

[TestFixture]
public sealed class EcdsaSha256SignerTests
{
    private static readonly byte[] Data = "the data to sign"u8.ToArray();

    [Test]
    public async Task Sign_then_verify_round_trips()
    {
        var signer = new EcdsaSha256Signer(ProviderWithEcKey(out var keyId));

        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        envelope.Alg.Should().Be(SignatureAlgorithm.EcdsaP256Sha256);
        envelope.KeyId.Should().Be(keyId);
        envelope.Value.Length.Should().Be(64); // IEEE P1363 r||s for P-256
        (await signer.VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeTrue();
    }

    [Test]
    public async Task Tampered_data_fails_verification()
    {
        var signer = new EcdsaSha256Signer(ProviderWithEcKey(out _));
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        (await signer.VerifyAsync("different!!"u8.ToArray(), envelope, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Tampered_signature_fails_verification()
    {
        var signer = new EcdsaSha256Signer(ProviderWithEcKey(out _));
        var envelope = await signer.SignAsync(Data, KeyScope.Global);
        envelope.Value[0] ^= 0xFF;

        (await signer.VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Unknown_key_id_fails_verification()
    {
        var signer = new EcdsaSha256Signer(ProviderWithEcKey(out _));
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        (await signer.VerifyAsync(Data, envelope with { KeyId = "vUnknown" }, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Mismatched_algorithm_fails_verification()
    {
        var signer = new EcdsaSha256Signer(ProviderWithEcKey(out _));
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        (await signer.VerifyAsync(Data, envelope with { Alg = SignatureAlgorithm.RsaPssSha256 }, KeyScope.Global))
            .Should().BeFalse();
    }

    [Test]
    public async Task Signature_from_a_different_key_under_the_same_id_fails()
    {
        var envelope = await new EcdsaSha256Signer(ProviderWithEcKey(out var keyId)).SignAsync(Data, KeyScope.Global);

        var other = new FakeSigningKeyProvider("ECDSA-P256-SHA256");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        other.AddKey(keyId, ecdsa.ExportPkcs8PrivateKey());

        (await new EcdsaSha256Signer(other).VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task End_to_end_through_the_ecdsa_file_signing_provider()
    {
        var root = Path.Combine(Path.GetTempPath(), "mwcrypto-ec-" + Guid.NewGuid().ToString("N"));
        try
        {
            var options = new FileSystemKeyProviderOptions
            {
                KeyStorePath = root,
                MasterKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(AeadFormat.KeySize)),
                AllowAutoKeyGeneration = true,
                SigningAlgorithm = SignatureAlgorithm.EcdsaP256Sha256,
            };
            using var provider = new FileSigningKeyProvider(
                new AesGcmCipher(new SecureRandom()), new SecureRandom(), TimeProvider.System, options);
            var signer = new EcdsaSha256Signer(provider);

            var envelope = await signer.SignAsync(Data, KeyScope.Global);

            envelope.Alg.Should().Be(SignatureAlgorithm.EcdsaP256Sha256);
            (await signer.VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeTrue();

            var (descriptor, key) = await provider.GetActiveAsync(KeyScope.Global);
            key.Dispose();
            descriptor.Algorithm.Should().Be("ECDSA-P256-SHA256");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static FakeSigningKeyProvider ProviderWithEcKey(out string keyId)
    {
        var provider = new FakeSigningKeyProvider("ECDSA-P256-SHA256");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        keyId = provider.AddKey("v-ec-1", ecdsa.ExportPkcs8PrivateKey());
        return provider;
    }
}
