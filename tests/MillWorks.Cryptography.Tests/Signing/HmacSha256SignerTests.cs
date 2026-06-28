using System.Security.Cryptography;
using MillWorks.Cryptography.Hashing;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.Tests.Signing;

[TestFixture]
public sealed class HmacSha256SignerTests
{
    private static readonly IHasher Hasher = new Sha2Hasher();
    private static readonly byte[] Data = "the data to sign"u8.ToArray();

    [Test]
    public async Task Sign_then_verify_round_trips()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out _), Hasher);

        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        envelope.Alg.Should().Be(SignatureAlgorithm.HmacSha256);
        (await signer.VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeTrue();
    }

    [Test]
    public async Task Envelope_carries_the_active_key_id()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out var keyId), Hasher);

        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        envelope.KeyId.Should().Be(keyId);
    }

    [Test]
    public async Task Tampered_data_fails_verification()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out _), Hasher);
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        (await signer.VerifyAsync("different data!!"u8.ToArray(), envelope, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Tampered_signature_fails_verification()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out _), Hasher);
        var envelope = await signer.SignAsync(Data, KeyScope.Global);
        envelope.Value[0] ^= 0xFF;

        (await signer.VerifyAsync(Data, envelope, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Unknown_key_id_fails_verification()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out _), Hasher);
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        var wrongKey = envelope with { KeyId = "vUnknownKey" };

        (await signer.VerifyAsync(Data, wrongKey, KeyScope.Global)).Should().BeFalse();
    }

    [Test]
    public async Task Mismatched_algorithm_fails_verification()
    {
        var signer = new HmacSha256Signer(ProviderWithKey(out _), Hasher);
        var envelope = await signer.SignAsync(Data, KeyScope.Global);

        var wrongAlg = envelope with { Alg = SignatureAlgorithm.RsaPssSha256 };

        (await signer.VerifyAsync(Data, wrongAlg, KeyScope.Global)).Should().BeFalse();
    }

    private static FakeSigningKeyProvider ProviderWithKey(out string keyId)
    {
        var provider = new FakeSigningKeyProvider();
        keyId = provider.AddKey("v-test-1", RandomNumberGenerator.GetBytes(32));
        return provider;
    }
}
