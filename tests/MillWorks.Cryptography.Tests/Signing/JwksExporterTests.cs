using System.Security.Cryptography;
using MillWorks.Cryptography;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.Tests.Signing;

[TestFixture]
public sealed class JwksExporterTests
{
    [Test]
    public async Task Exports_public_rsa_signing_keys()
    {
        var provider = new FakeSigningKeyProvider("RSA-PSS-SHA256");
        using var rsa = RSA.Create(2048);
        provider.AddKey("v-rsa-1", rsa.ExportPkcs8PrivateKey());

        var jwks = await new JwksExporter(provider).ExportAsync(KeyScope.Global);

        jwks.Keys.Should().HaveCount(1);
        var jwk = jwks.Keys[0];
        jwk.Kty.Should().Be("RSA");
        jwk.Use.Should().Be("sig");
        jwk.Alg.Should().Be("PS256");
        jwk.Kid.Should().Be("v-rsa-1");
        jwk.N.Should().NotBeNullOrEmpty();
        jwk.E.Should().NotBeNullOrEmpty();
    }

    [Test]
    public async Task Exported_components_are_the_public_modulus_and_exponent()
    {
        var provider = new FakeSigningKeyProvider("RSA-PSS-SHA256");
        using var rsa = RSA.Create(2048);
        provider.AddKey("v-rsa-1", rsa.ExportPkcs8PrivateKey());

        var jwks = await new JwksExporter(provider).ExportAsync(KeyScope.Global);

        var expected = rsa.ExportParameters(includePrivateParameters: false);
        CryptoEncoding.FromBase64Url(jwks.Keys[0].N!).Should().Equal(expected.Modulus!);
        CryptoEncoding.FromBase64Url(jwks.Keys[0].E!).Should().Equal(expected.Exponent!);
    }

    [Test]
    public async Task Hmac_keys_have_no_public_half_and_are_not_exported()
    {
        var provider = new FakeSigningKeyProvider("HMAC-SHA256");
        provider.AddKey("v-hmac-1", RandomNumberGenerator.GetBytes(32));

        var jwks = await new JwksExporter(provider).ExportAsync(KeyScope.Global);

        jwks.Keys.Should().BeEmpty();
    }
}
