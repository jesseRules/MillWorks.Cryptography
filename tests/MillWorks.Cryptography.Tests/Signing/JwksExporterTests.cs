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
    public async Task Exports_public_ecdsa_signing_keys()
    {
        var provider = new FakeSigningKeyProvider("ECDSA-P256-SHA256");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        provider.AddKey("v-ec-1", ecdsa.ExportPkcs8PrivateKey());

        var jwks = await new JwksExporter(provider).ExportAsync(KeyScope.Global);

        jwks.Keys.Should().HaveCount(1);
        var jwk = jwks.Keys[0];
        jwk.Kty.Should().Be("EC");
        jwk.Use.Should().Be("sig");
        jwk.Alg.Should().Be("ES256");
        jwk.Crv.Should().Be("P-256");
        jwk.Kid.Should().Be("v-ec-1");
        jwk.X.Should().NotBeNullOrEmpty();
        jwk.Y.Should().NotBeNullOrEmpty();
        jwk.N.Should().BeNull();
        jwk.E.Should().BeNull();

        // P-256 field elements are 32 bytes each.
        CryptoEncoding.FromBase64Url(jwk.X!).Should().HaveCount(32);
        CryptoEncoding.FromBase64Url(jwk.Y!).Should().HaveCount(32);
    }

    [Test]
    public async Task Exported_ec_public_key_verifies_the_signers_es256_signature()
    {
        // End-to-end JOSE interop: a relying party rebuilding the key from the JWK's x/y must be able to
        // verify an ES256 (IEEE P1363) signature the signer produced with the private half.
        var provider = new FakeSigningKeyProvider("ECDSA-P256-SHA256");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        provider.AddKey("v-ec-1", ecdsa.ExportPkcs8PrivateKey());

        var data = "es256 interop"u8.ToArray();
        var envelope = await new EcdsaSha256Signer(provider).SignAsync(data, KeyScope.Global);
        var jwk = (await new JwksExporter(provider).ExportAsync(KeyScope.Global)).Keys[0];

        using var publicKey = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = CryptoEncoding.FromBase64Url(jwk.X!),
                Y = CryptoEncoding.FromBase64Url(jwk.Y!),
            },
        });

        publicKey.VerifyData(
                data, envelope.Value, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            .Should().BeTrue();
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
