using System.Security.Cryptography;
using MillWorks.Cryptography.KeyVault.Internal;
using MillWorks.Cryptography.Random;
using MillWorks.Cryptography.Signing;

namespace MillWorks.Cryptography.Tests.KeyVault;

[TestFixture]
public sealed class KeyVaultKeyValidationTests
{
    [Test]
    public void Encryption_master_key_of_expected_size_is_accepted()
    {
        KeyVaultKeyValidation.ValidateEncryptionMasterKey(new byte[32]).Should().BeNull();
    }

    [TestCase(0)]
    [TestCase(16)]
    [TestCase(31)]
    [TestCase(33)]
    [TestCase(64)]
    public void Encryption_master_key_of_wrong_size_is_rejected(int size)
    {
        KeyVaultKeyValidation.ValidateEncryptionMasterKey(new byte[size]).Should().NotBeNull();
    }

    [Test]
    public void Hmac_signing_key_of_expected_size_is_accepted()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.HmacSha256);

        validate(new byte[32]).Should().BeNull();
    }

    [TestCase(16)]
    [TestCase(48)]
    public void Hmac_signing_key_of_wrong_size_is_rejected(int size)
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.HmacSha256);

        validate(new byte[size]).Should().NotBeNull();
    }

    [Test]
    public void Rsa_signing_key_that_is_a_valid_pkcs8_private_key_is_accepted()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.RsaPssSha256);
        var pkcs8 = SigningKeyFactory.GenerateKeyMaterial(SignatureAlgorithm.RsaPssSha256, new SecureRandom(), 2048);

        validate(pkcs8).Should().BeNull();
    }

    [Test]
    public void Rsa_signing_key_that_is_not_a_pkcs8_private_key_is_rejected()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.RsaPssSha256);

        // A 32-byte symmetric key is well-formed Base64 but not an importable RSA private key.
        validate(new byte[32]).Should().NotBeNull();
    }

    [Test]
    public void Ecdsa_signing_key_that_is_a_valid_p256_pkcs8_private_key_is_accepted()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);
        var pkcs8 = SigningKeyFactory.GenerateKeyMaterial(SignatureAlgorithm.EcdsaP256Sha256, new SecureRandom(), 0);

        validate(pkcs8).Should().BeNull();
    }

    [Test]
    public void Ecdsa_signing_key_that_is_not_a_pkcs8_private_key_is_rejected()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);

        validate(new byte[32]).Should().NotBeNull();
    }

    [Test]
    public void Ecdsa_validator_rejects_a_wrong_curve_key()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        validate(p384.ExportPkcs8PrivateKey()).Should().NotBeNull();
    }

    [Test]
    public void Ecdsa_validator_rejects_an_rsa_key()
    {
        var validate = KeyVaultKeyValidation.ForSigningAlgorithm(SignatureAlgorithm.EcdsaP256Sha256);
        using var rsa = RSA.Create(2048);

        validate(rsa.ExportPkcs8PrivateKey()).Should().NotBeNull();
    }
}
