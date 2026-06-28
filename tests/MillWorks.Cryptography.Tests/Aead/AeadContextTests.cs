using System.Security.Cryptography;
using System.Text;
using MillWorks.Cryptography;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.Aead;

[TestFixture]
public sealed class AeadContextTests
{
    [Test]
    public void Build_is_deterministic()
    {
        AeadContext.Build("a", "b", "c").Should().Equal(AeadContext.Build("a", "b", "c"));
    }

    [Test]
    public void Length_prefixing_prevents_component_ambiguity()
    {
        AeadContext.Build("ab", "c").Should().NotEqual(AeadContext.Build("a", "bc"));
    }

    [Test]
    public void Empty_components_are_allowed_and_distinct_from_absent()
    {
        AeadContext.Build("", "").Should().NotEqual(AeadContext.Build(""));
    }

    [Test]
    public void Null_component_throws()
    {
        var act = () => AeadContext.Build("a", null!, "c");

        act.Should().Throw<ArgumentNullException>();
    }

    [Test]
    public void ForKey_distinguishes_scope_version_and_field()
    {
        var tenant = KeyScope.ForTenant(Guid.NewGuid());

        var baseline = AeadContext.ForKey(KeyScope.Global, "v1", "Email");
        baseline.Should().NotEqual(AeadContext.ForKey(tenant, "v1", "Email"));     // scope
        baseline.Should().NotEqual(AeadContext.ForKey(KeyScope.Global, "v2", "Email")); // version
        baseline.Should().NotEqual(AeadContext.ForKey(KeyScope.Global, "v1", "Ssn"));    // field
        baseline.Should().Equal(AeadContext.ForKey(KeyScope.Global, "v1", "Email"));     // same
    }

    [Test]
    public void Bound_context_round_trips_and_rejects_a_different_context()
    {
        var cipher = new AesGcmCipher(new SecureRandom());
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var plaintext = "secret"u8.ToArray();

        var aad = AeadContext.ForKey(KeyScope.Global, "v1", "Email");
        var frame = cipher.Encrypt(key, plaintext, aad);

        Encoding.UTF8.GetString(cipher.Decrypt(key, frame, aad)).Should().Be("secret");

        var wrongContext = AeadContext.ForKey(KeyScope.Global, "v1", "Ssn");
        var act = () => cipher.Decrypt(key, frame, wrongContext);
        act.Should().Throw<CryptographyException>();
    }
}
