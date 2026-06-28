using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.KeyManagement;

[TestFixture]
public sealed class FieldKeyDerivationTests
{
    private static readonly byte[] Master = Enumerable.Repeat((byte)0x01, 32).ToArray();

    [Test]
    public void Derived_key_is_32_bytes()
    {
        FieldKeyDerivation.DeriveFieldKey(Master, "Email").Length.Should().Be(FieldKeyDerivation.DerivedKeySize);
    }

    [Test]
    public void Derivation_is_deterministic()
    {
        FieldKeyDerivation.DeriveFieldKey(Master, "Email")
            .Should().Equal(FieldKeyDerivation.DeriveFieldKey(Master, "Email"));
    }

    [Test]
    public void Distinct_fields_derive_distinct_keys()
    {
        FieldKeyDerivation.DeriveFieldKey(Master, "Email")
            .Should().NotEqual(FieldKeyDerivation.DeriveFieldKey(Master, "Ssn"));
    }

    [Test]
    public void Distinct_versions_derive_distinct_keys()
    {
        FieldKeyDerivation.DeriveFieldKey(Master, "Email", "v1")
            .Should().NotEqual(FieldKeyDerivation.DeriveFieldKey(Master, "Email", "v2"));
    }

    [Test]
    public void Versioned_and_unversioned_do_not_collide()
    {
        FieldKeyDerivation.DeriveFieldKey(Master, "Email")
            .Should().NotEqual(FieldKeyDerivation.DeriveFieldKey(Master, "Email", "1"));
    }

    [Test]
    public void Length_prefixing_prevents_field_version_ambiguity()
    {
        // ("ab","c") must not collide with ("a","bc"): the length prefixes disambiguate the boundary.
        FieldKeyDerivation.DeriveFieldKey(Master, "ab", "c")
            .Should().NotEqual(FieldKeyDerivation.DeriveFieldKey(Master, "a", "bc"));
    }

    [Test]
    public void Different_master_keys_derive_distinct_keys()
    {
        var other = Enumerable.Repeat((byte)0x02, 32).ToArray();

        FieldKeyDerivation.DeriveFieldKey(Master, "Email")
            .Should().NotEqual(FieldKeyDerivation.DeriveFieldKey(other, "Email"));
    }

    [Test]
    public void Golden_unversioned_derivation_is_stable()
    {
        // Regression anchor: master = 0x01 × 32, field "Email", unversioned.
        Convert.ToHexString(FieldKeyDerivation.DeriveFieldKey(Master, "Email")).ToLowerInvariant()
            .Should().Be(GoldenEmailKeyHex);
    }

    [Test]
    public void Empty_field_name_throws()
    {
        var act = () => FieldKeyDerivation.DeriveFieldKey(Master, "");

        act.Should().Throw<ArgumentException>();
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(16)]
    [TestCase(31)]
    public void Master_key_below_minimum_size_throws(int size)
    {
        var act = () => FieldKeyDerivation.DeriveFieldKey(new byte[size], "Email");

        act.Should().Throw<ArgumentException>();
    }

    private const string GoldenEmailKeyHex = "4a63b4aebfceb527a4b1845480941619de8a67be64ca4f74aba67f7b86558b81";
}
