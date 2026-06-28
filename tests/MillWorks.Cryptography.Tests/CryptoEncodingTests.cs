using System.Security.Cryptography;
using MillWorks.Cryptography;

namespace MillWorks.Cryptography.Tests;

[TestFixture]
public sealed class CryptoEncodingTests
{
    [Test]
    public void ToHexLower_matches_known_vector()
    {
        CryptoEncoding.ToHexLower(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }).Should().Be("deadbeef");
    }

    [Test]
    public void FromHex_is_case_insensitive()
    {
        CryptoEncoding.FromHex("DEADbeef").Should().Equal(0xDE, 0xAD, 0xBE, 0xEF);
    }

    [Test]
    public void Hex_round_trips()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);

        CryptoEncoding.FromHex(CryptoEncoding.ToHexLower(bytes)).Should().Equal(bytes);
    }

    [Test]
    public void ToBase64_matches_known_vector()
    {
        // "Man" -> "TWFu" (the canonical RFC 4648 example).
        CryptoEncoding.ToBase64("Man"u8).Should().Be("TWFu");
    }

    [Test]
    public void Base64_round_trips()
    {
        var bytes = RandomNumberGenerator.GetBytes(48);

        CryptoEncoding.FromBase64(CryptoEncoding.ToBase64(bytes)).Should().Equal(bytes);
    }

    // 0xFB -> standard Base64 "+w==" -> URL-safe "-w"  ('+' becomes '-', padding dropped).
    // {0xFF,0xFF} -> standard "//8=" -> URL-safe "__8"  ('/' becomes '_', padding dropped).
    [TestCase(new byte[] { 0xFB }, "-w")]
    [TestCase(new byte[] { 0xFF, 0xFF }, "__8")]
    public void ToBase64Url_matches_known_vector(byte[] bytes, string expected)
    {
        CryptoEncoding.ToBase64Url(bytes).Should().Be(expected);
    }

    [Test]
    public void Base64Url_output_has_no_padding_or_unsafe_chars()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);

        var encoded = CryptoEncoding.ToBase64Url(bytes);

        encoded.Should().NotContainAny("+", "/", "=");
    }

    [Test]
    public void Base64Url_round_trips()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);

        CryptoEncoding.FromBase64Url(CryptoEncoding.ToBase64Url(bytes)).Should().Equal(bytes);
    }

    [Test]
    public void FromHex_null_throws()
    {
        var act = () => CryptoEncoding.FromHex(null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
