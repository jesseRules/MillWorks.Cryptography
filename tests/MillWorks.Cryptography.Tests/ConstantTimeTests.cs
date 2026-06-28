using System.Text;
using MillWorks.Cryptography;

namespace MillWorks.Cryptography.Tests;

[TestFixture]
public sealed class ConstantTimeTests
{
    [Test]
    public void Equals_true_for_identical_bytes()
    {
        var a = "the-same-secret"u8.ToArray();
        var b = "the-same-secret"u8.ToArray();

        ConstantTime.Equals(a, b).Should().BeTrue();
    }

    [Test]
    public void Equals_false_for_same_length_different_bytes()
    {
        ConstantTime.Equals("secretA"u8, "secretB"u8).Should().BeFalse();
    }

    [Test]
    public void Equals_false_for_different_lengths_without_throwing()
    {
        ConstantTime.Equals("short"u8, "considerably-longer"u8).Should().BeFalse();
    }

    [Test]
    public void Equals_true_for_two_empty_spans()
    {
        ConstantTime.Equals(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty).Should().BeTrue();
    }

    [Test]
    public void EqualsUtf8_true_for_equal_strings()
    {
        ConstantTime.EqualsUtf8("token-value", "token-value").Should().BeTrue();
    }

    [Test]
    public void EqualsUtf8_false_for_different_strings()
    {
        ConstantTime.EqualsUtf8("token-value", "token-other").Should().BeFalse();
    }

    [TestCase(null, "x")]
    [TestCase("x", null)]
    [TestCase(null, null)]
    public void EqualsUtf8_false_when_either_is_null(string? a, string? b)
    {
        ConstantTime.EqualsUtf8(a, b).Should().BeFalse();
    }

    [Test]
    public void EqualsUtf8_false_for_different_lengths()
    {
        ConstantTime.EqualsUtf8("abc", "abcd").Should().BeFalse();
    }

    [Test]
    public void EqualsBase64_true_for_equal_decoded_bytes()
    {
        var b64 = Convert.ToBase64String("payload"u8.ToArray());

        ConstantTime.EqualsBase64(b64, b64).Should().BeTrue();
    }

    [Test]
    public void EqualsBase64_false_for_different_decoded_bytes()
    {
        var a = Convert.ToBase64String("payload-a"u8.ToArray());
        var b = Convert.ToBase64String("payload-b"u8.ToArray());

        ConstantTime.EqualsBase64(a, b).Should().BeFalse();
    }

    [Test]
    public void EqualsBase64_false_for_invalid_base64_without_throwing()
    {
        var valid = Convert.ToBase64String("payload"u8.ToArray());

        ConstantTime.EqualsBase64(valid, "not valid base64!!").Should().BeFalse();
    }

    [TestCase(null, "eA==")]
    [TestCase("eA==", null)]
    public void EqualsBase64_false_when_either_is_null(string? a, string? b)
    {
        ConstantTime.EqualsBase64(a, b).Should().BeFalse();
    }
}
