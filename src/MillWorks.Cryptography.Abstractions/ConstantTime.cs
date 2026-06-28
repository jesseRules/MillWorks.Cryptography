using System.Security.Cryptography;
using System.Text;

namespace MillWorks.Cryptography;

/// <summary>
/// Constant-time equality for secrets and MACs, wrapping
/// <see cref="CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>.
/// Consolidates the hand-rolled fixed-time comparers across the platform.
/// </summary>
/// <remarks>
/// <c>FixedTimeEquals</c> is constant-time for equal-length inputs and returns <c>false</c> on a length
/// mismatch. That is the standard, accepted behaviour: in every comparison here (tokens, fixed-width MACs,
/// hash digests) the input length is not the secret, so there is deliberately <b>no</b> artificial
/// "dummy compare" to mask length differences — masking the length with a self-compare consumes time
/// proportional to the wrong operand and closes no real channel, so it is omitted by design.
/// </remarks>
public static class ConstantTime
{
    /// <summary>Compares two byte spans in constant time (for equal-length inputs).</summary>
    public static bool Equals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        => CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>
    /// Compares two strings by their UTF-8 bytes in constant time (for equal-length inputs).
    /// Returns <c>false</c> if either argument is null. Never throws.
    /// </summary>
    /// <remarks>
    /// The decoded byte buffers are zeroed after the comparison. The source <see cref="string"/>s
    /// themselves cannot be zeroed (managed, immutable), so for the strongest secret hygiene compare
    /// raw bytes via <see cref="Equals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>.
    /// </remarks>
    public static bool EqualsUtf8(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }

        var aBytes = Encoding.UTF8.GetBytes(a);
        var bBytes = Encoding.UTF8.GetBytes(b);
        try
        {
            return CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aBytes);
            CryptographicOperations.ZeroMemory(bBytes);
        }
    }

    /// <summary>
    /// Decodes both inputs as standard Base64 and compares the bytes in constant time (for equal-length
    /// decoded inputs). Returns <c>false</c> if either argument is null or not valid Base64. Never throws.
    /// </summary>
    /// <remarks>The decoded byte buffers are zeroed after the comparison.</remarks>
    public static bool EqualsBase64(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }

        byte[]? aBytes = null;
        byte[]? bBytes = null;
        try
        {
            return TryFromBase64(a, out aBytes)
                   && TryFromBase64(b, out bBytes)
                   && CryptographicOperations.FixedTimeEquals(aBytes, bBytes);
        }
        finally
        {
            if (aBytes is not null)
            {
                CryptographicOperations.ZeroMemory(aBytes);
            }

            if (bBytes is not null)
            {
                CryptographicOperations.ZeroMemory(bBytes);
            }
        }
    }

    private static bool TryFromBase64(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
