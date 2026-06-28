using System.Buffers.Text;

namespace MillWorks.Cryptography;

/// <summary>
/// Encoding helpers for cryptographic byte material: lowercase hex, standard Base64, and URL-safe
/// Base64 (no padding). Pure and allocation-light — there is no reason to make these swappable, so
/// they are static rather than an interface. Consolidates the scattered
/// <c>Convert.ToHexString().ToLowerInvariant()</c> and Base64-URL call sites across the platform.
/// </summary>
public static class CryptoEncoding
{
    /// <summary>Encodes <paramref name="bytes"/> as a lowercase hex string.</summary>
    public static string ToHexLower(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>Decodes a hex string (either case) to bytes.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="hex"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="hex"/> is not valid hex.</exception>
    public static byte[] FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return Convert.FromHexString(hex);
    }

    /// <summary>Encodes <paramref name="bytes"/> as standard Base64.</summary>
    public static string ToBase64(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes);

    /// <summary>Decodes a standard Base64 string to bytes.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="base64"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="base64"/> is not valid Base64.</exception>
    public static byte[] FromBase64(string base64)
    {
        ArgumentNullException.ThrowIfNull(base64);
        return Convert.FromBase64String(base64);
    }

    /// <summary>Encodes <paramref name="bytes"/> as URL-safe Base64 with no padding (RFC 4648 §5).</summary>
    public static string ToBase64Url(ReadOnlySpan<byte> bytes) => Base64Url.EncodeToString(bytes);

    /// <summary>Decodes a URL-safe Base64 string (padding optional) to bytes.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="base64Url"/> is null.</exception>
    /// <exception cref="FormatException"><paramref name="base64Url"/> is not valid URL-safe Base64.</exception>
    public static byte[] FromBase64Url(string base64Url)
    {
        ArgumentNullException.ThrowIfNull(base64Url);
        return Base64Url.DecodeFromChars(base64Url);
    }
}
