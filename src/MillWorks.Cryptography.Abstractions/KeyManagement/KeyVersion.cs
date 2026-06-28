using System.Globalization;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// The shared key-version convention used by the key-provider backends: <c>v</c> + a UTC timestamp
/// (<c>yyyyMMddHHmmssfff</c>) + 8 lowercase hex characters of randomness. The timestamp gives ordering
/// and a creation time; the random suffix guarantees uniqueness within a millisecond.
/// </summary>
public static class KeyVersion
{
    private const string TimestampFormat = "yyyyMMddHHmmssfff";
    private const int StampLength = 17;

    /// <summary>Generates a fresh version string.</summary>
    public static string New(TimeProvider timeProvider, ISecureRandom secureRandom)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(secureRandom);

        var stamp = timeProvider.GetUtcNow().UtcDateTime.ToString(TimestampFormat, CultureInfo.InvariantCulture);
        return $"v{stamp}{Convert.ToHexStringLower(secureRandom.GetBytes(4))}";
    }

    /// <summary>
    /// Parses the creation time encoded in a version string, or <see cref="DateTimeOffset.MinValue"/> if it
    /// does not carry one in the expected format.
    /// </summary>
    public static DateTimeOffset ParseCreatedAt(string version)
    {
        if (!string.IsNullOrEmpty(version) && version.Length >= 1 + StampLength
            && DateTimeOffset.TryParseExact(
                version.Substring(1, StampLength),
                TimestampFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var created))
        {
            return created;
        }

        return DateTimeOffset.MinValue;
    }
}
