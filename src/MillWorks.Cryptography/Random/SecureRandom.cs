using System.Security.Cryptography;

namespace MillWorks.Cryptography.Random;

/// <summary>
/// Default <see cref="ISecureRandom"/> backed by the operating-system CSPRNG
/// (<see cref="RandomNumberGenerator"/>). Stateless and thread-safe.
/// </summary>
public sealed class SecureRandom : ISecureRandom
{
    /// <inheritdoc />
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    /// <inheritdoc />
    public byte[] GetBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        return RandomNumberGenerator.GetBytes(count);
    }
}
