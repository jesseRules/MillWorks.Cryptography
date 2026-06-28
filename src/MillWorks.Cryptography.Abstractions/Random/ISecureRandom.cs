namespace MillWorks.Cryptography.Random;

/// <summary>
/// Source of cryptographically secure random bytes.
/// </summary>
/// <remarks>
/// Modelled as an interface so tests can inject deterministic values (for example, a fixed nonce
/// when checking against published known-answer vectors). Production code uses the OS CSPRNG.
/// </remarks>
public interface ISecureRandom
{
    /// <summary>Fills the entire <paramref name="destination"/> span with secure random bytes.</summary>
    void Fill(Span<byte> destination);

    /// <summary>Returns a new array of <paramref name="count"/> secure random bytes.</summary>
    /// <param name="count">The number of bytes to generate; must be non-negative.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="count"/> is negative.</exception>
    byte[] GetBytes(int count);
}
