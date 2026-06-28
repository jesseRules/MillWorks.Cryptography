using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.TestDoubles;

/// <summary>
/// Deterministic <see cref="ISecureRandom"/> for known-answer tests: hands out a fixed, pre-seeded
/// byte sequence so a chosen nonce can be injected into the cipher. Never shipped — it lives only
/// in the test assembly.
/// </summary>
internal sealed class FixedSecureRandom : ISecureRandom
{
    private readonly byte[] _bytes;
    private int _offset;

    public FixedSecureRandom(byte[] bytes) => _bytes = bytes;

    public void Fill(Span<byte> destination)
    {
        if (_offset + destination.Length > _bytes.Length)
        {
            throw new InvalidOperationException(
                "FixedSecureRandom exhausted: requested more bytes than were seeded.");
        }

        _bytes.AsSpan(_offset, destination.Length).CopyTo(destination);
        _offset += destination.Length;
    }

    public byte[] GetBytes(int count)
    {
        var result = new byte[count];
        Fill(result);
        return result;
    }
}
