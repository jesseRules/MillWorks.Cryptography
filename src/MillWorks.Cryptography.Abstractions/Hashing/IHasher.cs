namespace MillWorks.Cryptography.Hashing;

/// <summary>
/// Raw byte hashing (SHA-2 family) and HMAC-SHA-256.
/// </summary>
/// <remarks>
/// This surface deals only in bytes; encoding a digest to text (hex/base64) is a separate concern
/// handled by the encoding helpers. Composite hashing of multiple fields (length-prefixing,
/// canonical projection) is domain logic that belongs to the consumer, not here.
/// </remarks>
public interface IHasher
{
    /// <summary>Computes the SHA-256 digest (32 bytes) of <paramref name="data"/>.</summary>
    byte[] Sha256(ReadOnlySpan<byte> data);

    /// <summary>Computes the SHA-384 digest (48 bytes) of <paramref name="data"/>.</summary>
    byte[] Sha384(ReadOnlySpan<byte> data);

    /// <summary>Computes the SHA-512 digest (64 bytes) of <paramref name="data"/>.</summary>
    byte[] Sha512(ReadOnlySpan<byte> data);

    /// <summary>
    /// Computes the HMAC-SHA-256 (32 bytes) of <paramref name="data"/> under <paramref name="key"/>.
    /// </summary>
    byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);

    /// <summary>
    /// Computes the HMAC-SHA-384 (48 bytes) of <paramref name="data"/> under <paramref name="key"/>.
    /// </summary>
    byte[] HmacSha384(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);

    /// <summary>
    /// Computes the HMAC-SHA-512 (64 bytes) of <paramref name="data"/> under <paramref name="key"/>.
    /// </summary>
    byte[] HmacSha512(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);
}
