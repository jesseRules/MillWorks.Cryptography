using System.Security.Cryptography;

namespace MillWorks.Cryptography.Hashing;

/// <summary>
/// SHA-2 / HMAC-SHA-256 implementation of <see cref="IHasher"/> using the BCL one-shot APIs
/// (<c>SHA256.HashData</c>, <c>SHA512.HashData</c>, <c>HMACSHA256.HashData</c>). Stateless and
/// thread-safe; the one-shots stream internally, so they are large-input/LOH-safe.
/// </summary>
public sealed class Sha2Hasher : IHasher
{
    /// <inheritdoc />
    public byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    /// <inheritdoc />
    public byte[] Sha384(ReadOnlySpan<byte> data) => SHA384.HashData(data);

    /// <inheritdoc />
    public byte[] Sha512(ReadOnlySpan<byte> data) => SHA512.HashData(data);

    /// <inheritdoc />
    public byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA256.HashData(key, data);

    /// <inheritdoc />
    public byte[] HmacSha384(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA384.HashData(key, data);

    /// <inheritdoc />
    public byte[] HmacSha512(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data) => HMACSHA512.HashData(key, data);
}
