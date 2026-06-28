namespace MillWorks.Cryptography.Aead;

/// <summary>
/// Constants for the single canonical MillWorks AEAD frame:
/// <c>[version:1][nonce:12][tag:16][ciphertext:N]</c>, AES-256-GCM.
/// </summary>
/// <remarks>
/// This is the one format every consumer converges on. There is no legacy-blob compatibility
/// requirement — the format was chosen on merit and the version byte starts at <see cref="Version"/>.
/// </remarks>
public static class AeadFormat
{
    /// <summary>The current frame version — the first byte of every framed value.</summary>
    public const byte Version = 1;

    /// <summary>Size of the version prefix, in bytes.</summary>
    public const int VersionSize = 1;

    /// <summary>AES-GCM nonce size, in bytes (96 bits — the size recommended for GCM).</summary>
    public const int NonceSize = 12;

    /// <summary>AES-GCM authentication tag size, in bytes (128 bits — the maximum).</summary>
    public const int TagSize = 16;

    /// <summary>AES-256 key size, in bytes (256 bits). The cipher accepts no other size.</summary>
    public const int KeySize = 32;

    /// <summary>
    /// The smallest valid frame: version + nonce + tag with an empty ciphertext.
    /// AES-GCM permits a zero-length plaintext, so this is a legal (if unusual) frame.
    /// </summary>
    public const int MinFrameSize = VersionSize + NonceSize + TagSize;
}
