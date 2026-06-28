using System.Security.Cryptography;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Aead;

/// <summary>
/// AES-256-GCM implementation of <see cref="IAeadCipher"/> over the canonical
/// <see cref="AeadFormat"/> frame.
/// </summary>
/// <remarks>
/// Stateless and thread-safe: a fresh <see cref="AesGcm"/> instance is created per call, since
/// <see cref="AesGcm"/> is not documented as thread-safe. The frame is written into a single
/// allocation: <c>[version:1][nonce:12][tag:16][ciphertext:N]</c>.
/// </remarks>
public sealed class AesGcmCipher : IAeadCipher
{
    private readonly ISecureRandom _secureRandom;

    /// <summary>Creates the cipher using <paramref name="secureRandom"/> as its nonce source.</summary>
    public AesGcmCipher(ISecureRandom secureRandom)
    {
        ArgumentNullException.ThrowIfNull(secureRandom);
        _secureRandom = secureRandom;
    }

    /// <inheritdoc />
    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        RequireKeySize(key);

        // Single allocation: [version:1][nonce:12][tag:16][ciphertext:N].
        var frame = new byte[AeadFormat.MinFrameSize + plaintext.Length];
        frame[0] = AeadFormat.Version;

        var nonce = frame.AsSpan(AeadFormat.VersionSize, AeadFormat.NonceSize);
        var tag = frame.AsSpan(AeadFormat.VersionSize + AeadFormat.NonceSize, AeadFormat.TagSize);
        var ciphertext = frame.AsSpan(AeadFormat.MinFrameSize);

        _secureRandom.Fill(nonce);

        using var aesGcm = new AesGcm(key, AeadFormat.TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return frame;
    }

    /// <inheritdoc />
    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> framed, ReadOnlySpan<byte> associatedData = default)
    {
        RequireKeySize(key);

        if (framed.Length < AeadFormat.MinFrameSize)
        {
            throw new CryptographyException(
                $"AEAD frame is too short: expected at least {AeadFormat.MinFrameSize} bytes, got {framed.Length}.");
        }

        var version = framed[0];
        if (version != AeadFormat.Version)
        {
            throw new CryptographyException(
                $"Unsupported AEAD frame version: {version}. Expected {AeadFormat.Version}.");
        }

        var nonce = framed.Slice(AeadFormat.VersionSize, AeadFormat.NonceSize);
        var tag = framed.Slice(AeadFormat.VersionSize + AeadFormat.NonceSize, AeadFormat.TagSize);
        var ciphertext = framed[AeadFormat.MinFrameSize..];

        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aesGcm = new AesGcm(key, AeadFormat.TagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            // Defence in depth: clear the destination before surfacing the failure. (The BCL also
            // clears it on a tag mismatch, but the buffer is ours and we own its lifetime here.)
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographyException(
                "AEAD authentication failed: wrong key or associated data, or the data was tampered with.", ex);
        }

        return plaintext;
    }

    private static void RequireKeySize(ReadOnlySpan<byte> key)
    {
        if (key.Length != AeadFormat.KeySize)
        {
            throw new CryptographyException(
                $"AES-256-GCM requires a {AeadFormat.KeySize}-byte key; got {key.Length} bytes.");
        }
    }
}
