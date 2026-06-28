namespace MillWorks.Cryptography.Aead;

/// <summary>
/// Authenticated encryption with associated data (AEAD), AES-256-GCM, over the canonical
/// <see cref="AeadFormat"/> frame. The key is supplied per call; this primitive holds no key
/// material and no domain logic.
/// </summary>
/// <remarks>
/// A fresh random 96-bit nonce is generated per <see cref="Encrypt"/> call and the cipher holds no
/// per-key counter, so it cannot bound nonce reuse on its own. Per NIST SP 800-38D, rotate the key
/// well before ~2^32 encryptions under it (tie key rotation to this bound), beyond which the
/// birthday-bound probability of a random 96-bit nonce collision (which would break AES-GCM's
/// confidentiality and integrity) is no longer negligible.
/// <para>
/// This is <b>one-shot</b> AEAD: the whole plaintext is held in memory and no plaintext is released
/// until the tag verifies — it is not a streaming/chunked construction, so do not use it for very
/// large payloads. It is also <b>not key-committing</b> (a frame can verify under more than one key);
/// that is fine for single-key field encryption but not for password-derived or multi-recipient keys.
/// Bind key id / tenant / field into the associated data to prevent cross-context ciphertext reuse.
/// </para>
/// </remarks>
public interface IAeadCipher
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> under <paramref name="key"/> and returns the framed
    /// value <c>[version:1][nonce:12][tag:16][ciphertext]</c>. A fresh random nonce is generated
    /// for every call, so encrypting the same plaintext twice yields different frames.
    /// </summary>
    /// <param name="key">The AES-256 key — exactly <see cref="AeadFormat.KeySize"/> bytes.</param>
    /// <param name="plaintext">The data to encrypt. May be empty.</param>
    /// <param name="associatedData">
    /// Optional additional authenticated data: authenticated but not encrypted, and not stored in
    /// the frame. The identical value must be supplied to <see cref="Decrypt"/>.
    /// </param>
    /// <returns>The framed ciphertext as a new byte array.</returns>
    /// <exception cref="CryptographyException">The key size is not <see cref="AeadFormat.KeySize"/>.</exception>
    byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Verifies and decrypts a framed value produced by <see cref="Encrypt"/>.
    /// </summary>
    /// <param name="key">The AES-256 key — exactly <see cref="AeadFormat.KeySize"/> bytes.</param>
    /// <param name="framed">The framed value <c>[version:1][nonce:12][tag:16][ciphertext]</c>.</param>
    /// <param name="associatedData">The same associated data that was supplied to <see cref="Encrypt"/>.</param>
    /// <returns>The recovered plaintext as a new byte array.</returns>
    /// <exception cref="CryptographyException">
    /// The key size is wrong, the frame is malformed or truncated, the version byte is unrecognised,
    /// or authentication fails (wrong key, wrong associated data, or tampering).
    /// </exception>
    byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> framed, ReadOnlySpan<byte> associatedData = default);
}
