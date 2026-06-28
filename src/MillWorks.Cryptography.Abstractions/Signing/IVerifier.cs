using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// Verifies a <see cref="SignatureEnvelope"/> against the signed bytes, resolving the key named by the
/// envelope via the signing key provider. Returns <c>false</c> (never throws) for an unknown key,
/// an algorithm it does not handle, or a failed signature.
/// </summary>
public interface IVerifier
{
    /// <summary>Verifies <paramref name="signature"/> over <paramref name="data"/> within <paramref name="scope"/>.</summary>
    Task<bool> VerifyAsync(
        ReadOnlyMemory<byte> data,
        SignatureEnvelope signature,
        KeyScope scope,
        CancellationToken cancellationToken = default);
}
