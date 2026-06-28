using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// Signs bytes, resolving the active signing key for a scope via the signing key provider. Each
/// implementation produces exactly one <see cref="Algorithm"/>.
/// </summary>
public interface ISigner
{
    /// <summary>The algorithm this signer produces.</summary>
    SignatureAlgorithm Algorithm { get; }

    /// <summary>Signs <paramref name="data"/> with the active key for <paramref name="scope"/>.</summary>
    Task<SignatureEnvelope> SignAsync(
        ReadOnlyMemory<byte> data, KeyScope scope, CancellationToken cancellationToken = default);
}
