namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Immutable metadata about a key version: its identity, lifecycle status, and algorithm.
/// Carries no key material.
/// </summary>
/// <param name="KeyId">Stable identifier of the logical key.</param>
/// <param name="Version">The version of <paramref name="KeyId"/> this descriptor refers to.</param>
/// <param name="Status">Lifecycle status (<see cref="KeyStatus.Active"/> or <see cref="KeyStatus.Retired"/>).</param>
/// <param name="CreatedAt">When this version was created.</param>
/// <param name="Algorithm">The algorithm the key is for (e.g. <c>AES-256-GCM</c>, <c>HMAC-SHA256</c>).</param>
public sealed record KeyDescriptor(
    string KeyId,
    string Version,
    KeyStatus Status,
    DateTimeOffset CreatedAt,
    string Algorithm);
