using System.Text.Json.Serialization;

namespace MillWorks.Cryptography.Signing;

/// <summary>A JWK Set (RFC 7517) — the public signing keys for verifiers to consume.</summary>
public sealed class JwksDocument
{
    /// <summary>The public keys in the set.</summary>
    [JsonPropertyName("keys")]
    public IReadOnlyList<Jwk> Keys { get; init; } = [];
}
