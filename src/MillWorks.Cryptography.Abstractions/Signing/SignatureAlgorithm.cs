namespace MillWorks.Cryptography.Signing;

/// <summary>
/// Signature algorithm carried on a <see cref="SignatureEnvelope"/> so verification and rotation are
/// unambiguous (JOSE/COSE-style).
/// </summary>
public enum SignatureAlgorithm
{
    /// <summary>HMAC-SHA-256 (symmetric).</summary>
    HmacSha256,

    /// <summary>RSASSA-PSS over SHA-256 (asymmetric).</summary>
    RsaPssSha256,

    /// <summary>
    /// Ed25519 (EdDSA). Declared for completeness but not built in the core — the .NET BCL does not
    /// expose Ed25519, so it ships as an optional package once a backend is ratified
    /// (see <c>docs/Roadmap-PostV1.md</c>).
    /// </summary>
    Ed25519,
}
