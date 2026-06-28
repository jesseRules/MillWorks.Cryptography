namespace MillWorks.Cryptography.Signing;

/// <summary>
/// A detached signature plus the metadata needed to verify it: the algorithm and the id of the key
/// that produced it. The signed bytes are kept separately (this carries only the signature).
/// </summary>
/// <param name="Alg">The signature algorithm.</param>
/// <param name="KeyId">The id (<c>kid</c>) of the signing key — resolvable via the signing key provider.</param>
/// <param name="Value">The raw signature bytes.</param>
public sealed record SignatureEnvelope(SignatureAlgorithm Alg, string KeyId, byte[] Value)
{
    /// <summary>The signature value as standard Base64.</summary>
    public string ValueBase64 => CryptoEncoding.ToBase64(Value);

    /// <summary>Creates an envelope from a Base64-encoded signature value.</summary>
    public static SignatureEnvelope FromBase64(SignatureAlgorithm alg, string keyId, string valueBase64) =>
        new(alg, keyId, CryptoEncoding.FromBase64(valueBase64));
}
