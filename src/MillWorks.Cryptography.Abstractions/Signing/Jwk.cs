using System.Text.Json.Serialization;

namespace MillWorks.Cryptography.Signing;

/// <summary>
/// A JSON Web Key (RFC 7517) carrying a <b>public</b> signing key only. RSA keys populate
/// <see cref="N"/>/<see cref="E"/>; EC keys populate <see cref="Crv"/>/<see cref="X"/>/<see cref="Y"/>;
/// no private parameters are ever represented by this type.
/// </summary>
public sealed class Jwk
{
    /// <summary>Key type, e.g. <c>RSA</c> or <c>EC</c>.</summary>
    [JsonPropertyName("kty")]
    public string Kty { get; init; } = string.Empty;

    /// <summary>Key id (matches the signing key's <c>kid</c>).</summary>
    [JsonPropertyName("kid")]
    public string Kid { get; init; } = string.Empty;

    /// <summary>Intended use; always <c>sig</c> here.</summary>
    [JsonPropertyName("use")]
    public string Use { get; init; } = "sig";

    /// <summary>Algorithm, e.g. <c>PS256</c>.</summary>
    [JsonPropertyName("alg")]
    public string Alg { get; init; } = string.Empty;

    /// <summary>RSA modulus, base64url (public).</summary>
    [JsonPropertyName("n")]
    public string? N { get; init; }

    /// <summary>RSA public exponent, base64url (public).</summary>
    [JsonPropertyName("e")]
    public string? E { get; init; }

    /// <summary>EC curve name, e.g. <c>P-256</c>.</summary>
    [JsonPropertyName("crv")]
    public string? Crv { get; init; }

    /// <summary>EC public key x-coordinate, base64url (public).</summary>
    [JsonPropertyName("x")]
    public string? X { get; init; }

    /// <summary>EC public key y-coordinate, base64url (public).</summary>
    [JsonPropertyName("y")]
    public string? Y { get; init; }
}
