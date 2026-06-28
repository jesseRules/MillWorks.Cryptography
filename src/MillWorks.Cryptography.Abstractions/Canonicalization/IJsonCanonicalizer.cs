using System.Text.Json;
using System.Text.Json.Nodes;

namespace MillWorks.Cryptography.Canonicalization;

/// <summary>
/// Produces the RFC 8785 (JSON Canonicalization Scheme) byte serialization of a JSON value:
/// a single deterministic UTF-8 encoding such that two independent implementations yield
/// byte-identical output for the same input, making signatures and hashes verifiable across
/// languages.
/// </summary>
/// <remarks>
/// This is the byte-level primitive only. Any domain-specific projection — choosing which members
/// to include, omitting null sections, excluding a signature field before signing — is the
/// caller's responsibility and happens before the value reaches this method. RFC 8785 itself
/// preserves explicit <c>null</c> members; this primitive does not drop them.
/// <para>
/// <b>Number range:</b> JCS numbers are IEEE-754 doubles. Rather than silently round a value that is
/// about to be signed, this primitive <b>throws</b> on a plain integer literal whose magnitude exceeds
/// the safe-integer range (2^53). Represent large integer ids (Snowflake ids, bigints, account numbers)
/// as JSON strings before canonicalizing. Object member names must also be unique (RFC 8785 input is
/// duplicate-free); a duplicate name throws.
/// </para>
/// </remarks>
public interface IJsonCanonicalizer
{
    /// <summary>Canonicalizes <paramref name="value"/> to its RFC 8785 UTF-8 byte form.</summary>
    /// <exception cref="CryptographyException">
    /// The value (or a descendant) cannot be canonicalized — for example a non-finite number.
    /// </exception>
    byte[] CanonicalizeToUtf8(JsonElement value);

    /// <summary>Canonicalizes <paramref name="node"/> (a null node is treated as JSON <c>null</c>).</summary>
    /// <exception cref="CryptographyException">
    /// The node (or a descendant) cannot be canonicalized — for example a non-finite number.
    /// </exception>
    byte[] CanonicalizeToUtf8(JsonNode? node);
}
