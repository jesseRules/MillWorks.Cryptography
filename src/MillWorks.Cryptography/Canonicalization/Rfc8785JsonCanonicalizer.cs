using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MillWorks.Cryptography.Canonicalization;

/// <summary>
/// RFC 8785 (JSON Canonicalization Scheme) implementation of <see cref="IJsonCanonicalizer"/>.
/// Stateless and thread-safe.
/// </summary>
/// <remarks>
/// Object members are sorted by their name's UTF-16 code units (<c>string.CompareOrdinal</c>),
/// there is no insignificant whitespace, strings use the minimal RFC 8785 §3.2.2.2 escaping, and
/// numbers use the ECMAScript <c>Number::toString</c> serialization (RFC 8785 §3.2.2.3) — which the
/// BCL number formatters do not produce, so it is implemented here explicitly.
/// </remarks>
public sealed class Rfc8785JsonCanonicalizer : IJsonCanonicalizer
{
    /// <inheritdoc />
    public byte[] CanonicalizeToUtf8(JsonElement value)
    {
        var builder = new StringBuilder();
        WriteValue(builder, value);
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    /// <inheritdoc />
    public byte[] CanonicalizeToUtf8(JsonNode? node)
    {
        // Constructed strings can hold unpaired (lone) UTF-16 surrogates. SerializeToDocument would
        // silently replace each with U+FFFD, collapsing distinct invalid inputs to identical bytes —
        // a collision hazard for a value about to be signed/hashed. Reject them before that happens;
        // by the time WriteString runs the surrogate is already gone. Valid pairs are left intact.
        ValidateNoLoneSurrogates(node);

        // SerializeToDocument turns a null node into JSON null and preserves numeric values verbatim.
        using var document = JsonSerializer.SerializeToDocument(node);
        return CanonicalizeToUtf8(document.RootElement);
    }

    // Stack-safety backstop for the pre-serialization walk below. This runs before SerializeToDocument
    // (which enforces its own max depth of 64), so without a bound an adversarial deeply-nested node
    // would StackOverflow here — uncatchable, crashing the process — before the serializer could reject
    // it. Set generously above any real document so it never pre-empts the serializer's depth policy.
    private const int MaxValidationDepth = 1000;

    private static void ValidateNoLoneSurrogates(JsonNode? node) => ValidateNoLoneSurrogates(node, depth: 0);

    private static void ValidateNoLoneSurrogates(JsonNode? node, int depth)
    {
        if (depth > MaxValidationDepth)
        {
            throw new CryptographyException(
                $"Cannot canonicalize a JSON value nested deeper than {MaxValidationDepth} levels.");
        }

        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, value) in obj)
                {
                    ThrowIfLoneSurrogate(name);
                    ValidateNoLoneSurrogates(value, depth + 1);
                }

                break;
            case JsonArray array:
                foreach (var item in array)
                {
                    ValidateNoLoneSurrogates(item, depth + 1);
                }

                break;
            case JsonValue value when value.TryGetValue<string>(out var text):
                ThrowIfLoneSurrogate(text);
                break;
        }
    }

    private static void WriteValue(StringBuilder builder, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(builder, element);
                break;
            case JsonValueKind.Array:
                WriteArray(builder, element);
                break;
            case JsonValueKind.String:
                WriteString(builder, element.GetString()!);
                break;
            case JsonValueKind.Number:
                builder.Append(FormatNumber(element));
                break;
            case JsonValueKind.True:
                builder.Append("true");
                break;
            case JsonValueKind.False:
                builder.Append("false");
                break;
            case JsonValueKind.Null:
                builder.Append("null");
                break;
            default:
                throw new CryptographyException(
                    $"Cannot canonicalize JSON value of kind '{element.ValueKind}'.");
        }
    }

    private static void WriteObject(StringBuilder builder, JsonElement element)
    {
        var members = new List<JsonProperty>();
        foreach (var property in element.EnumerateObject())
        {
            members.Add(property);
        }

        // RFC 8785 §3.2.3: sort by the member name's UTF-16 code units.
        members.Sort(static (a, b) => string.CompareOrdinal(a.Name, b.Name));

        builder.Append('{');
        for (var i = 0; i < members.Count; i++)
        {
            if (i > 0)
            {
                // After sorting, duplicate member names are adjacent. RFC 8785 input must be
                // duplicate-free; rejecting it keeps canonicalization deterministic.
                if (string.Equals(members[i].Name, members[i - 1].Name, StringComparison.Ordinal))
                {
                    throw new CryptographyException(
                        $"Cannot canonicalize an object with a duplicate member name '{members[i].Name}'.");
                }

                builder.Append(',');
            }

            WriteString(builder, members[i].Name);
            builder.Append(':');
            WriteValue(builder, members[i].Value);
        }

        builder.Append('}');
    }

    private static void WriteArray(StringBuilder builder, JsonElement element)
    {
        builder.Append('[');
        var first = true;
        foreach (var item in element.EnumerateArray())
        {
            if (!first)
            {
                builder.Append(',');
            }

            first = false;
            WriteValue(builder, item);
        }

        builder.Append(']');
    }

    /// <summary>RFC 8785 §3.2.2.2 string serialization: minimal escaping, lowercase <c>\u00xx</c>.</summary>
    private static void WriteString(StringBuilder builder, string value)
    {
        // A lone surrogate reaching here would be turned into U+FFFD by the final UTF-8 encoding,
        // silently colliding distinct inputs. Strings arriving via a parsed/serialized JsonElement
        // cannot contain one, but guard the emit boundary regardless so the invariant holds by
        // construction. Valid surrogate pairs pass and are appended (and UTF-8 encoded) verbatim.
        ThrowIfLoneSurrogate(value);

        builder.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                default:
                    if (c < ' ')
                    {
                        builder.Append("\\u");
                        builder.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        // Non-ASCII and other printable characters are kept literal (UTF-8 encoded
                        // at the end). Surrogate pairs are preserved in order and encode correctly.
                        builder.Append(c);
                    }

                    break;
            }
        }

        builder.Append('"');
    }

    /// <summary>
    /// Throws if <paramref name="value"/> contains an unpaired UTF-16 surrogate (a high surrogate not
    /// followed by a low surrogate, or a low surrogate not preceded by a high one). Well-formed pairs
    /// pass. This keeps canonicalization injective: no two distinct strings collapse via U+FFFD.
    /// </summary>
    private static void ThrowIfLoneSurrogate(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                {
                    i++; // consume the paired low surrogate
                    continue;
                }
            }
            else if (!char.IsLowSurrogate(c))
            {
                continue;
            }

            throw new CryptographyException(
                "Cannot canonicalize a string containing an unpaired UTF-16 surrogate: it would be "
                + "silently replaced with U+FFFD, colliding distinct inputs before signing.");
        }
    }

    // Integers up to 2^53 are exactly representable as IEEE-754 doubles; beyond that, the double
    // round-trip used below silently rounds. For a value about to be signed/hashed that is a
    // correctness hazard (distinct ids could collide), so such integers are rejected, not mangled.
    private static readonly BigInteger SafeIntegerLimit = BigInteger.Pow(2, 53);

    /// <summary>
    /// Serializes a JSON number per RFC 8785 §3.2.2.3, but rejects plain integer literals outside the
    /// IEEE-754 safe-integer range rather than emitting a silently-rounded value.
    /// </summary>
    private static string FormatNumber(JsonElement element)
    {
        var raw = element.GetRawText();
        if (IsIntegerLiteral(raw) && BigInteger.Abs(BigInteger.Parse(raw, CultureInfo.InvariantCulture)) > SafeIntegerLimit)
        {
            throw new CryptographyException(
                $"Cannot canonicalize integer '{raw}': it exceeds the IEEE-754 safe-integer range (±2^53) and "
                + "would be silently rounded before signing. Represent large integer ids as JSON strings.");
        }

        return FormatDouble(element.GetDouble());
    }

    private static bool IsIntegerLiteral(string raw) => raw.AsSpan().IndexOfAny('.', 'e', 'E') < 0;

    /// <summary>
    /// Serializes a finite double using the ECMAScript <c>Number::toString</c> algorithm (RFC 8785 §3.2.2.3).
    /// </summary>
    private static string FormatDouble(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
        {
            throw new CryptographyException("RFC 8785 cannot canonicalize a non-finite number (NaN or Infinity).");
        }

        if (value == 0.0)
        {
            return "0"; // covers both +0 and -0
        }

        return value < 0.0 ? "-" + FormatPositive(-value) : FormatPositive(value);
    }

    private static string FormatPositive(double value)
    {
        // .NET Core 3.0+ "R" yields the shortest round-trippable decimal string. Its notation
        // (uppercase 'E', signed/zero-padded exponent, fixed/exponential thresholds) differs from
        // ECMAScript, so normalize to (digits, n) and reformat per the ES6 rules.
        var text = value.ToString("R", CultureInfo.InvariantCulture);

        var exponent = 0;
        var eIndex = text.IndexOf('E');
        var mantissa = text;
        if (eIndex >= 0)
        {
            mantissa = text[..eIndex];
            exponent = int.Parse(text[(eIndex + 1)..], CultureInfo.InvariantCulture);
        }

        string digits;
        int pointPosition; // number of digits to the left of the decimal point
        var dotIndex = mantissa.IndexOf('.');
        if (dotIndex >= 0)
        {
            digits = mantissa[..dotIndex] + mantissa[(dotIndex + 1)..];
            pointPosition = dotIndex;
        }
        else
        {
            digits = mantissa;
            pointPosition = mantissa.Length;
        }

        // n: value == s * 10^(n - k), i.e. the decimal point sits after the n-th digit of 's'.
        var n = pointPosition + exponent;

        var lead = 0;
        while (lead < digits.Length - 1 && digits[lead] == '0')
        {
            lead++;
            n--;
        }

        digits = digits[lead..];

        var endExclusive = digits.Length;
        while (endExclusive > 1 && digits[endExclusive - 1] == '0')
        {
            endExclusive--;
        }

        digits = digits[..endExclusive];
        var k = digits.Length;

        // ECMAScript Number::toString case analysis.
        if (n >= k && n <= 21)
        {
            return digits + new string('0', n - k);
        }

        if (n is > 0 and <= 21)
        {   
            return digits[..n] + "." + digits[n..];
        }

        if (n is > -6 and <= 0)
        {
            return "0." + new string('0', -n) + digits;
        }

        var exp = n - 1;
        var builder = new StringBuilder();
        builder.Append(digits[0]);
        if (k > 1)
        {
            builder.Append('.');
            builder.Append(digits[1..]);
        }

        builder.Append('e');
        builder.Append(exp >= 0 ? '+' : '-');
        builder.Append(Math.Abs(exp).ToString(CultureInfo.InvariantCulture));
        return builder.ToString();
    }
}
