using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Derives field-specific 256-bit keys from a master key using HKDF-SHA256. Inputs are domain-separated
/// (distinct labels for the versioned and unversioned forms) and length-prefixed, so distinct
/// <c>(field, version)</c> tuples can never collide and an embedded delimiter cannot forge another
/// field's key. Deterministic across instances; used by the encryption key providers.
/// </summary>
public static class FieldKeyDerivation
{
    /// <summary>Size of a derived field key, in bytes (256 bits).</summary>
    public const int DerivedKeySize = 32;

    /// <summary>Minimum accepted master-key size, in bytes (256-bit) — matches the platform key size.</summary>
    public const int MinMasterKeySize = 32;

    // A fixed application salt avoids the degenerate all-zero HKDF salt while keeping derivation deterministic.
    private static readonly byte[] ApplicationSalt =
        SHA256.HashData("MillWorks.Cryptography.FieldKeyDerivation"u8);

    /// <summary>Derives an unversioned field key from <paramref name="masterKey"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="fieldName"/> is null or empty.</exception>
    public static byte[] DeriveFieldKey(ReadOnlySpan<byte> masterKey, string fieldName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        return Derive(masterKey, BuildInfo("field-unversioned:"u8, fieldName, version: null));
    }

    /// <summary>Derives a versioned field key from <paramref name="masterKey"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="fieldName"/> or <paramref name="keyVersion"/> is null or empty.</exception>
    public static byte[] DeriveFieldKey(ReadOnlySpan<byte> masterKey, string fieldName, string keyVersion)
    {
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        ArgumentException.ThrowIfNullOrEmpty(keyVersion);
        return Derive(masterKey, BuildInfo("field-versioned:"u8, fieldName, keyVersion));
    }

    private static byte[] Derive(ReadOnlySpan<byte> masterKey, byte[] info)
    {
        if (masterKey.Length < MinMasterKeySize)
        {
            throw new ArgumentException(
                $"Master key must be at least {MinMasterKeySize} bytes (256-bit); got {masterKey.Length}.",
                nameof(masterKey));
        }

        var derived = new byte[DerivedKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, derived, ApplicationSalt, info);
        return derived;
    }

    private static byte[] BuildInfo(ReadOnlySpan<byte> label, string fieldName, string? version)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(label);
        AppendLengthPrefixed(hash, fieldName);
        if (version is not null)
        {
            AppendLengthPrefixed(hash, version);
        }

        return hash.GetHashAndReset();
    }

    private static void AppendLengthPrefixed(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
