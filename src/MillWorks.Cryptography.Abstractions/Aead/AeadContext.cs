using System.Buffers.Binary;
using System.Text;
using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Aead;

/// <summary>
/// Builds associated-data (AAD) byte strings that bind a ciphertext to its context (key id, tenant,
/// field, record id, …) so it cannot be replayed in a different context (a confused-deputy / swapping
/// attack). Components are length-prefixed, so distinct component sequences can never collide
/// (<c>["ab","c"]</c> ≠ <c>["a","bc"]</c>). Pass the result as the <c>associatedData</c> of
/// <see cref="IAeadCipher"/> and supply the identical context on decrypt.
/// </summary>
public static class AeadContext
{
    /// <summary>Builds AAD from ordered context components, each length-prefixed (4-byte big-endian).</summary>
    /// <exception cref="ArgumentNullException"><paramref name="components"/> or any element is null.</exception>
    public static byte[] Build(params string[] components)
    {
        ArgumentNullException.ThrowIfNull(components);

        var total = 0;
        foreach (var component in components)
        {
            ArgumentNullException.ThrowIfNull(component);
            total += sizeof(int) + Encoding.UTF8.GetByteCount(component);
        }

        var buffer = new byte[total];
        var offset = 0;
        foreach (var component in components)
        {
            var byteCount = Encoding.UTF8.GetBytes(component, buffer.AsSpan(offset + sizeof(int)));
            BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(offset), byteCount);
            offset += sizeof(int) + byteCount;
        }

        return buffer;
    }

    /// <summary>
    /// Builds AAD binding the tenant scope, key version, and field name — the common context for a
    /// field encrypted via <see cref="IEncryptionKeyProvider"/>.
    /// </summary>
    public static byte[] ForKey(KeyScope scope, string keyVersion, string fieldName)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyVersion);
        ArgumentException.ThrowIfNullOrEmpty(fieldName);
        return Build(ScopeToken(scope), keyVersion, fieldName);
    }

    private static string ScopeToken(KeyScope scope) =>
        scope.IsGlobal ? "global" : scope.TenantId!.Value.ToString("N");
}
