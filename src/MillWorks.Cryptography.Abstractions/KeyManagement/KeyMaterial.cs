using System.Security.Cryptography;

namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Owns a block of secret key bytes and zeroes them on <see cref="Dispose"/>. Callers should keep
/// the lifetime as short as possible (use it inside a <c>using</c>) and never copy the bytes out
/// except into another zeroing owner.
/// </summary>
/// <remarks>
/// Zeroization is <b>best-effort</b>: the managed garbage collector may relocate (copy) the backing
/// array before <see cref="Dispose"/> runs, so residual copies can remain in memory. This reduces, but
/// does not guarantee elimination of, a secret's lifetime in the managed heap.
/// </remarks>
public sealed class KeyMaterial : IDisposable
{
    private readonly byte[] _material;
    private volatile bool _disposed;

    /// <summary>Takes ownership of <paramref name="material"/>; it is zeroed when this instance is disposed.</summary>
    public KeyMaterial(byte[] material)
    {
        ArgumentNullException.ThrowIfNull(material);
        _material = material;
    }

    /// <summary>Creates a key from a copy of <paramref name="material"/>, independent of the source buffer.</summary>
    public static KeyMaterial CopyOf(ReadOnlySpan<byte> material) => new(material.ToArray());

    /// <summary>The number of key bytes.</summary>
    public int Length => _material.Length;

    /// <summary>The key bytes. Throws once the instance has been disposed.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _material;
        }
    }

    /// <summary>The key bytes as memory. Throws once the instance has been disposed.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public ReadOnlyMemory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _material;
        }
    }

    /// <summary>Zeroes the key bytes. Idempotent.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_material);
    }
}
