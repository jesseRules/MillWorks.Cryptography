namespace MillWorks.Cryptography;

/// <summary>
/// Thrown when a MillWorks cryptographic primitive rejects its input or fails a verification:
/// for example a wrong key size, a malformed or truncated frame, an unrecognised version byte, or
/// a failed authentication tag. Carries no plaintext or key material in its message.
/// </summary>
public class CryptographyException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="CryptographyException"/> class.</summary>
    public CryptographyException()
    {
    }

    /// <summary>Initializes a new instance with the specified message.</summary>
    public CryptographyException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    public CryptographyException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
