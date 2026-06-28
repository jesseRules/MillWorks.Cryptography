namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// Thrown when a key provider cannot resolve, rotate, unwrap, or validate key material — for example
/// an unknown key id, a tamper-failed key file, or a missing backend configuration.
/// </summary>
public sealed class KeyProviderException : CryptographyException
{
    /// <summary>Initializes a new instance of the <see cref="KeyProviderException"/> class.</summary>
    public KeyProviderException()
    {
    }

    /// <summary>Initializes a new instance with the specified message.</summary>
    public KeyProviderException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    public KeyProviderException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
