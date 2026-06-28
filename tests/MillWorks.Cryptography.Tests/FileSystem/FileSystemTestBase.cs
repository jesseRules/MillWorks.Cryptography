using System.Security.Cryptography;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.FileSystem;

public abstract class FileSystemTestBase
{
    private string _root = string.Empty;

    protected string Root => _root;

    [SetUp]
    public void SetUpKeyStoreRoot() =>
        _root = Path.Combine(Path.GetTempPath(), "mwcrypto-" + Guid.NewGuid().ToString("N"));

    [TearDown]
    public void CleanUpKeyStoreRoot()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    protected FileSystemKeyProviderOptions Options(bool autoGen = false) => new()
    {
        KeyStorePath = _root,
        MasterKeyBase64 = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        AllowAutoKeyGeneration = autoGen,
    };

    protected static FileEncryptionKeyProvider Encryption(FileSystemKeyProviderOptions options) =>
        new(new AesGcmCipher(new SecureRandom()), new SecureRandom(), TimeProvider.System, options);

    protected static FileSigningKeyProvider Signing(FileSystemKeyProviderOptions options) =>
        new(new AesGcmCipher(new SecureRandom()), new SecureRandom(), TimeProvider.System, options);
}
