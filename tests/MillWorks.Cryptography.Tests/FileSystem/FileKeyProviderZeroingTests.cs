using System.Reflection;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.FileSystem;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.FileSystem;

/// <summary>
/// White-box regression for master-key hygiene: the store owns its wrapping master key and must zero it
/// on <see cref="IDisposable.Dispose"/> rather than leaving it resident until GC.
/// </summary>
[TestFixture]
public sealed class FileKeyProviderZeroingTests : FileSystemTestBase
{
    [Test]
    public async Task Dispose_zeroes_the_stored_master_key()
    {
        var masterKey = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var options = new FileSystemKeyProviderOptions
        {
            KeyStorePath = Root,
            MasterKeyBase64 = Convert.ToBase64String(masterKey),
            AllowAutoKeyGeneration = true,
        };

        var provider = new FileEncryptionKeyProvider(
            new AesGcmCipher(new SecureRandom()), new SecureRandom(), TimeProvider.System, options);

        // Exercise the store so the master key has actually been used to unwrap a version key.
        using (await provider.GetEncryptionKeyAsync("Email", KeyScope.Global))
        {
        }

        var stored = StoredMasterKey(provider);
        stored.Should().Equal(masterKey); // held verbatim while the provider is alive

        provider.Dispose();

        stored.Should().OnlyContain(b => b == 0);
    }

    private static byte[] StoredMasterKey(FileEncryptionKeyProvider provider)
    {
        var store = provider.GetType()
            .GetField("_store", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(provider)!;
        return (byte[])store.GetType()
            .GetField("_masterKey", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(store)!;
    }
}
