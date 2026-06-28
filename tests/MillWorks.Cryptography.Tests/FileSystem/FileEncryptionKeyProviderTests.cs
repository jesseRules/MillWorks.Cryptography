using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.FileSystem;

[TestFixture]
public sealed class FileEncryptionKeyProviderTests : FileSystemTestBase
{
    [Test]
    public async Task Missing_key_with_autogen_off_fails_closed()
    {
        using var provider = Encryption(Options());

        var act = () => provider.GetCurrentVersionAsync(KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>();
    }

    [Test]
    public async Task Autogen_creates_an_initial_key_on_first_use()
    {
        using var provider = Encryption(Options(autoGen: true));

        using var key = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);

        key.Length.Should().Be(32);
    }

    [Test]
    public async Task Rotate_then_derive_returns_a_256bit_field_key()
    {
        using var provider = Encryption(Options());

        await provider.RotateAsync(KeyScope.Global);
        using var key = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);

        key.Length.Should().Be(32);
    }

    [Test]
    public async Task Same_field_and_version_derive_the_same_key()
    {
        using var provider = Encryption(Options(autoGen: true));

        using var a = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);
        using var b = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);

        a.Span.ToArray().Should().Equal(b.Span.ToArray());
    }

    [Test]
    public async Task Distinct_fields_derive_distinct_keys()
    {
        using var provider = Encryption(Options(autoGen: true));

        using var email = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);
        using var ssn = await provider.GetEncryptionKeyAsync("Ssn", KeyScope.Global);

        email.Span.ToArray().Should().NotEqual(ssn.Span.ToArray());
    }

    [Test]
    public async Task Rotation_advances_current_and_keeps_old_versions_resolvable()
    {
        using var provider = Encryption(Options());

        var v1 = await provider.RotateAsync(KeyScope.Global);
        var v2 = await provider.RotateAsync(KeyScope.Global);

        v2.Should().NotBe(v1);
        (await provider.GetCurrentVersionAsync(KeyScope.Global)).Should().Be(v2);

        using var oldKey = await provider.GetEncryptionKeyAsync("Email", v1, KeyScope.Global);
        oldKey.Length.Should().Be(32);
    }

    [Test]
    public async Task Tampered_key_file_fails_closed()
    {
        var options = Options();
        string version;
        using (var writer = Encryption(options))
        {
            version = await writer.RotateAsync(KeyScope.Global);
        }

        var file = Directory.GetFiles(Root, "key-*.encrypted", SearchOption.AllDirectories).Single();
        var bytes = await File.ReadAllBytesAsync(file);
        bytes[^1] ^= 0xFF;
        await File.WriteAllBytesAsync(file, bytes);

        using var reader = Encryption(options);
        var act = () => reader.GetEncryptionKeyAsync("Email", version, KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>();
    }

    [Test]
    public async Task Path_traversal_version_is_rejected()
    {
        using var provider = Encryption(Options(autoGen: true));
        await provider.RotateAsync(KeyScope.Global);

        var act = () => provider.GetEncryptionKeyAsync("Email", "../../etc/passwd", KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>();
    }
}
