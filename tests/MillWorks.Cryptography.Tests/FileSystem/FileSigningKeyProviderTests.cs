using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.FileSystem;

[TestFixture]
public sealed class FileSigningKeyProviderTests : FileSystemTestBase
{
    [Test]
    public async Task Missing_key_with_autogen_off_fails_closed()
    {
        using var provider = Signing(Options());

        var act = () => provider.GetActiveAsync(KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>();
    }

    [Test]
    public async Task GetActive_returns_descriptor_and_256bit_key()
    {
        using var provider = Signing(Options(autoGen: true));

        var (descriptor, key) = await provider.GetActiveAsync(KeyScope.Global);
        using (key)
        {
            key.Length.Should().Be(32);
            descriptor.Status.Should().Be(KeyStatus.Active);
            descriptor.Algorithm.Should().Be("HMAC-SHA256");
            descriptor.KeyId.Should().Be(descriptor.Version);
            descriptor.CreatedAt.Should().BeAfter(DateTimeOffset.MinValue);
        }
    }

    [Test]
    public async Task GetById_resolves_known_and_returns_null_for_unknown()
    {
        using var provider = Signing(Options());
        var version = (await provider.RotateAsync(KeyScope.Global)).Version;

        using var found = await provider.GetByIdAsync(version, KeyScope.Global);
        found.Should().NotBeNull();
        found!.Length.Should().Be(32);

        (await provider.GetByIdAsync("vDoesNotExist", KeyScope.Global)).Should().BeNull();
    }

    [Test]
    public async Task ListActive_marks_current_active_and_prior_retired()
    {
        using var provider = Signing(Options());
        var v1 = (await provider.RotateAsync(KeyScope.Global)).Version;
        var v2 = (await provider.RotateAsync(KeyScope.Global)).Version;

        var descriptors = await provider.ListActiveAsync(KeyScope.Global);

        descriptors.Should().HaveCount(2);
        descriptors.Single(d => d.Version == v2).Status.Should().Be(KeyStatus.Active);
        descriptors.Single(d => d.Version == v1).Status.Should().Be(KeyStatus.Retired);
    }

    [Test]
    public async Task ListActive_on_empty_scope_is_empty()
    {
        using var provider = Signing(Options());

        (await provider.ListActiveAsync(KeyScope.Global)).Should().BeEmpty();
    }
}
