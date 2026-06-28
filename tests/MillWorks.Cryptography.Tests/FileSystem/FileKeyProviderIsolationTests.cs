using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.FileSystem;

[TestFixture]
public sealed class FileKeyProviderIsolationTests : FileSystemTestBase
{
    [Test]
    public async Task Signing_provider_cannot_resolve_an_encryption_key_id()
    {
        var options = Options(autoGen: true);
        using var encryption = Encryption(options);
        using var signing = Signing(options);

        // Both share the same root and master key, but live in disjoint usage namespaces.
        var encryptionVersion = await encryption.RotateAsync(KeyScope.Global);
        var (_, signingKey) = await signing.GetActiveAsync(KeyScope.Global);
        using (signingKey)
        {
            (await signing.GetByIdAsync(encryptionVersion, KeyScope.Global)).Should().BeNull();
        }
    }

    [Test]
    public async Task Tenant_scopes_are_isolated_and_fail_closed_across_tenants()
    {
        var options = Options(); // auto-generation off
        using var provider = Encryption(options);
        var tenantA = KeyScope.ForTenant(Guid.NewGuid());

        await provider.RotateAsync(tenantA);

        (await provider.GetCurrentVersionAsync(tenantA)).Should().NotBeNullOrEmpty();

        var otherTenant = () => provider.GetCurrentVersionAsync(KeyScope.ForTenant(Guid.NewGuid()));
        await otherTenant.Should().ThrowAsync<KeyProviderException>();

        var global = () => provider.GetCurrentVersionAsync(KeyScope.Global);
        await global.Should().ThrowAsync<KeyProviderException>();
    }

    [Test]
    public async Task Same_tenant_resolves_its_own_key_distinct_from_global()
    {
        var options = Options(autoGen: true);
        using var provider = Encryption(options);
        var tenant = KeyScope.ForTenant(Guid.NewGuid());

        using var tenantKey = await provider.GetEncryptionKeyAsync("Email", tenant);
        using var globalKey = await provider.GetEncryptionKeyAsync("Email", KeyScope.Global);

        tenantKey.Span.ToArray().Should().NotEqual(globalKey.Span.ToArray());
    }
}
