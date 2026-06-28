using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault.Internal;

namespace MillWorks.Cryptography.Tests.KeyVault;

[TestFixture]
public sealed class KeyVaultSecretNamingTests
{
    [Test]
    public void Global_scope_segment_is_global()
    {
        KeyVaultSecretNaming.ScopeSegment(KeyScope.Global).Should().Be("global");
    }

    [Test]
    public void Tenant_scope_segment_is_dash_free_guid()
    {
        var id = Guid.NewGuid();

        KeyVaultSecretNaming.ScopeSegment(KeyScope.ForTenant(id)).Should().Be($"t-{id:N}");
    }

    [Test]
    public void Secret_names_use_only_keyvault_legal_characters()
    {
        var names = new[]
        {
            KeyVaultSecretNaming.KeySecretName("enc", KeyScope.Global, "v20260628120000000abcdef0"),
            KeyVaultSecretNaming.KeySecretName("sig", KeyScope.ForTenant(Guid.NewGuid()), "v20260628120000000abcdef0"),
            KeyVaultSecretNaming.CurrentVersionSecretName("enc", KeyScope.ForTenant(Guid.NewGuid())),
        };

        foreach (var name in names)
        {
            name.Should().MatchRegex("^[0-9a-zA-Z-]+$");
            name.Length.Should().BeLessThanOrEqualTo(127);
        }
    }

    [Test]
    public void Key_secret_name_round_trips_through_extract_version()
    {
        const string version = "v20260628120000000abcdef0";
        var scope = KeyScope.ForTenant(Guid.NewGuid());

        var name = KeyVaultSecretNaming.KeySecretName("enc", scope, version);

        KeyVaultSecretNaming.TryExtractVersion("enc", scope, name).Should().Be(version);
    }

    [Test]
    public void Extract_version_rejects_other_usage_and_scope()
    {
        const string version = "v20260628120000000abcdef0";
        var scope = KeyScope.Global;
        var name = KeyVaultSecretNaming.KeySecretName("enc", scope, version);

        // Different usage and different scope must not match.
        KeyVaultSecretNaming.TryExtractVersion("sig", scope, name).Should().BeNull();
        KeyVaultSecretNaming.TryExtractVersion("enc", KeyScope.ForTenant(Guid.NewGuid()), name).Should().BeNull();
    }

    [Test]
    public void Usage_and_scope_produce_distinct_names()
    {
        var tenant = KeyScope.ForTenant(Guid.NewGuid());

        KeyVaultSecretNaming.KeySecretName("enc", KeyScope.Global, "v1")
            .Should().NotBe(KeyVaultSecretNaming.KeySecretName("sig", KeyScope.Global, "v1"));
        KeyVaultSecretNaming.KeySecretName("enc", KeyScope.Global, "v1")
            .Should().NotBe(KeyVaultSecretNaming.KeySecretName("enc", tenant, "v1"));
    }
}
