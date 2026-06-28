using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.KeyVault;

/// <summary>
/// Round-trip tests against a live Azure Key Vault. Excluded from the default run; set
/// <c>MWCRYPTO_KEYVAULT_URI</c> to a test vault and run explicitly. Each test rotates into a fresh
/// random tenant scope to avoid interfering with other data.
/// </summary>
[TestFixture]
[Explicit("Requires a live Azure Key Vault; set MWCRYPTO_KEYVAULT_URI.")]
[Category("Azure")]
public sealed class AzureKeyVaultProviderExplicitTests
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

    private SecretClient _client = null!;

    [OneTimeSetUp]
    public void SetUp()
    {
        var uri = Environment.GetEnvironmentVariable("MWCRYPTO_KEYVAULT_URI");
        if (string.IsNullOrWhiteSpace(uri))
        {
            Assert.Ignore("MWCRYPTO_KEYVAULT_URI is not set.");
        }

        _client = new SecretClient(new Uri(uri!), new DefaultAzureCredential());
    }

    [Test]
    public async Task Encryption_rotate_then_derive_round_trips()
    {
        using var provider = new AzureKeyVaultEncryptionKeyProvider(_client, new SecureRandom(), TimeProvider.System, CacheTtl);
        var scope = KeyScope.ForTenant(Guid.NewGuid());

        await provider.RotateAsync(scope);
        using var a = await provider.GetEncryptionKeyAsync("Email", scope);
        using var b = await provider.GetEncryptionKeyAsync("Email", scope);

        a.Length.Should().Be(32);
        a.Span.ToArray().Should().Equal(b.Span.ToArray());
    }

    [Test]
    public async Task Signing_rotate_then_get_active_and_by_id()
    {
        using var provider = new AzureKeyVaultSigningKeyProvider(_client, new SecureRandom(), TimeProvider.System, CacheTtl);
        var scope = KeyScope.ForTenant(Guid.NewGuid());

        var rotated = await provider.RotateAsync(scope);
        var (descriptor, key) = await provider.GetActiveAsync(scope);
        using (key)
        {
            descriptor.KeyId.Should().Be(rotated.KeyId);
            key.Length.Should().Be(32);
        }

        using var byId = await provider.GetByIdAsync(rotated.KeyId, scope);
        byId.Should().NotBeNull();
        (await provider.GetByIdAsync("vDoesNotExist", scope)).Should().BeNull();
    }
}
