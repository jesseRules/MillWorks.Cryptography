using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.KeyVault;

/// <summary>
/// Verifies the Key Vault providers fail closed on a secret whose decoded material has an unexpected
/// shape, using a fake <see cref="SecretClient"/> that serves a fixed secret value (no live vault).
/// </summary>
[TestFixture]
public sealed class AzureKeyVaultFailClosedTests
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
    private const string Version = "v1abcdef";

    [Test]
    public async Task Encryption_rejects_a_wrong_length_secret()
    {
        var client = new FixedSecretClient(Convert.ToBase64String(new byte[16])); // 16 bytes, not 32
        using var provider = new AzureKeyVaultEncryptionKeyProvider(client, new SecureRandom(), TimeProvider.System, CacheTtl);

        var act = async () => await provider.GetEncryptionKeyAsync("Email", Version, KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>().WithMessage("*unexpected shape*");
    }

    [Test]
    public async Task Encryption_accepts_a_valid_32_byte_secret()
    {
        var client = new FixedSecretClient(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        using var provider = new AzureKeyVaultEncryptionKeyProvider(client, new SecureRandom(), TimeProvider.System, CacheTtl);

        using var key = await provider.GetEncryptionKeyAsync("Email", Version, KeyScope.Global);

        key.Length.Should().Be(32);
    }

    [Test]
    public async Task Signing_rejects_a_wrong_length_hmac_secret()
    {
        var client = new FixedSecretClient(Convert.ToBase64String(new byte[48])); // 48 bytes, not 32
        using var provider = new AzureKeyVaultSigningKeyProvider(client, new SecureRandom(), TimeProvider.System, CacheTtl);

        var act = async () => await provider.GetByIdAsync(Version, KeyScope.Global);

        await act.Should().ThrowAsync<KeyProviderException>().WithMessage("*unexpected shape*");
    }

    private sealed class FixedSecretClient : SecretClient
    {
        private readonly string _value;

        public FixedSecretClient(string value) => _value = value;

        // The store binds to the four-argument overload (the three-argument one has no default for
        // version); override both so the fake is robust regardless of which is called.
        public override Task<Response<KeyVaultSecret>> GetSecretAsync(
            string name, string? version, CancellationToken cancellationToken = default) =>
            Serve(name);

        public override Task<Response<KeyVaultSecret>> GetSecretAsync(
            string name, string? version = null, SecretContentType? outContentType = null,
            CancellationToken cancellationToken = default) =>
            Serve(name);

        private Task<Response<KeyVaultSecret>> Serve(string name) =>
            Task.FromResult(Response.FromValue(new KeyVaultSecret(name, _value), new EmptyResponse()));
    }

    private sealed class EmptyResponse : Response
    {
        public override int Status => 200;
        public override string ReasonPhrase => "OK";
        public override System.IO.Stream? ContentStream { get; set; }
        public override string ClientRequestId { get; set; } = string.Empty;
        public override void Dispose() { }
        protected override bool ContainsHeader(string name) => false;
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => Array.Empty<HttpHeader>();
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
        {
            value = null;
            return false;
        }

        protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
        {
            values = null;
            return false;
        }
    }
}
