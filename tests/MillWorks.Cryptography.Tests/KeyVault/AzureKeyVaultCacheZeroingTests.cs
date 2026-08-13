using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.KeyVault;

[TestFixture]
public sealed class AzureKeyVaultCacheZeroingTests
{
    private const string Version = "v1abcdef";

    [Test]
    public async Task Refresh_zeroes_expired_cached_material_without_zeroing_caller_copy()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 8, 13, 12, 0, 0, TimeSpan.Zero));
        var client = new SequentialSecretClient(
            Convert.ToBase64String(Enumerable.Repeat((byte)0x11, 32).ToArray()),
            Convert.ToBase64String(Enumerable.Repeat((byte)0x22, 32).ToArray()));
        using var provider = new AzureKeyVaultEncryptionKeyProvider(
            client, new SecureRandom(), time, TimeSpan.FromMinutes(1));

        using var firstDerived = await provider.GetEncryptionKeyAsync("Email", Version, KeyScope.Global);
        var expiredBuffer = CachedKeyBuffer(provider);
        expiredBuffer.Should().OnlyContain(value => value == 0x11);

        time.Advance(TimeSpan.FromMinutes(2));
        using var secondDerived = await provider.GetEncryptionKeyAsync("Email", Version, KeyScope.Global);

        expiredBuffer.Should().OnlyContain(value => value == 0);
        firstDerived.Span.ToArray().Should().Contain(value => value != 0);
        secondDerived.Span.ToArray().Should().NotEqual(firstDerived.Span.ToArray());
        client.RequestCount.Should().Be(2);
    }

    private static byte[] CachedKeyBuffer(AzureKeyVaultEncryptionKeyProvider provider)
    {
        var store = provider.GetType().GetField("_store", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(provider)!;
        var cache = store.GetType().GetField("_keyCache", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(store)!;
        var values = (IEnumerable)cache.GetType().GetProperty("Values")!.GetValue(cache)!;
        var entry = values.Cast<object>().Single();
        return (byte[])entry.GetType().GetProperty("Value")!.GetValue(entry)!;
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }

    private sealed class SequentialSecretClient(params string[] values) : SecretClient
    {
        private int _requestCount;
        public int RequestCount => Volatile.Read(ref _requestCount);

        public override Task<Response<KeyVaultSecret>> GetSecretAsync(
            string name, string? version = null, SecretContentType? outContentType = null,
            CancellationToken cancellationToken = default)
        {
            var index = Interlocked.Increment(ref _requestCount) - 1;
            return Task.FromResult(Response.FromValue(
                new KeyVaultSecret(name, values[index]), new EmptyResponse()));
        }
    }

    private sealed class EmptyResponse : Response
    {
        public override int Status => 200;
        public override string ReasonPhrase => "OK";
        public override Stream? ContentStream { get; set; }
        public override string ClientRequestId { get; set; } = string.Empty;
        public override void Dispose() { }
        protected override bool ContainsHeader(string name) => false;
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];
        protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
        {
            value = null;
            return false;
        }

        protected override bool TryGetHeaderValues(
            string name, [NotNullWhen(true)] out IEnumerable<string>? values)
        {
            values = null;
            return false;
        }
    }
}
