using System.Diagnostics.CodeAnalysis;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.KeyVault;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.KeyVault;

[TestFixture]
public sealed class AzureKeyVaultCancellationTests
{
    private const string Version = "v1abcdef";

    [Test]
    public async Task Cancelling_one_waiter_does_not_cancel_a_coalesced_key_read()
    {
        var client = new DelayedSecretClient(Convert.ToBase64String(new byte[32]));
        using var provider = new AzureKeyVaultEncryptionKeyProvider(
            client, new SecureRandom(), TimeProvider.System, TimeSpan.FromMinutes(5));
        using var cancellation = new CancellationTokenSource();

        var cancelledWaiter = provider.GetEncryptionKeyAsync(
            "Email", Version, KeyScope.Global, cancellation.Token);
        await client.RequestStarted;

        var successfulWaiter = provider.GetEncryptionKeyAsync("Email", Version, KeyScope.Global);
        cancellation.Cancel();

        var cancelledAct = async () => await cancelledWaiter;
        await cancelledAct.Should().ThrowAsync<OperationCanceledException>();

        client.Release();
        using var key = await successfulWaiter;

        key.Length.Should().Be(32);
        client.RequestCount.Should().Be(1);
        client.RequestCancellationToken.CanBeCanceled.Should().BeFalse();
    }

    private sealed class DelayedSecretClient : SecretClient
    {
        private readonly string _value;
        private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _requestCount;

        public DelayedSecretClient(string value) => _value = value;

        public Task RequestStarted => _started.Task;
        public int RequestCount => Volatile.Read(ref _requestCount);
        public CancellationToken RequestCancellationToken { get; private set; }

        public void Release() => _release.TrySetResult();

        public override async Task<Response<KeyVaultSecret>> GetSecretAsync(
            string name, string? version = null, SecretContentType? outContentType = null,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _requestCount);
            RequestCancellationToken = cancellationToken;
            _started.TrySetResult();
            await _release.Task.ConfigureAwait(false);
            return Response.FromValue(new KeyVaultSecret(name, _value), new EmptyResponse());
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
