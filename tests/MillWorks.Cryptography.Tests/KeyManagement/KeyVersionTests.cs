using MillWorks.Cryptography.KeyManagement;
using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.KeyManagement;

[TestFixture]
public sealed class KeyVersionTests
{
    private static readonly SecureRandom Random = new();

    [Test]
    public void New_has_the_expected_shape()
    {
        KeyVersion.New(TimeProvider.System, Random).Should().MatchRegex("^v[0-9]{17}[0-9a-f]{8}$");
    }

    [Test]
    public void ParseCreatedAt_round_trips_the_timestamp()
    {
        var now = new DateTimeOffset(2026, 6, 28, 13, 45, 30, 123, TimeSpan.Zero);

        var version = KeyVersion.New(new FixedTimeProvider(now), Random);

        KeyVersion.ParseCreatedAt(version).Should().Be(now);
    }

    [Test]
    public void ParseCreatedAt_returns_min_value_for_unparseable_input()
    {
        KeyVersion.ParseCreatedAt("not-a-version").Should().Be(DateTimeOffset.MinValue);
    }

    [Test]
    public void Successive_versions_differ_by_their_random_suffix()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 6, 28, 13, 45, 30, 123, TimeSpan.Zero));

        KeyVersion.New(time, Random).Should().NotBe(KeyVersion.New(time, Random));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
