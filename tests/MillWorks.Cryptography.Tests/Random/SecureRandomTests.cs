using MillWorks.Cryptography.Random;

namespace MillWorks.Cryptography.Tests.Random;

[TestFixture]
public sealed class SecureRandomTests
{
    [Test]
    public void GetBytes_returns_requested_length()
    {
        new SecureRandom().GetBytes(32).Length.Should().Be(32);
    }

    [Test]
    public void GetBytes_zero_returns_empty()
    {
        new SecureRandom().GetBytes(0).Should().BeEmpty();
    }

    [Test]
    public void GetBytes_negative_throws()
    {
        var act = () => new SecureRandom().GetBytes(-1);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Test]
    public void Fill_populates_the_span()
    {
        var buffer = new byte[64];

        new SecureRandom().Fill(buffer);

        // The probability of a 64-byte all-zero draw from a CSPRNG is negligible.
        buffer.Should().Contain(b => b != 0);
    }

    [Test]
    public void Successive_draws_differ()
    {
        var random = new SecureRandom();

        random.GetBytes(32).Should().NotEqual(random.GetBytes(32));
    }
}
