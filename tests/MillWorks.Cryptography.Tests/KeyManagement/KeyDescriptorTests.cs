using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.KeyManagement;

[TestFixture]
public sealed class KeyDescriptorTests
{
    [Test]
    public void Descriptors_with_the_same_values_are_equal()
    {
        var at = DateTimeOffset.UnixEpoch;

        var a = new KeyDescriptor("k1", "v1", KeyStatus.Active, at, "AES-256-GCM");
        var b = new KeyDescriptor("k1", "v1", KeyStatus.Active, at, "AES-256-GCM");

        a.Should().Be(b);
    }

    [Test]
    public void Descriptor_exposes_its_components()
    {
        var at = DateTimeOffset.UnixEpoch;

        var descriptor = new KeyDescriptor("k1", "v2", KeyStatus.Retired, at, "HMAC-SHA256");

        descriptor.KeyId.Should().Be("k1");
        descriptor.Version.Should().Be("v2");
        descriptor.Status.Should().Be(KeyStatus.Retired);
        descriptor.CreatedAt.Should().Be(at);
        descriptor.Algorithm.Should().Be("HMAC-SHA256");
    }
}
