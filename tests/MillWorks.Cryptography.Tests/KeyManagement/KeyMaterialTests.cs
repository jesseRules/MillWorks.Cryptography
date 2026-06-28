using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.KeyManagement;

[TestFixture]
public sealed class KeyMaterialTests
{
    [Test]
    public void Span_exposes_the_material()
    {
        using var key = new KeyMaterial([1, 2, 3, 4]);

        key.Span.ToArray().Should().Equal(new byte[] { 1, 2, 3, 4 });
        key.Length.Should().Be(4);
    }

    [Test]
    public void Dispose_zeroes_the_underlying_material()
    {
        var bytes = new byte[] { 9, 8, 7, 6 };
        var key = new KeyMaterial(bytes);

        key.Dispose();

        bytes.Should().OnlyContain(b => b == 0);
    }

    [Test]
    public void Accessing_span_after_dispose_throws()
    {
        var key = new KeyMaterial([1, 2, 3]);
        key.Dispose();

        var act = () => key.Span.ToArray();

        act.Should().Throw<ObjectDisposedException>();
    }

    [Test]
    public void Dispose_is_idempotent()
    {
        var key = new KeyMaterial([1, 2, 3]);
        key.Dispose();

        var act = () => key.Dispose();

        act.Should().NotThrow();
    }

    [Test]
    public void CopyOf_is_independent_of_the_source_buffer()
    {
        var source = new byte[] { 1, 2, 3 };
        using var key = KeyMaterial.CopyOf(source);

        source[0] = 99;

        key.Span.ToArray().Should().Equal(new byte[] { 1, 2, 3 });
    }

    [Test]
    public void Null_material_throws()
    {
        var act = () => new KeyMaterial(null!);

        act.Should().Throw<ArgumentNullException>();
    }
}
