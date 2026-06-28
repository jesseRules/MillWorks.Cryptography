using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.Tests.KeyManagement;

[TestFixture]
public sealed class KeyScopeTests
{
    [Test]
    public void Global_is_not_tenant_scoped()
    {
        KeyScope.Global.IsGlobal.Should().BeTrue();
        KeyScope.Global.TenantId.Should().BeNull();
    }

    [Test]
    public void Default_value_equals_global()
    {
        default(KeyScope).Should().Be(KeyScope.Global);
    }

    [Test]
    public void ForTenant_carries_the_tenant_id()
    {
        var id = Guid.NewGuid();

        var scope = KeyScope.ForTenant(id);

        scope.TenantId.Should().Be(id);
        scope.IsGlobal.Should().BeFalse();
    }

    [Test]
    public void Same_tenant_scopes_are_equal_and_distinct_from_global()
    {
        var id = Guid.NewGuid();

        KeyScope.ForTenant(id).Should().Be(KeyScope.ForTenant(id));
        KeyScope.ForTenant(id).Should().NotBe(KeyScope.Global);
    }

    [Test]
    public void Different_tenant_scopes_are_distinct()
    {
        KeyScope.ForTenant(Guid.NewGuid()).Should().NotBe(KeyScope.ForTenant(Guid.NewGuid()));
    }
}
