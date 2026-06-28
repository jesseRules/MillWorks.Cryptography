namespace MillWorks.Cryptography.KeyManagement;

/// <summary>
/// The tenant dimension of a key lookup. <see cref="Global"/> (no tenant) is the default;
/// <see cref="ForTenant"/> scopes resolution to a single tenant. One type, shared by both
/// the signing and encryption key providers.
/// </summary>
public readonly record struct KeyScope
{
    private KeyScope(Guid? tenantId) => TenantId = tenantId;

    /// <summary>The tenant this scope is bound to, or <c>null</c> for the global (non-tenant) ring.</summary>
    public Guid? TenantId { get; }

    /// <summary>The global, non-tenant scope (also the <c>default</c> value).</summary>
    public static KeyScope Global => default;

    /// <summary>A scope bound to a specific tenant.</summary>
    public static KeyScope ForTenant(Guid tenantId) => new(tenantId);

    /// <summary>True when this is the global (non-tenant) scope.</summary>
    public bool IsGlobal => TenantId is null;
}
