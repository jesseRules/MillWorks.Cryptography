using MillWorks.Cryptography.KeyManagement;

namespace MillWorks.Cryptography.KeyVault.Internal;

/// <summary>
/// Maps usage, tenant scope, and version to Azure Key Vault secret names. Key Vault names allow only
/// <c>[0-9a-zA-Z-]</c> (≤ 127 chars), so the tenant is encoded with a dashed, dash-free GUID segment
/// rather than a path. Pure and deterministic.
/// </summary>
internal static class KeyVaultSecretNaming
{
    private const string Prefix = "mwcrypto";

    /// <summary>The scope segment: <c>global</c> or <c>t-{guidN}</c>.</summary>
    public static string ScopeSegment(KeyScope scope) =>
        scope.IsGlobal ? "global" : $"t-{scope.TenantId!.Value:N}";

    /// <summary>Secret name holding the wrapped key for a specific version.</summary>
    public static string KeySecretName(string usage, KeyScope scope, string version) =>
        $"{KeySecretPrefix(usage, scope)}{version}";

    /// <summary>Name prefix shared by all key-version secrets of a usage and scope.</summary>
    public static string KeySecretPrefix(string usage, KeyScope scope) =>
        $"{Prefix}-{usage}-{ScopeSegment(scope)}-key-";

    /// <summary>Secret name holding the current-version pointer for a usage and scope.</summary>
    public static string CurrentVersionSecretName(string usage, KeyScope scope) =>
        $"{Prefix}-{usage}-{ScopeSegment(scope)}-current";

    /// <summary>
    /// Extracts the version from a key secret name, or null if it does not belong to this usage and scope.
    /// </summary>
    public static string? TryExtractVersion(string usage, KeyScope scope, string secretName)
    {
        var prefix = KeySecretPrefix(usage, scope);
        return secretName.StartsWith(prefix, StringComparison.Ordinal)
            ? secretName[prefix.Length..]
            : null;
    }
}
