namespace MillWorks.Cryptography.KeyManagement;

/// <summary>Lifecycle status of a key version.</summary>
public enum KeyStatus
{
    /// <summary>The current key — new material is produced under it.</summary>
    Active,

    /// <summary>Superseded by rotation, but still resolvable by id to verify or decrypt older data.</summary>
    Retired,
}
