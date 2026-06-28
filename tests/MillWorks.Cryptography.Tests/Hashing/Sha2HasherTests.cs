using System.Security.Cryptography;
using System.Text;
using MillWorks.Cryptography.Hashing;

namespace MillWorks.Cryptography.Tests.Hashing;

[TestFixture]
public sealed class Sha2HasherTests
{
    private static readonly Sha2Hasher Hasher = new();

    // FIPS 180-4 SHA-256 example digests (empty, "abc", and the 448-bit two-block message).
    [TestCase("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [TestCase("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    [TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
    public void Sha256_matches_fips_180_4_vector(string message, string expectedHex)
    {
        ToHexLower(Hasher.Sha256(Encoding.UTF8.GetBytes(message))).Should().Be(expectedHex);
    }

    // FIPS 180-4 SHA-384 example digests (empty, "abc", and the 896-bit two-block message).
    [TestCase("", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")]
    [TestCase("abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")]
    [TestCase("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")]
    public void Sha384_matches_fips_180_4_vector(string message, string expectedHex)
    {
        ToHexLower(Hasher.Sha384(Encoding.UTF8.GetBytes(message))).Should().Be(expectedHex);
    }

    // FIPS 180-4 SHA-512 example digests (empty, "abc", and the 896-bit two-block message).
    [TestCase("",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")]
    [TestCase("abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")]
    [TestCase("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")]
    public void Sha512_matches_fips_180_4_vector(string message, string expectedHex)
    {
        ToHexLower(Hasher.Sha512(Encoding.UTF8.GetBytes(message))).Should().Be(expectedHex);
    }

    [TestCaseSource(nameof(Rfc4231Cases))]
    public void HmacSha256_matches_rfc4231(Rfc4231Case c) =>
        ToHexLower(Hasher.HmacSha256(c.Key, c.Data)).Should().Be(c.Sha256);

    [TestCaseSource(nameof(Rfc4231Cases))]
    public void HmacSha384_matches_rfc4231(Rfc4231Case c) =>
        ToHexLower(Hasher.HmacSha384(c.Key, c.Data)).Should().Be(c.Sha384);

    [TestCaseSource(nameof(Rfc4231Cases))]
    public void HmacSha512_matches_rfc4231(Rfc4231Case c) =>
        ToHexLower(Hasher.HmacSha512(c.Key, c.Data)).Should().Be(c.Sha512);

    [Test]
    public void Sha256_digest_is_32_bytes() => Hasher.Sha256("x"u8).Length.Should().Be(32);

    [Test]
    public void Sha384_digest_is_48_bytes() => Hasher.Sha384("x"u8).Length.Should().Be(48);

    [Test]
    public void Sha512_digest_is_64_bytes() => Hasher.Sha512("x"u8).Length.Should().Be(64);

    [Test]
    public void HmacSha256_digest_is_32_bytes() => Hasher.HmacSha256("key"u8, "message"u8).Length.Should().Be(32);

    [Test]
    public void HmacSha384_digest_is_48_bytes() => Hasher.HmacSha384("key"u8, "message"u8).Length.Should().Be(48);

    [Test]
    public void HmacSha512_digest_is_64_bytes() => Hasher.HmacSha512("key"u8, "message"u8).Length.Should().Be(64);

    [Test]
    public void Sha256_large_input_matches_incremental_chunked()
    {
        var data = new byte[5 * 1024 * 1024]; // 5 MB — well past any single-block path.
        RandomNumberGenerator.Fill(data);

        var oneShot = Hasher.Sha256(data);

        using var incremental = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        const int chunkSize = 64 * 1024;
        for (var offset = 0; offset < data.Length; offset += chunkSize)
        {
            incremental.AppendData(data.AsSpan(offset, Math.Min(chunkSize, data.Length - offset)));
        }

        oneShot.Should().Equal(incremental.GetHashAndReset());
    }

    /// <summary>RFC 4231 §4 HMAC test cases 1–4, with the SHA-256/384/512 expected MACs.</summary>
    private static IEnumerable<Rfc4231Case> Rfc4231Cases()
    {
        yield return new Rfc4231Case("TC1", Repeat(0x0b, 20), Encoding.UTF8.GetBytes("Hi There"),
            Sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            Sha384: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            Sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

        yield return new Rfc4231Case("TC2", Encoding.UTF8.GetBytes("Jefe"),
            Encoding.UTF8.GetBytes("what do ya want for nothing?"),
            Sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            Sha384: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            Sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                    + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");

        yield return new Rfc4231Case("TC3", Repeat(0xaa, 20), Repeat(0xdd, 50),
            Sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            Sha384: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            Sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                    + "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");

        yield return new Rfc4231Case("TC4",
            Convert.FromHexString("0102030405060708090a0b0c0d0e0f10111213141516171819"), Repeat(0xcd, 50),
            Sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            Sha384: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            Sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                    + "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
    }

    private static byte[] Repeat(byte value, int count)
    {
        var bytes = new byte[count];
        Array.Fill(bytes, value);
        return bytes;
    }

    private static string ToHexLower(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public sealed record Rfc4231Case(string Name, byte[] Key, byte[] Data, string Sha256, string Sha384, string Sha512)
    {
        public override string ToString() => Name;
    }
}
