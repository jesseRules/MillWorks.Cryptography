using System.Security.Cryptography;
using MillWorks.Cryptography;
using MillWorks.Cryptography.Aead;
using MillWorks.Cryptography.Random;
using MillWorks.Cryptography.Tests.TestDoubles;

namespace MillWorks.Cryptography.Tests.Aead;

[TestFixture]
public sealed class AesGcmCipherTests
{
    /// <summary>
    /// Published AES-256-GCM known-answer vectors from the GCM specification (McGrew &amp; Viega,
    /// "The Galois/Counter Mode of Operation (GCM)", Appendix B — the NIST-referenced test cases),
    /// restricted to test cases 13–16, which use a 96-bit (12-byte) IV matching the canonical frame.
    /// </summary>
    private static readonly GcmVector[] PublishedVectors =
    [
        // Test case 13 — 256-bit key, empty plaintext, no AAD.
        new(
            Name: "TC13/256/empty",
            KeyHex: "0000000000000000000000000000000000000000000000000000000000000000",
            NonceHex: "000000000000000000000000",
            PlaintextHex: "",
            AadHex: "",
            CiphertextHex: "",
            TagHex: "530f8afbc74536b9a963b4f1c4cb738b"),

        // Test case 14 — 256-bit key, one block of zeros, no AAD.
        new(
            Name: "TC14/256/16B",
            KeyHex: "0000000000000000000000000000000000000000000000000000000000000000",
            NonceHex: "000000000000000000000000",
            PlaintextHex: "00000000000000000000000000000000",
            AadHex: "",
            CiphertextHex: "cea7403d4d606b6e074ec5d3baf39d18",
            TagHex: "d0d1c8a799996bf0265b98b5d48ab919"),

        // Test case 15 — 256-bit key, 64-byte plaintext, no AAD.
        new(
            Name: "TC15/256/64B/no-aad",
            KeyHex: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            NonceHex: "cafebabefacedbaddecaf888",
            PlaintextHex: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                          + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            AadHex: "",
            CiphertextHex: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                           + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            TagHex: "b094dac5d93471bdec1a502270e3cc6c"),

        // Test case 16 — 256-bit key, 60-byte plaintext, 20-byte AAD.
        new(
            Name: "TC16/256/60B/aad",
            KeyHex: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            NonceHex: "cafebabefacedbaddecaf888",
            PlaintextHex: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                          + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            AadHex: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            CiphertextHex: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                           + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            TagHex: "76fc6ece0f4e1768cddf8853bb2d551b"),
    ];

    [TestCaseSource(nameof(PublishedVectors))]
    public void Encrypt_produces_published_ciphertext_and_tag(GcmVector v)
    {
        var key = Convert.FromHexString(v.KeyHex);
        var nonce = Convert.FromHexString(v.NonceHex);
        var plaintext = Convert.FromHexString(v.PlaintextHex);
        var aad = Convert.FromHexString(v.AadHex);
        var expectedCt = Convert.FromHexString(v.CiphertextHex);
        var expectedTag = Convert.FromHexString(v.TagHex);

        // Inject the published nonce so Encrypt reproduces the exact frame for the vector.
        var cipher = new AesGcmCipher(new FixedSecureRandom(nonce));
        var frame = cipher.Encrypt(key, plaintext, aad);

        // Frame layout: [version:1][nonce:12][tag:16][ciphertext].
        frame[0].Should().Be(AeadFormat.Version);
        frame.AsSpan(1, AeadFormat.NonceSize).ToArray().Should().Equal(nonce);
        frame.AsSpan(1 + AeadFormat.NonceSize, AeadFormat.TagSize).ToArray().Should().Equal(expectedTag);
        frame.AsSpan(AeadFormat.MinFrameSize).ToArray().Should().Equal(expectedCt);
    }

    [TestCaseSource(nameof(PublishedVectors))]
    public void Decrypt_recovers_plaintext_for_published_vector(GcmVector v)
    {
        var key = Convert.FromHexString(v.KeyHex);
        var nonce = Convert.FromHexString(v.NonceHex);
        var aad = Convert.FromHexString(v.AadHex);
        var expectedPt = Convert.FromHexString(v.PlaintextHex);
        var frame = BuildFrame(nonce, Convert.FromHexString(v.TagHex), Convert.FromHexString(v.CiphertextHex));

        var recovered = RealCipher().Decrypt(key, frame, aad);

        recovered.Should().Equal(expectedPt);
    }

    [Test]
    public void Encrypt_then_decrypt_round_trips()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var plaintext = "the quick brown fox jumps over the lazy dog"u8.ToArray();
        var cipher = RealCipher();

        var recovered = cipher.Decrypt(key, cipher.Encrypt(key, plaintext));

        recovered.Should().Equal(plaintext);
    }

    [Test]
    public void Round_trips_with_associated_data()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var pt = "secret payload"u8.ToArray();
        var aad = "context-header-v1"u8.ToArray();
        var cipher = RealCipher();

        cipher.Decrypt(key, cipher.Encrypt(key, pt, aad), aad).Should().Equal(pt);
    }

    [Test]
    public void Decrypt_with_wrong_associated_data_throws()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var frame = cipher.Encrypt(key, "secret"u8.ToArray(), "aad-a"u8.ToArray());

        var act = () => cipher.Decrypt(key, frame, "aad-b"u8.ToArray());

        act.Should().Throw<CryptographyException>();
    }

    [Test]
    public void Decrypt_with_wrong_key_throws()
    {
        var cipher = RealCipher();
        var frame = cipher.Encrypt(RandomNumberGenerator.GetBytes(AeadFormat.KeySize), "secret"u8.ToArray());

        var act = () => cipher.Decrypt(RandomNumberGenerator.GetBytes(AeadFormat.KeySize), frame);

        act.Should().Throw<CryptographyException>();
    }

    [Test]
    public void Decrypt_with_tampered_tag_throws()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var frame = cipher.Encrypt(key, "secret"u8.ToArray());
        frame[1 + AeadFormat.NonceSize] ^= 0xFF; // flip the first tag byte

        var act = () => cipher.Decrypt(key, frame);

        act.Should().Throw<CryptographyException>();
    }

    [Test]
    public void Decrypt_with_tampered_ciphertext_throws()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var frame = cipher.Encrypt(key, "0123456789"u8.ToArray());
        frame[^1] ^= 0xFF; // flip the last ciphertext byte

        var act = () => cipher.Decrypt(key, frame);

        act.Should().Throw<CryptographyException>();
    }

    [TestCase(0)]
    [TestCase(16)]
    [TestCase(24)]
    [TestCase(31)]
    [TestCase(33)]
    [TestCase(64)]
    public void Encrypt_with_non_256bit_key_throws(int keySize)
    {
        var act = () => RealCipher().Encrypt(new byte[keySize], "x"u8.ToArray());

        act.Should().Throw<CryptographyException>();
    }

    [Test]
    public void Decrypt_with_non_256bit_key_throws()
    {
        var act = () => RealCipher().Decrypt(new byte[16], new byte[AeadFormat.MinFrameSize]);

        act.Should().Throw<CryptographyException>();
    }

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(AeadFormat.MinFrameSize - 1)]
    public void Decrypt_with_truncated_frame_throws(int frameLength)
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);

        var act = () => RealCipher().Decrypt(key, new byte[frameLength]);

        act.Should().Throw<CryptographyException>();
    }

    [Test]
    public void Decrypt_with_unsupported_version_throws()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var frame = cipher.Encrypt(key, "x"u8.ToArray());
        frame[0] = 0x09; // unknown version

        var act = () => cipher.Decrypt(key, frame);

        act.Should().Throw<CryptographyException>().WithMessage("*version*");
    }

    [Test]
    public void Empty_plaintext_yields_min_size_frame_and_round_trips()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();

        var frame = cipher.Encrypt(key, ReadOnlySpan<byte>.Empty);

        frame.Length.Should().Be(AeadFormat.MinFrameSize);
        cipher.Decrypt(key, frame).Should().BeEmpty();
    }

    [Test]
    public void Nonce_never_repeats_across_encryptions()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var pt = "same-plaintext"u8.ToArray();

        var nonces = new HashSet<string>();
        for (var i = 0; i < 2048; i++)
        {
            var frame = cipher.Encrypt(key, pt);
            var nonce = Convert.ToHexString(frame.AsSpan(1, AeadFormat.NonceSize));
            nonces.Add(nonce).Should().BeTrue("a fresh nonce must be drawn for every encryption");
        }
    }

    [Test]
    public void Same_plaintext_encrypts_to_different_frames()
    {
        var key = RandomNumberGenerator.GetBytes(AeadFormat.KeySize);
        var cipher = RealCipher();
        var pt = "deterministic-input"u8.ToArray();

        cipher.Encrypt(key, pt).Should().NotEqual(cipher.Encrypt(key, pt));
    }

    [Test]
    public void Constructor_rejects_null_secure_random()
    {
        var act = () => new AesGcmCipher(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    private static AesGcmCipher RealCipher() => new(new SecureRandom());

    private static byte[] BuildFrame(byte[] nonce, byte[] tag, byte[] ciphertext)
    {
        var frame = new byte[AeadFormat.VersionSize + nonce.Length + tag.Length + ciphertext.Length];
        frame[0] = AeadFormat.Version;
        nonce.CopyTo(frame, AeadFormat.VersionSize);
        tag.CopyTo(frame, AeadFormat.VersionSize + nonce.Length);
        ciphertext.CopyTo(frame, AeadFormat.VersionSize + nonce.Length + tag.Length);
        return frame;
    }

    public sealed record GcmVector(
        string Name,
        string KeyHex,
        string NonceHex,
        string PlaintextHex,
        string AadHex,
        string CiphertextHex,
        string TagHex)
    {
        // NUnit uses ToString() for the test-case label; keep it to the short vector name.
        public override string ToString() => Name;
    }
}
