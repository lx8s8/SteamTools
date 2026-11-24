using BD.WTTS.Enums;
using BD.WTTS.Helpers;
using System.Text;
using WinAuth;

namespace BD.WTTS.UnitTest;

public sealed class AuthenticatorImportTest
{
    [TestCase(10, 0)]
    [TestCase(16, 6)]
    [TestCase(17, 4)]
    [TestCase(18, 3)]
    [TestCase(19, 1)]
    [TestCase(32, 4)]
    public void Base32AcceptsBothRepresentations(int byteCount, int padding)
    {
        var secret = Enumerable.Range(1, byteCount).Select(i => (byte)i).ToArray();
        var encoded = Base32.GetInstance().Encode(secret);
        var padded = encoded + new string('=', padding);

        Assert.That(AuthenticatorRegexHelper.TryDecodeBase32(encoded, out var fromUnpadded), Is.True);
        Assert.That(AuthenticatorRegexHelper.TryDecodeBase32(padded.ToLowerInvariant(), out var fromPadded), Is.True);
        Assert.That(fromUnpadded, Is.EqualTo(secret));
        Assert.That(fromPadded, Is.EqualTo(secret));
    }

    [TestCase("10234892")]
    [TestCase("M")]
    [TestCase("MZ=XA")]
    [TestCase("MZXA=")]
    [TestCase("https://example.invalid/")]
    public void RejectsMalformedBase32(string input)
    {
        Assert.That(AuthenticatorRegexHelper.TryDecodeBase32(input, out _), Is.False);
    }

    [TestCase(1, 1, HMACTypes.SHA1, 6)]
    [TestCase(2, 2, HMACTypes.SHA256, 8)]
    [TestCase(3, 2, HMACTypes.SHA512, 8)]
    public void ReadsExportedSecretAndParameters(byte algorithm, byte digits, HMACTypes expectedAlgorithm, int expectedDigits)
    {
        var secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var qr = ToMigrationUri(EncodeToken(secret, algorithm, digits));

        Assert.That(GoogleAuthenticatorMigration.Read(qr, out var token), Is.EqualTo(GoogleAuthenticatorMigration.Result.Success));
        Assert.That(token!.Name, Is.EqualTo("12345678"));
        Assert.That(token.Issuer, Is.EqualTo("Demo"));
        Assert.That(token.Secret, Is.EqualTo(secret));
        Assert.That(token.Algorithm, Is.EqualTo(expectedAlgorithm));
        Assert.That(token.Digits, Is.EqualTo(expectedDigits));
    }

    [Test]
    public void RejectsAmbiguousOrMalformedMigrationData()
    {
        var entry = EncodeToken([1, 2, 3], 1, 1);
        var multiple = ToMigrationUri([.. entry, .. entry]);
        var truncated = ToMigrationUri([0x0A, 0x20, 0x0A]);
        var hotp = ToMigrationUri(EncodeToken([1, 2, 3], 1, 1, type: 1));

        Assert.That(GoogleAuthenticatorMigration.Read(multiple, out _), Is.EqualTo(GoogleAuthenticatorMigration.Result.MultipleAccounts));
        Assert.That(GoogleAuthenticatorMigration.Read(truncated, out _), Is.EqualTo(GoogleAuthenticatorMigration.Result.Invalid));
        Assert.That(GoogleAuthenticatorMigration.Read(hotp, out _), Is.EqualTo(GoogleAuthenticatorMigration.Result.UnsupportedToken));
    }

    static byte[] EncodeToken(byte[] secret, byte algorithm, byte digits, byte type = 2)
    {
        byte[] record = [0x0A, (byte)secret.Length, .. secret,
            0x12, 8, .. Encoding.ASCII.GetBytes("12345678"), 0x1A, 4, .. Encoding.ASCII.GetBytes("Demo"),
            0x20, algorithm, 0x28, digits, 0x30, type, 0x42, 1, 0x00];
        return [0x0A, (byte)record.Length, .. record];
    }

    static string ToMigrationUri(byte[] message)
    {
        byte[] payload = [.. message, 0x10, 2, 0x18, 1];
        return $"otpauth-migration://offline?data={Uri.EscapeDataString(Convert.ToBase64String(payload))}";
    }
}
