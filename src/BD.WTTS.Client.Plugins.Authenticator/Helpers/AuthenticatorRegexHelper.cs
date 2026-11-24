using WinAuth;

namespace BD.WTTS.Helpers;

internal sealed partial class AuthenticatorRegexHelper
{
    [GeneratedRegex(@"\Aotpauth://(totp|hotp)/([^?]+)\?(.*)\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    internal static partial Regex SecretCodeOptAuthRegex();

    [GeneratedRegex(@"[\s_-]+")]
    private static partial Regex Base32SeparatorsRegex();

    internal static bool TryDecodeBase32(string? input, [NotNullWhen(true)] out byte[]? key)
    {
        key = null;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var text = Base32SeparatorsRegex().Replace(input, "").ToUpperInvariant();
        var secret = text.TrimEnd('=');
        var remainder = secret.Length % 8;
        var padding = text.Length - secret.Length;
        if (secret.Length < 2 || remainder is 1 or 3 or 6
            || padding != 0 && padding != (8 - remainder) % 8
            || !secret.All(static ch => ch is (>= 'A' and <= 'Z') or (>= '2' and <= '7')))
            return false;

        key = Base32.GetInstance().Decode(secret);
        return true;
    }
}
