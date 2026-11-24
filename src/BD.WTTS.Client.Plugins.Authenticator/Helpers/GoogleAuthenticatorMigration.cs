using BD.WTTS.Enums;
using System.Text;
using System.Web;

namespace BD.WTTS.Helpers;

internal static class GoogleAuthenticatorMigration
{
    internal const string Scheme = "otpauth-migration";

    internal enum Result
    {
        Invalid,
        MultipleAccounts,
        UnsupportedToken,
        Success,
    }

    internal sealed record Token(byte[] Secret, string Name, string Issuer, HMACTypes Algorithm, int Digits);

    internal static Result Read(string text, out Token? token)
    {
        token = null;
        if (text.Length > 16_384 || !Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || uri.Scheme != Scheme || uri.Host != "offline")
            return Result.Invalid;

        var data = HttpUtility.ParseQueryString(uri.Query)["data"];
        if (string.IsNullOrEmpty(data))
            return Result.Invalid;

        // Google encodes the protobuf in Base64. Accept URL-safe text and unescaped '+' as well.
        data = data.Replace(' ', '+').Replace('-', '+').Replace('_', '/');
        data = data.PadRight((data.Length + 3) / 4 * 4, '=');
        try
        {
            var payload = new ProtobufReader(Convert.FromBase64String(data));
            ReadOnlySpan<byte> entry = default;
            var hasEntry = false;
            // MigrationPayload.otp_parameters is a repeated message in versions 1 and 2.
            while (payload.TryReadField(out var field, out var wire))
            {
                if (field == 1 && wire == 2)
                {
                    if (hasEntry)
                        return Result.MultipleAccounts;
                    entry = payload.ReadBytes();
                    hasEntry = true;
                }
                else
                {
                    payload.Skip(wire);
                }
            }

            return hasEntry ? ReadToken(entry, out token) : Result.Invalid;
        }
        catch (FormatException)
        {
            return Result.Invalid;
        }
    }

    static Result ReadToken(ReadOnlySpan<byte> data, out Token? token)
    {
        token = null;
        var reader = new ProtobufReader(data);
        byte[]? secret = null;
        string name = "", issuer = "";
        ulong algorithm = 0, digits = 0, type = 0;
        while (reader.TryReadField(out var field, out var wire))
        {
            switch (field, wire)
            {
                case (1, 2): secret = reader.ReadBytes().ToArray(); break;
                case (2, 2): name = Encoding.UTF8.GetString(reader.ReadBytes()); break;
                case (3, 2): issuer = Encoding.UTF8.GetString(reader.ReadBytes()); break;
                case (4, 0): algorithm = reader.ReadVarint(); break;
                case (5, 0): digits = reader.ReadVarint(); break;
                case (6, 0): type = reader.ReadVarint(); break;
                default: reader.Skip(wire); break;
            }
        }

        if (secret is not { Length: > 0 })
            return Result.Invalid;
        // Use the declared token type and parameters. WinAuth's HOTP preview advances the counter.
        if (type != 2 || algorithm > 3 || digits > 2)
            return Result.UnsupportedToken;

        var hash = algorithm switch
        {
            2 => HMACTypes.SHA256,
            3 => HMACTypes.SHA512,
            _ => HMACTypes.SHA1,
        };
        token = new Token(secret, name, issuer, hash, digits == 2 ? 8 : 6);
        return Result.Success;
    }

    ref struct ProtobufReader
    {
        ReadOnlySpan<byte> remaining;

        public ProtobufReader(ReadOnlySpan<byte> data) => remaining = data;

        public bool TryReadField(out ulong field, out ulong wire)
        {
            field = wire = 0;
            if (remaining.IsEmpty)
                return false;

            var tag = ReadVarint();
            field = tag >> 3;
            wire = tag & 7;
            if (field is 0 or > 0x1FFFFFFF)
                throw new FormatException();
            return true;
        }

        public ulong ReadVarint()
        {
            ulong result = 0;
            for (var shift = 0; shift <= 63 && !remaining.IsEmpty; shift += 7)
            {
                var value = remaining[0];
                remaining = remaining[1..];
                if (shift == 63 && value > 1)
                    break;
                result |= (ulong)(value & 0x7F) << shift;
                if (value < 0x80)
                    return result;
            }

            throw new FormatException();
        }

        public ReadOnlySpan<byte> ReadBytes() => Read(ReadVarint());

        public void Skip(ulong wire)
        {
            switch (wire)
            {
                case 0: ReadVarint(); break;
                case 1: Read(8); break;
                case 2: ReadBytes(); break;
                case 5: Read(4); break;
                default: throw new FormatException();
            }
        }

        ReadOnlySpan<byte> Read(ulong length)
        {
            if (length > (ulong)remaining.Length)
                throw new FormatException();
            var result = remaining[..(int)length];
            remaining = remaining[(int)length..];
            return result;
        }
    }
}
