using SkiaSharp;
using ZXing;
using ZXing.Common;

namespace BD.WTTS.Helpers;

internal static class AuthenticatorQrImage
{
    internal static string? Read(Stream image)
    {
        using var codec = SKCodec.Create(image);
        if (codec == null || (long)codec.Info.Width * codec.Info.Height > 25_000_000)
            return null;

        var info = new SKImageInfo(codec.Info.Width, codec.Info.Height, SKColorType.Rgba8888, SKAlphaType.Unpremul);
        using var bitmap = SKBitmap.Decode(codec, info);
        if (bitmap == null)
            return null;

        var pixels = bitmap.Bytes;
        var source = new RGBLuminanceSource(pixels, bitmap.Width, bitmap.Height, RGBLuminanceSource.BitmapFormat.RGBA32);
        try
        {
            var reader = new BarcodeReaderGeneric
            {
                AutoRotate = true,
                Options = new DecodingOptions
                {
                    PossibleFormats = [BarcodeFormat.QR_CODE],
                    TryHarder = true,
                    TryInverted = true,
                },
            };
            var text = reader.Decode(source)?.Text;
            return Uri.TryCreate(text, UriKind.Absolute, out var uri)
                && uri.Scheme is "otpauth" or GoogleAuthenticatorMigration.Scheme ? text : null;
        }
        finally
        {
            Array.Clear(pixels);
            Array.Clear(source.Matrix);
            bitmap.Erase(SKColors.Transparent);
        }
    }
}
