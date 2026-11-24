using BD.WTTS.Enums;
using BD.WTTS.Helpers;
using WinAuth;

namespace BD.WTTS.UI.ViewModels;

public partial class AuthenticatorGeneralImportPageViewModel
{
    const string EmptyCode = "------";

    public string Name => Strings.LocalAuth_Import.Format(Strings.HOTP);

    IAuthenticatorValueDTO? importAuthenticatorValueDto;

    public AuthenticatorPlatform Platform { get; }

    public ICommand GenerateCodeCommand { get; }

    public ICommand ImportCommand { get; }

    public ICommand ReadQrImageCommand { get; }

    public AuthenticatorGeneralImportPageViewModel() : this(AuthenticatorPlatform.HOTP)
    {
    }

    public AuthenticatorGeneralImportPageViewModel(AuthenticatorPlatform platform)
    {
        Platform = platform;

        var generateCode = ReactiveCommand.Create(GenerateCode);
        var import = ReactiveCommand.CreateFromTask(Import);
        var readQrImage = ReactiveCommand.CreateFromTask(ReadQrImage);
        CompositeDisposable.Add(generateCode);
        CompositeDisposable.Add(import);
        CompositeDisposable.Add(readQrImage);
        CompositeDisposable.Add(import.ThrownExceptions.Subscribe(static ex => ex.LogAndShowT()));
        CompositeDisposable.Add(readQrImage.ThrownExceptions.Subscribe(_ =>
        {
            InvalidatePreview();
            ShowInvalidQrImage();
        }));
        CompositeDisposable.Add(this.WhenAnyValue(x => x.SecretCode, x => x.AuthType, x => x.HMACType,
                x => x.CodeDigits, x => x.Period)
            .Subscribe(_ => InvalidatePreview()));
        GenerateCodeCommand = generateCode;
        ImportCommand = import;
        ReadQrImageCommand = readQrImage;
    }

    async Task ReadQrImage()
    {
        var file = await FilePicker2.PickAsync(new PickOptions
        {
            PickerTitle = Strings.AuthImport_ReadQrImage,
            FileTypes = IFilePickerFileType.Images(),
        });
        if (file == null)
            return;

        var previousInput = SecretCode;
        await using var image = await file.OpenReadAsync();
        var text = await Task.Run(() => AuthenticatorQrImage.Read(image));
        if (SecretCode != previousInput)
            return;
        if (text == null)
        {
            InvalidatePreview();
            ShowInvalidQrImage();
            return;
        }

        SecretCode = text;
        GenerateCode();
    }

    static void ShowInvalidQrImage() => Toast.Show(ToastIcon.Error, Strings.AuthImport_InvalidQrImage);

    void InvalidatePreview()
    {
        var hadPreview = importAuthenticatorValueDto != null;
        importAuthenticatorValueDto = null;
        if (AuthType == AuthType.TOTP || hadPreview)
            CurrentCode = EmptyCode;
    }

    void GenerateCode()
    {
        var counterText = CurrentCode;
        InvalidatePreview();
        var text = SecretCode?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            Toast.Show(ToastIcon.Info, Strings.Info_PleaseEnterImportText);
            return;
        }

        try
        {
            AuthenticatorValueDTO? authenticator = text.StartsWith(GoogleAuthenticatorMigration.Scheme + ":", StringComparison.OrdinalIgnoreCase)
                ? ReadMigration(text)
                : ReadStandardToken(text, counterText);
            if (authenticator == null)
                return;

            CurrentCode = authenticator.CurrentCode;
            importAuthenticatorValueDto = authenticator;
        }
        catch (Exception)
        {
            // Errors during import may include part of the source token. Show a fixed message.
            ShowInvalidSecret();
        }
    }

    AuthenticatorValueDTO? ReadMigration(string text)
    {
        var result = GoogleAuthenticatorMigration.Read(text, out var token);
        if (token == null)
        {
            Toast.Show(ToastIcon.Error, result switch
            {
                GoogleAuthenticatorMigration.Result.MultipleAccounts => Strings.AuthImport_GoogleSingleAccount,
                GoogleAuthenticatorMigration.Result.UnsupportedToken => Strings.AuthImport_GoogleUnsupportedToken,
                _ => Strings.AuthImport_InvalidQrImage,
            });
            return null;
        }

        AuthType = AuthType.TOTP;
        HMACType = token.Algorithm;
        CodeDigits = token.Digits;
        Period = AuthenticatorValueDTO.DEFAULT_PERIOD;
        AuthenticatorName = FormatName(token.Name, token.Issuer);
        return new TOTPAuthenticator
        {
            SecretKey = token.Secret,
            Issuer = token.Issuer,
            HMACType = token.Algorithm,
            CodeDigits = token.Digits,
            Period = Period,
        };
    }

    AuthenticatorValueDTO? ReadStandardToken(string text, string? counterText)
    {
        string? secret = text;
        string? issuer = null;
        if (text.StartsWith("otpauth:", StringComparison.OrdinalIgnoreCase))
        {
            var match = AuthenticatorRegexHelper.SecretCodeOptAuthRegex().Match(text);
            if (!match.Success)
                return ShowInvalidSecret();

            var options = HttpUtility.ParseQueryString(match.Groups[3].Value);
            if (!TryReadOptions(options["period"], options["digits"], options["algorithm"]))
                return ShowInvalidSecret();

            secret = options["secret"];
            issuer = options["issuer"];
            AuthType = match.Groups[1].Value.Equals("hotp", StringComparison.OrdinalIgnoreCase) ? AuthType.HOTP : AuthType.TOTP;
            AuthenticatorName = FormatName(Uri.UnescapeDataString(match.Groups[2].Value), issuer);
            counterText = options["counter"];
        }
        else if (Platform != AuthenticatorPlatform.HOTP)
        {
            AuthType = AuthType.TOTP;
            HMACType = HMACTypes.SHA1;
            CodeDigits = AuthenticatorValueDTO.DEFAULT_CODE_DIGITS;
            Period = AuthenticatorValueDTO.DEFAULT_PERIOD;
        }

        if (!AuthenticatorRegexHelper.TryDecodeBase32(secret, out var key) || Period <= 0
            || CodeDigits is < 1 or > 9 || !Enum.IsDefined(HMACType))
            return ShowInvalidSecret();

        AuthenticatorValueDTO authenticator;
        if (AuthType == AuthType.HOTP)
        {
            if (!long.TryParse(counterText, out var count) || count < 0)
            {
                if (counterText is not (null or "" or EmptyCode))
                    return ShowInvalidSecret();
                count = 0;
            }
            authenticator = new HOTPAuthenticator { Counter = count };
        }
        else
        {
            authenticator = Platform switch
            {
                AuthenticatorPlatform.Google => new GoogleAuthenticator(),
                AuthenticatorPlatform.Microsoft => new MicrosoftAuthenticator(),
                _ => new TOTPAuthenticator(),
            };
        }

        authenticator.SecretKey = key;
        authenticator.Issuer = issuer ?? authenticator.Issuer;
        authenticator.HMACType = HMACType;
        authenticator.CodeDigits = CodeDigits;
        authenticator.Period = Period;
        // CurrentCode starts any available time sync and can generate a preview using the system clock.
        return authenticator;
    }

    bool TryReadOptions(string? periodText, string? digitsText, string? algorithmText)
    {
        var period = AuthenticatorValueDTO.DEFAULT_PERIOD;
        var digits = AuthenticatorValueDTO.DEFAULT_CODE_DIGITS;
        var algorithm = HMACTypes.SHA1;
        if (periodText != null && (!int.TryParse(periodText, out period) || period <= 0)
            || digitsText != null && (!int.TryParse(digitsText, out digits) || digits is < 1 or > 9)
            || algorithmText != null && (!Enum.TryParse(algorithmText, true, out algorithm) || !Enum.IsDefined(algorithm)))
            return false;

        Period = period;
        CodeDigits = digits;
        HMACType = algorithm;
        return true;
    }

    static string FormatName(string name, string? issuer) => string.IsNullOrWhiteSpace(issuer) ? name
        : string.IsNullOrWhiteSpace(name) ? issuer : $"{issuer} ({name})";

    AuthenticatorValueDTO? ShowInvalidSecret()
    {
        Toast.Show(ToastIcon.Error, Strings.LocalAuth_Import_DecodePrivateKeyError.Format(Platform.ToString()));
        return null;
    }

    async Task Import()
    {
        var authenticator = importAuthenticatorValueDto;
        if (authenticator == null)
        {
            Toast.Show(ToastIcon.Info, Strings.Info_PleaseVerifyFirstAuthCode);
            return;
        }

        if (string.IsNullOrEmpty(AuthenticatorName))
        {
            Toast.Show(ToastIcon.Warning, Strings.Warning_PleaseEnterAuthName);
            return;
        }

        var iAuthenticatorDtoDto = new AuthenticatorDTO()
        {
            Name = $"{authenticator.Platform}({AuthenticatorName})",
            Value = authenticator,
            Created = DateTimeOffset.Now,
        };

        if (await AuthenticatorHelper.SaveAuthenticator(iAuthenticatorDtoDto))
            Toast.Show(ToastIcon.Success, Strings.ModelContent_ImportSuccessful_.Format(iAuthenticatorDtoDto.Name));
    }
}
