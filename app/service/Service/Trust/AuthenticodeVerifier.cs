using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Antivirus.Service.Trust;

public sealed record AuthenticodeResult(bool ChainValid, string? PublisherName, string? PublisherThumbprint);

// security/09-bao-mat.md muc 1: "goi WinVerifyTrust voi action GUID
// WINTRUST_ACTION_GENERIC_VERIFY_V2 tren duong dan file thuc thi; ham tu
// kiem tra toan bo chain certificate, thoi han hieu luc va trang thai thu
// hoi (CRL/OCSP neu co mang). Sau khi chain hop le, kiem tra publisher name
// trong subject certificate khop CHINH XAC voi 'Microsoft Windows'/
// 'Microsoft Corporation' bang so khop chuoi chinh xac, khong dung ham
// chua chuoi con" (chong ERR-02 gia mao Unicode trong sổ tay lỗi/bảng rủi ro).
public static class AuthenticodeVerifier
{
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static readonly string[] TrustedMicrosoftPublisherNames =
    {
        "Microsoft Windows",
        "Microsoft Corporation",
        "Microsoft Windows Publisher",
    };

    public static AuthenticodeResult Verify(string filePath)
    {
        bool chainValid = CallWinVerifyTrust(filePath);
        string? publisherName = null;
        string? thumbprint = null;

        try
        {
#pragma warning disable SYSLIB0057 // API cu nhung van la cach chinh de doc chu ky Authenticode nhung khong tu verify chain (WinVerifyTrust da lam viec do o tren)
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(cert);
#pragma warning restore SYSLIB0057
            publisherName = cert2.GetNameInfo(X509NameType.SimpleName, false);
            thumbprint = cert2.Thumbprint;
        }
        catch
        {
            // Khong ky so (unsigned) — publisherName/thumbprint = null, hien
            // thi "Khong xac dinh" o UI theo dung sections/09.
        }

        return new AuthenticodeResult(chainValid, publisherName, thumbprint);
    }

    // So khop CHINH XAC (khong dung Contains/wcsstr) — chong gia mao Unicode
    // trong so tay loi ERR-02 / bang rui ro security/09.
    public static bool IsMicrosoftPublisher(string? publisherName)
    {
        if (string.IsNullOrEmpty(publisherName)) return false;
        return TrustedMicrosoftPublisherNames.Any(name =>
            string.Equals(name, publisherName, StringComparison.Ordinal));
    }

    private static bool CallWinVerifyTrust(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            long result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return result == 0; // ERROR_SUCCESS
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern long WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}
